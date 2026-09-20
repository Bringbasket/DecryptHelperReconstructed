#import "DHLogStore.h"
#import "DHConfig.h"
#import <pthread.h>
#import <sys/time.h>
#include <stdlib.h>

static const NSUInteger kDHRetainedEventLimit = 2000;
static const unsigned long long kDHLogRotationBytes = 8ULL * 1024ULL * 1024ULL;
static const NSUInteger kDHLogRotationSegments = 3;
static const NSUInteger kDHJournalBatchBytes = 64 * 1024;
static const NSUInteger kDHSoftPendingLimit = 1024;
static const NSUInteger kDHHardPendingLimit = 4096;

static NSString *DHDataText(NSData *data) {
    if (!data.length) return @"";
    NSString *utf8 = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return utf8 ?: [data base64EncodedStringWithOptions:0];
}

static NSString *DHStringValue(id value) {
    return [value isKindOfClass:NSString.class] ? value : @"";
}

static BOOL DHContainsText(NSString *value, NSString *needle) {
    if (!needle.length) return YES;
    return [value rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound;
}

uint64_t DHTimestampMilliseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

uint64_t DHCurrentThreadId(void) {
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return tid;
}

NSArray<NSString *> *DHFilteredCallStack(void) {
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    for (NSString *line in NSThread.callStackSymbols) {
        if ([line containsString:@"decrypt_helper"] || [line containsString:@"DHFilteredCallStack"] ||
            [line containsString:@"DHLogStore"]) continue;
        [result addObject:line];
        if (result.count >= 24) break;
    }
    return result;
}

@implementation DHLogEntry

+ (instancetype)entryWithCategory:(NSString *)category algorithm:(NSString *)algorithm operation:(NSString *)operation {
    DHLogEntry *entry = [DHLogEntry new];
    entry.category = category ?: @"OTHER";
    entry.algorithm = algorithm ?: @"unknown";
    entry.operation = operation ?: @"observe";
    entry.callStack = @[];
    entry.timestampMs = DHTimestampMilliseconds();
    entry.threadId = DHCurrentThreadId();
    entry.contextId = [NSString stringWithFormat:@"thread:%llu", entry.threadId];
    return entry;
}

- (NSDictionary<NSString *,id> *)dictionaryRepresentation {
    NSMutableDictionary *dictionary = [@{
        @"seq": @(self.sequence), @"category": self.category ?: @"OTHER",
        @"algorithm": self.algorithm ?: @"unknown", @"operation": self.operation ?: @"observe",
        @"timestampMs": @(self.timestampMs), @"threadId": @(self.threadId),
        @"contextId": self.contextId ?: @"", @"callStack": self.callStack ?: @[],
        @"noise": @(self.noise)
    } mutableCopy];
    if (self.noiseRule) dictionary[@"noiseRule"] = self.noiseRule;
    if (self.detail) {
        dictionary[@"detail"] = self.detail;
        NSData *detailData = [self.detail dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *metadata = detailData ? [NSJSONSerialization JSONObjectWithData:detailData options:0 error:nil] : nil;
        if ([metadata isKindOfClass:NSDictionary.class] && [metadata[@"requestId"] isKindOfClass:NSString.class]) {
            dictionary[@"requestId"] = metadata[@"requestId"];
        }
    }
    if (self.input) {
        dictionary[@"input"] = DHDataText(self.input);
        dictionary[@"inputBase64"] = [self.input base64EncodedStringWithOptions:0];
        dictionary[@"inputLength"] = @(self.input.length);
    }
    if (self.output) {
        dictionary[@"output"] = DHDataText(self.output);
        dictionary[@"outputBase64"] = [self.output base64EncodedStringWithOptions:0];
        dictionary[@"outputLength"] = @(self.output.length);
    }
    return dictionary;
}

@end

@interface DHLogStore ()
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) NSMutableArray<DHLogEntry *> *entries;
@property (nonatomic, strong) NSMutableArray<DHLogEntry *> *noiseEntries;
@property (nonatomic) uint64_t nextSequence;
@property (nonatomic, strong) NSMutableData *journalBuffer;
@property (nonatomic) BOOL journalFlushScheduled;
@property (nonatomic) NSUInteger pendingEvents;
@property (nonatomic) NSUInteger restoredEvents;
@property (nonatomic) NSUInteger droppedEvents;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *droppedByCategory;
@end

@implementation DHLogStore

+ (instancetype)shared {
    static DHLogStore *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ instance = [DHLogStore new]; });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _queue = dispatch_queue_create("com.decrypthelper.reconstructed.log", DISPATCH_QUEUE_SERIAL);
    _entries = [NSMutableArray array];
    _noiseEntries = [NSMutableArray array];
    _nextSequence = 1;
    _journalBuffer = [NSMutableData data];
    _droppedByCategory = [NSMutableDictionary dictionary];
    NSString *directory = [[self logFilePath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    [self restoreFromJournal];
    return self;
}

- (NSString *)logDirectory {
    const char *override = getenv("DH_LOG_DIR");
    if (override && override[0] == '/') {
        NSString *value = [NSString stringWithUTF8String:override];
        if (value.length) return [value stringByStandardizingPath];
    }
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/IOSDecryptHub"];
}

- (NSString *)logFilePath {
    return [[self logDirectory] stringByAppendingPathComponent:@"decrypt_helper.log"];
}

- (NSString *)noiseLogFilePath {
    return [[self logDirectory] stringByAppendingPathComponent:@"decrypt_helper.noise.log"];
}

- (NSString *)journalFilePath { return self.logFilePath; }

- (void)rotateLogAtPathIfNeeded:(NSString *)path incomingLength:(NSUInteger)incomingLength {
    NSFileManager *manager = NSFileManager.defaultManager;
    NSDictionary *attributes = [manager attributesOfItemAtPath:path error:nil];
    unsigned long long size = [attributes[NSFileSize] unsignedLongLongValue];
    if (size + incomingLength < kDHLogRotationBytes) return;
    NSString *oldest = [path stringByAppendingFormat:@".%lu", (unsigned long)kDHLogRotationSegments];
    [manager removeItemAtPath:oldest error:nil];
    for (NSUInteger index = kDHLogRotationSegments; index > 1; index--) {
        NSString *source = [path stringByAppendingFormat:@".%lu", (unsigned long)(index - 1)];
        NSString *destination = [path stringByAppendingFormat:@".%lu", (unsigned long)index];
        if ([manager fileExistsAtPath:source]) [manager moveItemAtPath:source toPath:destination error:nil];
    }
    if ([manager fileExistsAtPath:path]) [manager moveItemAtPath:path toPath:[path stringByAppendingString:@".1"] error:nil];
}

- (void)writeLineData:(NSData *)line toPath:(NSString *)path {
    if (!line.length) return;
    [self rotateLogAtPathIfNeeded:path incomingLength:line.length];
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!handle) { [line writeToFile:path atomically:YES]; return; }
    @try { [handle seekToEndOfFile]; [handle writeData:line]; [handle closeFile]; }
    @catch (__unused NSException *exception) { [handle closeFile]; }
}

- (void)flushJournalBufferLocked {
    if (!self.journalBuffer.length) { self.journalFlushScheduled = NO; return; }
    NSData *batch = [self.journalBuffer copy];
    [self.journalBuffer setLength:0];
    self.journalFlushScheduled = NO;
    [self writeLineData:batch toPath:self.logFilePath];
}

- (void)appendDictionary:(NSDictionary *)dictionary toPath:(NSString *)path {
    NSData *json = [NSJSONSerialization dataWithJSONObject:dictionary options:0 error:nil];
    if (!json) return;
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    if (![path isEqualToString:self.logFilePath]) { [self writeLineData:line toPath:path]; return; }
    [self.journalBuffer appendData:line];
    if (self.journalBuffer.length >= kDHJournalBatchBytes) { [self flushJournalBufferLocked]; return; }
    if (self.journalFlushScheduled) return;
    self.journalFlushScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), self.queue, ^{ [self flushJournalBufferLocked]; });
}

- (DHLogEntry *)entryFromDictionary:(NSDictionary *)dictionary {
    if (![dictionary isKindOfClass:NSDictionary.class]) return nil;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:DHStringValue(dictionary[@"category"])
                                            algorithm:DHStringValue(dictionary[@"algorithm"])
                                            operation:DHStringValue(dictionary[@"operation"])];
    entry.sequence = [dictionary[@"seq"] unsignedLongLongValue];
    entry.timestampMs = [dictionary[@"timestampMs"] unsignedLongLongValue];
    entry.threadId = [dictionary[@"threadId"] unsignedLongLongValue];
    entry.contextId = DHStringValue(dictionary[@"contextId"]);
    entry.detail = [dictionary[@"detail"] isKindOfClass:NSString.class] ? dictionary[@"detail"] : nil;
    entry.callStack = [dictionary[@"callStack"] isKindOfClass:NSArray.class] ? dictionary[@"callStack"] : @[];
    entry.noise = [dictionary[@"noise"] boolValue];
    entry.noiseRule = [dictionary[@"noiseRule"] isKindOfClass:NSString.class] ? dictionary[@"noiseRule"] : nil;
    NSString *input = [dictionary[@"inputBase64"] isKindOfClass:NSString.class] ? dictionary[@"inputBase64"] : nil;
    NSString *output = [dictionary[@"outputBase64"] isKindOfClass:NSString.class] ? dictionary[@"outputBase64"] : nil;
    if (input.length) entry.input = [[NSData alloc] initWithBase64EncodedString:input options:0];
    if (output.length) entry.output = [[NSData alloc] initWithBase64EncodedString:output options:0];
    return entry;
}

- (void)restorePath:(NSString *)path into:(NSMutableArray<DHLogEntry *> *)destination {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data.length) return;
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        if (!line.length) continue;
        NSData *json = [line dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *dictionary = json ? [NSJSONSerialization JSONObjectWithData:json options:0 error:nil] : nil;
        DHLogEntry *entry = [self entryFromDictionary:dictionary];
        if (!entry) continue;
        [destination addObject:entry];
        self.nextSequence = MAX(self.nextSequence, entry.sequence + 1);
    }
}

- (void)restoreFromJournal {
    NSMutableArray<DHLogEntry *> *restored = [NSMutableArray array];
    for (NSInteger index = (NSInteger)kDHLogRotationSegments; index >= 1; index--) {
        [self restorePath:[self.logFilePath stringByAppendingFormat:@".%ld", (long)index] into:restored];
    }
    [self restorePath:self.logFilePath into:restored];
    NSMutableArray<DHLogEntry *> *restoredNoise = [NSMutableArray array];
    for (NSInteger index = (NSInteger)kDHLogRotationSegments; index >= 1; index--) {
        [self restorePath:[self.noiseLogFilePath stringByAppendingFormat:@".%ld", (long)index] into:restoredNoise];
    }
    [self restorePath:self.noiseLogFilePath into:restoredNoise];
    if (restored.count > kDHRetainedEventLimit) [restored removeObjectsInRange:NSMakeRange(0, restored.count - kDHRetainedEventLimit)];
    for (DHLogEntry *entry in restored) {
        if (entry.noise) [self.noiseEntries addObject:entry];
        else [self.entries addObject:entry];
    }
    [self.noiseEntries addObjectsFromArray:restoredNoise];
    if (self.entries.count > kDHRetainedEventLimit) [self.entries removeObjectsInRange:NSMakeRange(0, self.entries.count - kDHRetainedEventLimit)];
    if (self.noiseEntries.count > kDHRetainedEventLimit) [self.noiseEntries removeObjectsInRange:NSMakeRange(0, self.noiseEntries.count - kDHRetainedEventLimit)];
    self.restoredEvents = restored.count + restoredNoise.count;
}

- (void)append:(DHLogEntry *)entry {
    if (!entry || ![[DHConfig shared] captureEnabledForCategory:entry.category]) return;
    @synchronized (self) {
        BOOL softDrop = self.pendingEvents >= kDHSoftPendingLimit &&
            ([entry.category isEqualToString:@"NETWORK"] || [entry.category hasPrefix:@"FILE_"] || [entry.category isEqualToString:@"WEBKIT"]);
        if (self.pendingEvents >= kDHHardPendingLimit || softDrop) {
            self.droppedEvents++;
            NSString *category = entry.category ?: @"OTHER";
            self.droppedByCategory[category] = @([self.droppedByCategory[category] unsignedIntegerValue] + 1);
            return;
        }
        self.pendingEvents++;
    }
    dispatch_async(self.queue, ^{
        @autoreleasepool {
        NSDictionary *candidate = entry.dictionaryRepresentation;
        NSString *ruleName = nil;
        NSString *action = [[DHConfig shared] noiseActionForEvent:candidate matchedRuleName:&ruleName];
        if ([action isEqualToString:@"drop"]) { @synchronized (self) { self.pendingEvents--; } return; }

        entry.sequence = self.nextSequence++;
        NSMutableArray<DHLogEntry *> *destination = self.entries;
        NSString *path = self.logFilePath;
        if ([action isEqualToString:@"route"]) {
            entry.noise = YES;
            entry.noiseRule = ruleName;
            destination = self.noiseEntries;
            path = self.noiseLogFilePath;
        }
        [destination addObject:entry];
        if (destination.count > kDHRetainedEventLimit) {
            [destination removeObjectsInRange:NSMakeRange(0, destination.count - kDHRetainedEventLimit)];
        }
        [self appendDictionary:entry.dictionaryRepresentation toPath:path];
        @synchronized (self) { self.pendingEvents--; }
        }
    });
}

- (NSDictionary<NSString *,id> *)pipelineStats {
    __block NSUInteger journalBufferBytes = 0;
    dispatch_sync(self.queue, ^{ journalBufferBytes = self.journalBuffer.length; });
    unsigned long long diskBytes = 0;
    NSFileManager *manager = NSFileManager.defaultManager;
    for (NSUInteger index = 0; index <= kDHLogRotationSegments; index++) {
        NSString *path = index ? [self.logFilePath stringByAppendingFormat:@".%lu", (unsigned long)index] : self.logFilePath;
        diskBytes += [[manager attributesOfItemAtPath:path error:nil][NSFileSize] unsignedLongLongValue];
    }
    @synchronized (self) {
        return @{
            @"pending": @(self.pendingEvents), @"softLimit": @(kDHSoftPendingLimit), @"hardLimit": @(kDHHardPendingLimit),
            @"journalBytes": @(diskBytes + journalBufferBytes), @"journalMaxBytes": @(kDHLogRotationBytes * (kDHLogRotationSegments + 1)),
            @"restoredEvents": @(self.restoredEvents), @"dropped": @(self.droppedEvents),
            @"droppedByCategory": [self.droppedByCategory copy] ?: @{}
        };
    }
}

- (NSArray<DHLogEntry *> *)snapshot {
    __block NSArray<DHLogEntry *> *result;
    dispatch_sync(self.queue, ^{ result = [self.entries copy]; });
    return result ?: @[];
}

- (NSArray<NSDictionary<NSString *,id> *> *)dictionarySnapshot {
    NSMutableArray *result = [NSMutableArray array];
    for (DHLogEntry *entry in self.snapshot) [result addObject:entry.dictionaryRepresentation];
    return result;
}

- (NSDictionary<NSString *,id> *)eventForSequence:(uint64_t)sequence includeNoise:(BOOL)includeNoise {
    __block NSDictionary *result = nil;
    dispatch_sync(self.queue, ^{
        for (DHLogEntry *entry in self.entries) {
            if (entry.sequence == sequence) { result = entry.dictionaryRepresentation; return; }
        }
        if (!includeNoise) return;
        for (DHLogEntry *entry in self.noiseEntries) {
            if (entry.sequence == sequence) { result = entry.dictionaryRepresentation; return; }
        }
    });
    return result;
}

- (BOOL)dictionary:(NSDictionary *)event matchesFilters:(NSDictionary *)filters {
    NSDictionary *exact = @{
        @"category": @"category", @"algorithm": @"algorithm", @"operation": @"operation",
        @"requestId": @"requestId", @"contextId": @"contextId"
    };
    for (NSString *filterKey in exact) {
        NSString *expected = DHStringValue(filters[filterKey]);
        if (expected.length && [DHStringValue(event[exact[filterKey]]) caseInsensitiveCompare:expected] != NSOrderedSame) return NO;
    }
    NSString *thread = [filters[@"threadId"] respondsToSelector:@selector(stringValue)] ? [filters[@"threadId"] stringValue] : DHStringValue(filters[@"threadId"]);
    if (thread.length && ![[event[@"threadId"] stringValue] isEqualToString:thread]) return NO;

    uint64_t timestamp = [event[@"timestampMs"] unsignedLongLongValue];
    uint64_t sequence = [event[@"seq"] unsignedLongLongValue];
    if ([filters[@"sinceMs"] respondsToSelector:@selector(unsignedLongLongValue)] && timestamp < [filters[@"sinceMs"] unsignedLongLongValue]) return NO;
    if ([filters[@"untilMs"] respondsToSelector:@selector(unsignedLongLongValue)] && timestamp > [filters[@"untilMs"] unsignedLongLongValue]) return NO;
    if ([filters[@"afterSeq"] respondsToSelector:@selector(unsignedLongLongValue)] && sequence <= [filters[@"afterSeq"] unsignedLongLongValue]) return NO;
    if ([filters[@"beforeSeq"] respondsToSelector:@selector(unsignedLongLongValue)] && sequence >= [filters[@"beforeSeq"] unsignedLongLongValue]) return NO;

    NSString *stackNeedle = DHStringValue(filters[@"stack"]);
    NSString *stack = [event[@"callStack"] isKindOfClass:NSArray.class] ? [event[@"callStack"] componentsJoinedByString:@"\n"] : @"";
    if (!DHContainsText(stack, stackNeedle)) return NO;
    NSString *contains = DHStringValue(filters[@"contains"]);
    if (contains.length) {
        NSData *json = [NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
        NSString *text = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : @"";
        if (!DHContainsText(text, contains)) return NO;
    }
    return YES;
}

- (NSDictionary<NSString *,id> *)queryWithFilters:(NSDictionary<NSString *,id> *)filters noise:(BOOL)noise {
    filters = [filters isKindOfClass:NSDictionary.class] ? filters : @{};
    __block NSArray<DHLogEntry *> *sourceEntries;
    dispatch_sync(self.queue, ^{ sourceEntries = [(noise ? self.noiseEntries : self.entries) copy]; });
    NSMutableArray<NSDictionary *> *matched = [NSMutableArray array];
    for (DHLogEntry *entry in sourceEntries) {
        NSDictionary *event = entry.dictionaryRepresentation;
        if ([self dictionary:event matchesFilters:filters]) [matched addObject:event];
    }
    NSString *order = [DHStringValue(filters[@"order"]) lowercaseString];
    if (![order isEqualToString:@"asc"]) matched = [[[matched reverseObjectEnumerator] allObjects] mutableCopy];
    NSUInteger limit = [filters[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [filters[@"limit"] unsignedIntegerValue] : 100;
    limit = MAX(1, MIN(limit, kDHRetainedEventLimit));
    BOOL hasMore = matched.count > limit;
    NSArray *events = hasMore ? [matched subarrayWithRange:NSMakeRange(0, limit)] : [matched copy];
    uint64_t cursor = [events.lastObject[@"seq"] unsignedLongLongValue];
    return @{
        @"events": events ?: @[], @"nextCursor": @(cursor), @"hasMore": @(hasMore),
        @"count": @(events.count), @"source": noise ? @"noise" : @"events"
    };
}

- (NSUInteger)totalCount {
    __block NSUInteger count = 0;
    dispatch_sync(self.queue, ^{ count = self.entries.count; });
    return count;
}

- (NSUInteger)noiseCount {
    __block NSUInteger count = 0;
    dispatch_sync(self.queue, ^{ count = self.noiseEntries.count; });
    return count;
}

- (void)clearFilesAtBasePath:(NSString *)path {
    NSFileManager *manager = NSFileManager.defaultManager;
    [manager removeItemAtPath:path error:nil];
    for (NSUInteger index = 1; index <= kDHLogRotationSegments; index++) {
        [manager removeItemAtPath:[path stringByAppendingFormat:@".%lu", (unsigned long)index] error:nil];
    }
}

- (void)clearAll {
    dispatch_sync(self.queue, ^{
        [self.entries removeAllObjects];
        [self.journalBuffer setLength:0];
        self.journalFlushScheduled = NO;
        [self clearFilesAtBasePath:self.logFilePath];
    });
}

- (void)clearNoise {
    dispatch_sync(self.queue, ^{
        [self.noiseEntries removeAllObjects];
        [self clearFilesAtBasePath:self.noiseLogFilePath];
    });
}

@end
