#import "DHLogStore.h"
#import "DHConfig.h"
#import <pthread.h>
#import <sys/time.h>

static const NSUInteger kDHRetainedEventLimit = 2000;
static const unsigned long long kDHLogRotationBytes = 8ULL * 1024ULL * 1024ULL;
static const NSUInteger kDHLogRotationSegments = 3;

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
    NSString *directory = [[self logFilePath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    return self;
}

- (NSString *)logFilePath {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/IOSDecryptHub/decrypt_helper.log"];
}

- (NSString *)noiseLogFilePath {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/IOSDecryptHub/decrypt_helper.noise.log"];
}

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

- (void)appendDictionary:(NSDictionary *)dictionary toPath:(NSString *)path {
    NSData *json = [NSJSONSerialization dataWithJSONObject:dictionary options:0 error:nil];
    if (!json) return;
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    [self rotateLogAtPathIfNeeded:path incomingLength:line.length];
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!handle) {
        [line writeToFile:path atomically:YES];
        return;
    }
    @try {
        [handle seekToEndOfFile];
        [handle writeData:line];
        [handle closeFile];
    } @catch (__unused NSException *exception) {
        [handle closeFile];
    }
}

- (void)append:(DHLogEntry *)entry {
    if (!entry || ![[DHConfig shared] captureEnabledForCategory:entry.category]) return;
    dispatch_async(self.queue, ^{
        NSDictionary *candidate = entry.dictionaryRepresentation;
        NSString *ruleName = nil;
        NSString *action = [[DHConfig shared] noiseActionForEvent:candidate matchedRuleName:&ruleName];
        if ([action isEqualToString:@"drop"]) return;

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
    });
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
