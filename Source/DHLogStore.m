#import "DHLogStore.h"
#import "DHConfig.h"
#import <pthread.h>
#import <sys/time.h>

static NSString *DHDataText(NSData *data) {
    if (!data.length) return @"";
    NSString *utf8 = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (utf8) return utf8;
    return [data base64EncodedStringWithOptions:0];
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
        if ([line containsString:@"decrypt_helper"] ||
            [line containsString:@"DHFilteredCallStack"] ||
            [line containsString:@"DHLogStore"]) continue;
        [result addObject:line];
        if (result.count >= 24) break;
    }
    return result;
}

@implementation DHLogEntry

+ (instancetype)entryWithCategory:(NSString *)category
                         algorithm:(NSString *)algorithm
                         operation:(NSString *)operation {
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
        @"seq": @(self.sequence),
        @"category": self.category ?: @"OTHER",
        @"algorithm": self.algorithm ?: @"unknown",
        @"operation": self.operation ?: @"observe",
        @"timestampMs": @(self.timestampMs),
        @"threadId": @(self.threadId),
        @"contextId": self.contextId ?: @"",
        @"callStack": self.callStack ?: @[]
    } mutableCopy];
    if (self.detail) dictionary[@"detail"] = self.detail;
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
    _nextSequence = 1;
    NSString *dir = [[self logFilePath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    return self;
}

- (NSString *)logFilePath {
    return [NSHomeDirectory() stringByAppendingPathComponent:
            @"Library/Caches/IOSDecryptHub/decrypt_helper.log"];
}

- (void)append:(DHLogEntry *)entry {
    if (!entry || ![[DHConfig shared] captureEnabledForCategory:entry.category]) return;
    dispatch_async(self.queue, ^{
        entry.sequence = self.nextSequence++;
        [self.entries addObject:entry];
        if (self.entries.count > 2000) {
            [self.entries removeObjectsInRange:NSMakeRange(0, self.entries.count - 2000)];
        }
        NSData *json = [NSJSONSerialization dataWithJSONObject:entry.dictionaryRepresentation options:0 error:nil];
        if (!json) return;
        NSMutableData *line = [json mutableCopy];
        [line appendBytes:"\n" length:1];
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
        if (!handle) {
            [line writeToFile:self.logFilePath atomically:YES];
            return;
        }
        @try {
            [handle seekToEndOfFile];
            [handle writeData:line];
            [handle closeFile];
        } @catch (__unused NSException *exception) {
        }
    });
}

- (NSArray<DHLogEntry *> *)snapshot {
    __block NSArray<DHLogEntry *> *result;
    dispatch_sync(self.queue, ^{ result = [self.entries copy]; });
    return result ?: @[];
}

- (NSArray<NSDictionary<NSString *,id> *> *)dictionarySnapshot {
    NSMutableArray *result = [NSMutableArray array];
    for (DHLogEntry *entry in [self snapshot]) [result addObject:entry.dictionaryRepresentation];
    return result;
}

- (NSUInteger)totalCount {
    __block NSUInteger count = 0;
    dispatch_sync(self.queue, ^{ count = self.entries.count; });
    return count;
}

- (void)clearAll {
    dispatch_sync(self.queue, ^{
        [self.entries removeAllObjects];
        [[NSFileManager defaultManager] removeItemAtPath:self.logFilePath error:nil];
    });
}

@end
