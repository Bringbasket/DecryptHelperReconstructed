#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DHLogEntry : NSObject

@property (nonatomic, copy) NSString *category;
@property (nonatomic, copy) NSString *algorithm;
@property (nonatomic, copy) NSString *operation;
@property (nonatomic, copy, nullable) NSString *detail;
@property (nonatomic, copy, nullable) NSData *input;
@property (nonatomic, copy, nullable) NSData *output;
@property (nonatomic, copy) NSArray<NSString *> *callStack;
@property (nonatomic) uint64_t timestampMs;
@property (nonatomic) uint64_t threadId;
@property (nonatomic) uint64_t sequence;
@property (nonatomic, copy) NSString *contextId;
@property (nonatomic) BOOL noise;
@property (nonatomic, copy, nullable) NSString *noiseRule;

+ (instancetype)entryWithCategory:(NSString *)category
                         algorithm:(NSString *)algorithm
                         operation:(NSString *)operation;
- (NSDictionary<NSString *, id> *)dictionaryRepresentation;

@end

@interface DHLogStore : NSObject

+ (instancetype)shared;
- (void)append:(DHLogEntry *)entry;
- (NSArray<DHLogEntry *> *)snapshot;
- (NSArray<NSDictionary<NSString *, id> *> *)dictionarySnapshot;
- (nullable NSDictionary<NSString *, id> *)eventForSequence:(uint64_t)sequence includeNoise:(BOOL)includeNoise;
- (NSDictionary<NSString *, id> *)queryWithFilters:(NSDictionary<NSString *, id> *)filters noise:(BOOL)noise;
- (NSUInteger)totalCount;
- (NSUInteger)noiseCount;
- (void)clearAll;
- (void)clearNoise;
- (NSString *)logFilePath;
- (NSString *)noiseLogFilePath;
- (NSString *)journalFilePath;
- (NSDictionary<NSString *, id> *)pipelineStats;

@end

FOUNDATION_EXPORT NSArray<NSString *> *DHFilteredCallStack(void);
FOUNDATION_EXPORT uint64_t DHTimestampMilliseconds(void);
FOUNDATION_EXPORT uint64_t DHCurrentThreadId(void);

NS_ASSUME_NONNULL_END
