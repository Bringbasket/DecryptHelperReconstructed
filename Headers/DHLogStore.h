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
- (NSUInteger)totalCount;
- (void)clearAll;
- (NSString *)logFilePath;

@end

FOUNDATION_EXPORT NSArray<NSString *> *DHFilteredCallStack(void);
FOUNDATION_EXPORT uint64_t DHTimestampMilliseconds(void);
FOUNDATION_EXPORT uint64_t DHCurrentThreadId(void);

NS_ASSUME_NONNULL_END
