#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DHConfig : NSObject

@property (nonatomic, readonly) BOOL networkEnabled;
@property (nonatomic, readonly) BOOL cryptoEnabled;
@property (nonatomic, readonly) BOOL keychainEnabled;
@property (nonatomic, readonly) BOOL fileEnabled;
@property (nonatomic, readonly) BOOL antiDebugEnabled;
@property (nonatomic, readonly) BOOL jailbreakHideEnabled;
@property (nonatomic, readonly) BOOL deviceSpoofEnabled;
@property (nonatomic, readonly) uint16_t httpPort;

+ (instancetype)shared;
- (void)reload;
- (nullable NSString *)spoofValueForKey:(NSString *)key;
- (NSDictionary<NSString *, id> *)publicSnapshot;

@end

NS_ASSUME_NONNULL_END
