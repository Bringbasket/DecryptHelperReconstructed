#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DHConfig : NSObject

@property (nonatomic, readonly) BOOL networkEnabled;
@property (nonatomic, readonly) BOOL cryptoEnabled;
@property (nonatomic, readonly) BOOL keychainEnabled;
@property (nonatomic, readonly) BOOL fileEnabled;
@property (nonatomic, readonly) BOOL dynamicEnabled;
@property (nonatomic, readonly) BOOL antiDebugEnabled;
@property (nonatomic, readonly) BOOL jailbreakHideEnabled;
@property (nonatomic, readonly) BOOL deviceSpoofEnabled;
@property (nonatomic, readonly) BOOL environmentProbeEnabled;
@property (nonatomic, readonly) BOOL floatingUIEnabled;
@property (nonatomic, readonly) BOOL webkitProbeEnabled;
@property (nonatomic, readonly) BOOL webkitProbeRedact;
@property (nonatomic, readonly) NSUInteger webkitProbeMaxBytes;
@property (nonatomic, readonly, copy) NSArray<NSString *> *webkitProbeAllowDomains;
@property (nonatomic, readonly, copy) NSArray<NSString *> *webkitProbeDenyDomains;
@property (nonatomic, readonly, getter=isPaused) BOOL paused;
@property (nonatomic, readonly, copy) NSDictionary<NSString *, NSNumber *> *pausedByCategory;
@property (nonatomic, readonly, copy) NSArray<NSDictionary<NSString *, id> *> *noiseRules;
@property (nonatomic, readonly) uint16_t httpPort;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenPaths;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenImages;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenSchemes;

+ (instancetype)shared;
- (void)reload;
- (BOOL)updateFromDictionary:(NSDictionary<NSString *, id> *)values error:(NSError * _Nullable * _Nullable)error;
- (BOOL)setCaptureEnabled:(BOOL)enabled forCategory:(NSString *)category error:(NSError * _Nullable * _Nullable)error;
- (BOOL)setPaused:(BOOL)paused error:(NSError * _Nullable * _Nullable)error;
- (BOOL)setPaused:(BOOL)paused forCategory:(NSString *)category error:(NSError * _Nullable * _Nullable)error;
- (BOOL)captureEnabledForCategory:(NSString *)category;
- (nullable NSString *)noiseActionForEvent:(NSDictionary<NSString *, id> *)event
                           matchedRuleName:(NSString * _Nullable * _Nullable)ruleName;
- (nullable NSString *)spoofValueForKey:(NSString *)key;
- (BOOL)updateSpoofRuleOperation:(NSString *)operation
                            kind:(NSString *)kind
                           value:(NSString *)value
                           error:(NSError * _Nullable * _Nullable)error;
- (NSDictionary<NSString *, id> *)publicSnapshot;

@end

NS_ASSUME_NONNULL_END

FOUNDATION_EXPORT NSUInteger DHPersistFailureCount(void);
