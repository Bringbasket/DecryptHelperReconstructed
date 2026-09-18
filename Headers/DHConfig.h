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
@property (nonatomic, readonly) BOOL floatingUIEnabled;
@property (nonatomic, readonly, getter=isPaused) BOOL paused;
@property (nonatomic, readonly) uint16_t httpPort;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenPaths;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenImages;
@property (nonatomic, readonly, copy) NSArray<NSString *> *hiddenSchemes;

+ (instancetype)shared;
- (void)reload;
- (BOOL)updateFromDictionary:(NSDictionary<NSString *, id> *)values error:(NSError * _Nullable * _Nullable)error;
- (BOOL)setCaptureEnabled:(BOOL)enabled forCategory:(NSString *)category error:(NSError * _Nullable * _Nullable)error;
- (BOOL)setPaused:(BOOL)paused error:(NSError * _Nullable * _Nullable)error;
- (BOOL)captureEnabledForCategory:(NSString *)category;
- (nullable NSString *)spoofValueForKey:(NSString *)key;
- (NSDictionary<NSString *, id> *)publicSnapshot;

@end

NS_ASSUME_NONNULL_END
