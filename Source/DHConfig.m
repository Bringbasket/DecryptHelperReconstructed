#import "DHConfig.h"

@interface DHConfig ()
@property (nonatomic) BOOL networkEnabled;
@property (nonatomic) BOOL cryptoEnabled;
@property (nonatomic) BOOL keychainEnabled;
@property (nonatomic) BOOL fileEnabled;
@property (nonatomic) BOOL antiDebugEnabled;
@property (nonatomic) BOOL jailbreakHideEnabled;
@property (nonatomic) BOOL deviceSpoofEnabled;
@property (nonatomic) uint16_t httpPort;
@property (nonatomic, copy) NSDictionary<NSString *, id> *deviceValues;
@end

@implementation DHConfig

+ (instancetype)shared {
    static DHConfig *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [DHConfig new];
        [instance reload];
    });
    return instance;
}

- (void)reload {
    self.networkEnabled = YES;
    self.cryptoEnabled = YES;
    self.keychainEnabled = YES;
    self.fileEnabled = NO;
    self.antiDebugEnabled = NO;
    self.jailbreakHideEnabled = NO;
    self.deviceSpoofEnabled = NO;
    self.httpPort = 8088;
    self.deviceValues = @{};

    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:
                      @"Library/Preferences/com.decrypthelper.reconstructed.plist"];
    NSDictionary *root = [NSDictionary dictionaryWithContentsOfFile:path];
    if (![root isKindOfClass:NSDictionary.class]) return;

    id value = root[@"network"];
    if ([value respondsToSelector:@selector(boolValue)]) self.networkEnabled = [value boolValue];
    value = root[@"crypto"];
    if ([value respondsToSelector:@selector(boolValue)]) self.cryptoEnabled = [value boolValue];
    value = root[@"keychain"];
    if ([value respondsToSelector:@selector(boolValue)]) self.keychainEnabled = [value boolValue];
    value = root[@"file"];
    if ([value respondsToSelector:@selector(boolValue)]) self.fileEnabled = [value boolValue];
    value = root[@"anti_debug"];
    if ([value respondsToSelector:@selector(boolValue)]) self.antiDebugEnabled = [value boolValue];
    value = root[@"jailbreak_hide"];
    if ([value respondsToSelector:@selector(boolValue)]) self.jailbreakHideEnabled = [value boolValue];
    value = root[@"device_spoof"];
    if ([value respondsToSelector:@selector(boolValue)]) self.deviceSpoofEnabled = [value boolValue];
    value = root[@"http_port"];
    if ([value respondsToSelector:@selector(unsignedIntegerValue)]) {
        NSUInteger port = [value unsignedIntegerValue];
        if (port > 0 && port <= UINT16_MAX) self.httpPort = (uint16_t)port;
    }
    NSDictionary *device = root[@"device"];
    if ([device isKindOfClass:NSDictionary.class]) self.deviceValues = device;
}

- (NSString *)spoofValueForKey:(NSString *)key {
    id value = self.deviceValues[key];
    return [value isKindOfClass:NSString.class] ? value : nil;
}

- (NSDictionary<NSString *,id> *)publicSnapshot {
    return @{
        @"network": @(self.networkEnabled),
        @"crypto": @(self.cryptoEnabled),
        @"keychain": @(self.keychainEnabled),
        @"file": @(self.fileEnabled),
        @"anti_debug": @(self.antiDebugEnabled),
        @"jailbreak_hide": @(self.jailbreakHideEnabled),
        @"device_spoof": @(self.deviceSpoofEnabled),
        @"http_port": @(self.httpPort),
        @"device": self.deviceValues ?: @{}
    };
}

@end
