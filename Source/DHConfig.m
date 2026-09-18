#import "DHConfig.h"

@interface DHConfig ()
@property (nonatomic) BOOL networkEnabled;
@property (nonatomic) BOOL cryptoEnabled;
@property (nonatomic) BOOL keychainEnabled;
@property (nonatomic) BOOL fileEnabled;
@property (nonatomic) BOOL dynamicEnabled;
@property (nonatomic) BOOL antiDebugEnabled;
@property (nonatomic) BOOL jailbreakHideEnabled;
@property (nonatomic) BOOL deviceSpoofEnabled;
@property (nonatomic) BOOL paused;
@property (nonatomic) uint16_t httpPort;
@property (nonatomic, copy) NSDictionary<NSString *, id> *deviceValues;
@property (nonatomic, copy) NSArray<NSString *> *hiddenPaths;
@property (nonatomic, copy) NSArray<NSString *> *hiddenImages;
@property (nonatomic, copy) NSArray<NSString *> *hiddenSchemes;
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
    self.dynamicEnabled = NO;
    self.antiDebugEnabled = NO;
    self.jailbreakHideEnabled = NO;
    self.deviceSpoofEnabled = NO;
    self.paused = NO;
    self.httpPort = 8088;
    self.deviceValues = @{};
    self.hiddenPaths = @[
        @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
        @"/Applications/Filza.app", @"/Library/MobileSubstrate", @"/usr/sbin/sshd",
        @"/usr/bin/ssh", @"/usr/libexec/cydia", @"/usr/libexec/sftp-server",
        @"/usr/lib/libjailbreak.dylib", @"/bin/bash", @"/etc/apt", @"/private/var/lib/apt",
        @"/private/var/lib/cydia", @"/private/var/stash", @"/private/var/tmp/cydia.log",
        @"/var/jb", @"/var/binpack"
    ];
    self.hiddenImages = @[
        @"decrypt_helper", @"MobileSubstrate", @"SubstrateLoader", @"SubstrateInserter",
        @"TweakInject", @"libhooker", @"libsubstitute", @"substitute", @"ellekit",
        @"RocketBootstrap", @"cynject", @"libjailbreak", @"Cephei", @"Choicy", @"DynamicLibraries"
    ];
    self.hiddenSchemes = @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator", @"apt-repo"];

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
    value = root[@"dynamic"];
    if ([value respondsToSelector:@selector(boolValue)]) self.dynamicEnabled = [value boolValue];
    value = root[@"anti_debug"];
    if ([value respondsToSelector:@selector(boolValue)]) self.antiDebugEnabled = [value boolValue];
    value = root[@"jailbreak_hide"];
    if ([value respondsToSelector:@selector(boolValue)]) self.jailbreakHideEnabled = [value boolValue];
    value = root[@"device_spoof"];
    if ([value respondsToSelector:@selector(boolValue)]) self.deviceSpoofEnabled = [value boolValue];
    value = root[@"paused"];
    if ([value respondsToSelector:@selector(boolValue)]) self.paused = [value boolValue];
    value = root[@"http_port"];
    if ([value respondsToSelector:@selector(unsignedIntegerValue)]) {
        NSUInteger port = [value unsignedIntegerValue];
        if (port > 0 && port <= UINT16_MAX) self.httpPort = (uint16_t)port;
    }
    NSDictionary *device = root[@"device"];
    if ([device isKindOfClass:NSDictionary.class]) self.deviceValues = device;
    NSArray *paths = root[@"hidden_paths"];
    if ([paths isKindOfClass:NSArray.class]) self.hiddenPaths = [self normalizedStringArray:paths fallback:self.hiddenPaths];
    NSArray *images = root[@"hidden_images"];
    if ([images isKindOfClass:NSArray.class]) self.hiddenImages = [self normalizedStringArray:images fallback:self.hiddenImages];
    NSArray *schemes = root[@"hidden_schemes"];
    if ([schemes isKindOfClass:NSArray.class]) self.hiddenSchemes = [self normalizedStringArray:schemes fallback:self.hiddenSchemes];
}

- (NSArray<NSString *> *)normalizedStringArray:(NSArray *)values fallback:(NSArray<NSString *> *)fallback {
    NSMutableArray *result = [NSMutableArray array];
    for (id item in values) if ([item isKindOfClass:NSString.class] && [(NSString *)item length]) [result addObject:item];
    return result.count ? [result copy] : fallback;
}

- (NSMutableDictionary *)mutableConfiguration {
    return [@{
        @"network": @(self.networkEnabled), @"crypto": @(self.cryptoEnabled),
        @"keychain": @(self.keychainEnabled), @"file": @(self.fileEnabled),
        @"dynamic": @(self.dynamicEnabled), @"anti_debug": @(self.antiDebugEnabled),
        @"jailbreak_hide": @(self.jailbreakHideEnabled), @"device_spoof": @(self.deviceSpoofEnabled),
        @"paused": @(self.paused), @"http_port": @(self.httpPort),
        @"device": self.deviceValues ?: @{}, @"hidden_paths": self.hiddenPaths ?: @[],
        @"hidden_images": self.hiddenImages ?: @[], @"hidden_schemes": self.hiddenSchemes ?: @[]
    } mutableCopy];
}

- (BOOL)writeConfiguration:(NSError **)error {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/com.decrypthelper.reconstructed.plist"];
    NSString *directory = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    return [[self mutableConfiguration] writeToFile:path atomically:YES];
}

- (BOOL)updateFromDictionary:(NSDictionary<NSString *,id> *)values error:(NSError **)error {
    if (![values isKindOfClass:NSDictionary.class]) {
        if (error) *error = [NSError errorWithDomain:@"DHConfig" code:1 userInfo:@{NSLocalizedDescriptionKey: @"configuration must be an object"}];
        return NO;
    }
    @synchronized (self) {
        NSDictionary *booleanKeys = @{@"network": @"networkEnabled", @"crypto": @"cryptoEnabled", @"keychain": @"keychainEnabled", @"file": @"fileEnabled", @"dynamic": @"dynamicEnabled", @"anti_debug": @"antiDebugEnabled", @"jailbreak_hide": @"jailbreakHideEnabled", @"device_spoof": @"deviceSpoofEnabled", @"paused": @"paused"};
        for (NSString *key in booleanKeys) {
            id value = values[key];
            if ([value respondsToSelector:@selector(boolValue)]) [self setValue:@([value boolValue]) forKey:booleanKeys[key]];
        }
        id port = values[@"http_port"];
        if ([port respondsToSelector:@selector(unsignedIntegerValue)]) {
            NSUInteger number = [port unsignedIntegerValue];
            if (number == 0 || number > UINT16_MAX) { if (error) *error = [NSError errorWithDomain:@"DHConfig" code:2 userInfo:@{NSLocalizedDescriptionKey: @"http_port must be between 1 and 65535"}]; return NO; }
            self.httpPort = (uint16_t)number;
        }
        id device = values[@"device"];
        if ([device isKindOfClass:NSDictionary.class]) self.deviceValues = [device copy];
        NSArray *paths = values[@"hidden_paths"], *images = values[@"hidden_images"], *schemes = values[@"hidden_schemes"];
        if ([paths isKindOfClass:NSArray.class]) self.hiddenPaths = [self normalizedStringArray:paths fallback:self.hiddenPaths];
        if ([images isKindOfClass:NSArray.class]) self.hiddenImages = [self normalizedStringArray:images fallback:self.hiddenImages];
        if ([schemes isKindOfClass:NSArray.class]) self.hiddenSchemes = [self normalizedStringArray:schemes fallback:self.hiddenSchemes];
        return [self writeConfiguration:error];
    }
}

- (BOOL)setCaptureEnabled:(BOOL)enabled forCategory:(NSString *)category error:(NSError **)error {
    NSString *key = category.lowercaseString;
    NSDictionary *map = @{@"network": @"network", @"crypto": @"crypto", @"keychain": @"keychain", @"file": @"file", @"dynamic": @"dynamic"};
    NSString *configKey = map[key];
    if (!configKey) { if (error) *error = [NSError errorWithDomain:@"DHConfig" code:3 userInfo:@{NSLocalizedDescriptionKey: @"unknown capture category"}]; return NO; }
    return [self updateFromDictionary:@{configKey: @(enabled)} error:error];
}

- (BOOL)setPaused:(BOOL)paused error:(NSError **)error { return [self updateFromDictionary:@{@"paused": @(paused)} error:error]; }

- (BOOL)captureEnabledForCategory:(NSString *)category {
    if (self.paused && ![category.uppercaseString isEqualToString:@"DIAGNOSTIC"]) return NO;
    NSString *upper = category.uppercaseString;
    if ([upper isEqualToString:@"NETWORK"]) return self.networkEnabled;
    if ([upper isEqualToString:@"KEYCHAIN"]) return self.keychainEnabled;
    if ([upper hasPrefix:@"FILE_"]) return self.fileEnabled;
    if ([upper isEqualToString:@"SYS_DYNAMIC"]) return self.dynamicEnabled;
    if ([upper isEqualToString:@"CRYPTO"] || [upper isEqualToString:@"DIGEST"] || [upper isEqualToString:@"HMAC"] || [upper isEqualToString:@"ASYMMETRIC"]) return self.cryptoEnabled;
    if ([upper isEqualToString:@"ENV_PROBE"]) return self.antiDebugEnabled || self.jailbreakHideEnabled || self.deviceSpoofEnabled;
    return YES;
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
        @"dynamic": @(self.dynamicEnabled),
        @"anti_debug": @(self.antiDebugEnabled),
        @"jailbreak_hide": @(self.jailbreakHideEnabled),
        @"device_spoof": @(self.deviceSpoofEnabled),
        @"paused": @(self.paused),
        @"http_port": @(self.httpPort),
        @"device": self.deviceValues ?: @{},
        @"hidden_paths": self.hiddenPaths ?: @[],
        @"hidden_images": self.hiddenImages ?: @[],
        @"hidden_schemes": self.hiddenSchemes ?: @[]
    };
}

@end
