#import "DHConfig.h"

static BOOL DHRuleTextEquals(id expected, id actual) {
    if (![expected isKindOfClass:NSString.class] || ![(NSString *)expected length]) return YES;
    if (![actual isKindOfClass:NSString.class]) return NO;
    return [(NSString *)expected caseInsensitiveCompare:(NSString *)actual] == NSOrderedSame;
}

static BOOL DHRuleTextContains(id needle, id haystack) {
    if (![needle isKindOfClass:NSString.class] || ![(NSString *)needle length]) return YES;
    if (![haystack isKindOfClass:NSString.class]) return NO;
    return [(NSString *)haystack rangeOfString:(NSString *)needle options:NSCaseInsensitiveSearch].location != NSNotFound;
}

@interface DHConfig ()
@property (nonatomic) BOOL networkEnabled;
@property (nonatomic) BOOL cryptoEnabled;
@property (nonatomic) BOOL keychainEnabled;
@property (nonatomic) BOOL fileEnabled;
@property (nonatomic) BOOL dynamicEnabled;
@property (nonatomic) BOOL antiDebugEnabled;
@property (nonatomic) BOOL jailbreakHideEnabled;
@property (nonatomic) BOOL deviceSpoofEnabled;
@property (nonatomic) BOOL environmentProbeEnabled;
@property (nonatomic) BOOL floatingUIEnabled;
@property (nonatomic) BOOL webkitProbeEnabled;
@property (nonatomic) BOOL webkitProbeRedact;
@property (nonatomic) NSUInteger webkitProbeMaxBytes;
@property (nonatomic, copy) NSArray<NSString *> *webkitProbeAllowDomains;
@property (nonatomic, copy) NSArray<NSString *> *webkitProbeDenyDomains;
@property (nonatomic) BOOL paused;
@property (nonatomic, copy) NSDictionary<NSString *, NSNumber *> *pausedByCategory;
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *noiseRules;
@property (nonatomic) uint16_t httpPort;
@property (nonatomic, copy) NSDictionary<NSString *, id> *deviceValues;
@property (nonatomic, copy) NSArray<NSString *> *hiddenPaths;
@property (nonatomic, copy) NSArray<NSString *> *hiddenImages;
@property (nonatomic, copy) NSArray<NSString *> *hiddenSchemes;
@end

static NSUInteger gDHPersistFailureCount;

NSUInteger DHPersistFailureCount(void) {
    @synchronized ([DHConfig class]) { return gDHPersistFailureCount; }
}

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
    self.environmentProbeEnabled = NO;
    self.floatingUIEnabled = YES;
    self.webkitProbeEnabled = NO;
    self.webkitProbeRedact = YES;
    self.webkitProbeMaxBytes = 64 * 1024;
    self.webkitProbeAllowDomains = @[];
    self.webkitProbeDenyDomains = @[];
    self.paused = NO;
    self.pausedByCategory = @{};
    self.noiseRules = @[];
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
    value = root[@"environment_probe"] ?: root[@"environment"];
    if ([value respondsToSelector:@selector(boolValue)]) self.environmentProbeEnabled = [value boolValue];
    value = root[@"floating_ui"];
    if ([value respondsToSelector:@selector(boolValue)]) self.floatingUIEnabled = [value boolValue];
    value = root[@"webkit_probe"];
    if ([value respondsToSelector:@selector(boolValue)]) self.webkitProbeEnabled = [value boolValue];
    value = root[@"webkit_probe_redact"];
    if ([value respondsToSelector:@selector(boolValue)]) self.webkitProbeRedact = [value boolValue];
    value = root[@"webkit_probe_max_bytes"];
    if ([value respondsToSelector:@selector(unsignedIntegerValue)]) {
        NSUInteger maxBytes = [value unsignedIntegerValue];
        if (maxBytes >= 1024 && maxBytes <= 1024 * 1024) self.webkitProbeMaxBytes = maxBytes;
    }
    NSArray *webkitAllow = root[@"webkit_probe_allow_domains"];
    NSArray *webkitDeny = root[@"webkit_probe_deny_domains"];
    if ([webkitAllow isKindOfClass:NSArray.class]) self.webkitProbeAllowDomains = [self normalizedStringArray:webkitAllow fallback:self.webkitProbeAllowDomains];
    if ([webkitDeny isKindOfClass:NSArray.class]) self.webkitProbeDenyDomains = [self normalizedStringArray:webkitDeny fallback:self.webkitProbeDenyDomains];
    value = root[@"paused"];
    if ([value respondsToSelector:@selector(boolValue)]) self.paused = [value boolValue];
    NSDictionary *pausedCategories = root[@"paused_by_category"];
    if ([pausedCategories isKindOfClass:NSDictionary.class]) self.pausedByCategory = [self normalizedPausedCategories:pausedCategories];
    NSArray *noiseRules = root[@"noise_rules"];
    if ([noiseRules isKindOfClass:NSArray.class]) self.noiseRules = [self normalizedNoiseRules:noiseRules];
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

- (NSDictionary<NSString *, NSNumber *> *)normalizedPausedCategories:(NSDictionary *)values {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    [values enumerateKeysAndObjectsUsingBlock:^(id key, id value, __unused BOOL *stop) {
        if (![key isKindOfClass:NSString.class] || ![value respondsToSelector:@selector(boolValue)]) return;
        NSString *category = [(NSString *)key uppercaseString];
        if (category.length) result[category] = @([value boolValue]);
    }];
    return [result copy];
}

- (NSArray<NSDictionary<NSString *, id> *> *)normalizedNoiseRules:(NSArray *)values {
    NSSet *actions = [NSSet setWithObjects:@"route", @"drop", nil];
    NSMutableArray *result = [NSMutableArray array];
    for (id value in values) {
        if (![value isKindOfClass:NSDictionary.class]) continue;
        NSMutableDictionary *rule = [(NSDictionary *)value mutableCopy];
        NSString *action = [rule[@"action"] isKindOfClass:NSString.class] ? [rule[@"action"] lowercaseString] : @"route";
        if (![actions containsObject:action]) continue;
        rule[@"action"] = action;
        rule[@"enabled"] = @(!rule[@"enabled"] || [rule[@"enabled"] boolValue]);
        if (![rule[@"name"] isKindOfClass:NSString.class] || ![rule[@"name"] length]) {
            rule[@"name"] = [NSString stringWithFormat:@"rule-%lu", (unsigned long)result.count + 1];
        }
        [result addObject:[rule copy]];
    }
    return [result copy];
}

- (NSMutableDictionary *)mutableConfiguration {
    return [@{
        @"network": @(self.networkEnabled), @"crypto": @(self.cryptoEnabled),
        @"keychain": @(self.keychainEnabled), @"file": @(self.fileEnabled),
        @"dynamic": @(self.dynamicEnabled), @"anti_debug": @(self.antiDebugEnabled),
        @"jailbreak_hide": @(self.jailbreakHideEnabled), @"device_spoof": @(self.deviceSpoofEnabled),
        @"environment_probe": @(self.environmentProbeEnabled),
        @"floating_ui": @(self.floatingUIEnabled), @"paused": @(self.paused), @"http_port": @(self.httpPort),
        @"webkit_probe": @(self.webkitProbeEnabled), @"webkit_probe_redact": @(self.webkitProbeRedact),
        @"webkit_probe_max_bytes": @(self.webkitProbeMaxBytes),
        @"webkit_probe_allow_domains": self.webkitProbeAllowDomains ?: @[],
        @"webkit_probe_deny_domains": self.webkitProbeDenyDomains ?: @[],
        @"paused_by_category": self.pausedByCategory ?: @{}, @"noise_rules": self.noiseRules ?: @[],
        @"device": self.deviceValues ?: @{}, @"hidden_paths": self.hiddenPaths ?: @[],
        @"hidden_images": self.hiddenImages ?: @[], @"hidden_schemes": self.hiddenSchemes ?: @[]
    } mutableCopy];
}

- (BOOL)writeConfiguration:(NSError **)error {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/com.decrypthelper.reconstructed.plist"];
    NSString *directory = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:error]) {
        @synchronized ([DHConfig class]) { gDHPersistFailureCount++; }
        return NO;
    }
    BOOL success = [[self mutableConfiguration] writeToFile:path atomically:YES];
    if (!success) {
        @synchronized ([DHConfig class]) { gDHPersistFailureCount++; }
        if (error && !*error) *error = [NSError errorWithDomain:@"DHConfig" code:7 userInfo:@{NSLocalizedDescriptionKey: @"configuration could not be persisted"}];
    }
    return success;
}

- (BOOL)updateFromDictionary:(NSDictionary<NSString *,id> *)values error:(NSError **)error {
    if (![values isKindOfClass:NSDictionary.class]) {
        if (error) *error = [NSError errorWithDomain:@"DHConfig" code:1 userInfo:@{NSLocalizedDescriptionKey: @"configuration must be an object"}];
        return NO;
    }
    @synchronized (self) {
        NSDictionary *booleanKeys = @{@"network": @"networkEnabled", @"crypto": @"cryptoEnabled", @"keychain": @"keychainEnabled", @"file": @"fileEnabled", @"dynamic": @"dynamicEnabled", @"anti_debug": @"antiDebugEnabled", @"jailbreak_hide": @"jailbreakHideEnabled", @"device_spoof": @"deviceSpoofEnabled", @"environment_probe": @"environmentProbeEnabled", @"environment": @"environmentProbeEnabled", @"floating_ui": @"floatingUIEnabled", @"webkit_probe": @"webkitProbeEnabled", @"webkit_probe_redact": @"webkitProbeRedact", @"paused": @"paused"};
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
        id maxBytesValue = values[@"webkit_probe_max_bytes"];
        if ([maxBytesValue respondsToSelector:@selector(unsignedIntegerValue)]) {
            NSUInteger maxBytes = [maxBytesValue unsignedIntegerValue];
            if (maxBytes < 1024 || maxBytes > 1024 * 1024) {
                if (error) *error = [NSError errorWithDomain:@"DHConfig" code:8 userInfo:@{NSLocalizedDescriptionKey: @"webkit_probe_max_bytes must be between 1024 and 1048576"}];
                return NO;
            }
            self.webkitProbeMaxBytes = maxBytes;
        }
        id device = values[@"device"];
        if ([device isKindOfClass:NSDictionary.class]) self.deviceValues = [device copy];
        id pausedCategories = values[@"paused_by_category"];
        if ([pausedCategories isKindOfClass:NSDictionary.class]) self.pausedByCategory = [self normalizedPausedCategories:pausedCategories];
        id noiseRules = values[@"noise_rules"];
        if ([noiseRules isKindOfClass:NSArray.class]) self.noiseRules = [self normalizedNoiseRules:noiseRules];
        id webkitAllow = values[@"webkit_probe_allow_domains"];
        id webkitDeny = values[@"webkit_probe_deny_domains"];
        if ([webkitAllow isKindOfClass:NSArray.class]) self.webkitProbeAllowDomains = [self normalizedStringArray:webkitAllow fallback:self.webkitProbeAllowDomains];
        if ([webkitDeny isKindOfClass:NSArray.class]) self.webkitProbeDenyDomains = [self normalizedStringArray:webkitDeny fallback:self.webkitProbeDenyDomains];
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

- (BOOL)setPaused:(BOOL)paused forCategory:(NSString *)category error:(NSError **)error {
    NSString *upper = [category isKindOfClass:NSString.class] ? category.uppercaseString : @"";
    if (!upper.length) {
        if (error) *error = [NSError errorWithDomain:@"DHConfig" code:4 userInfo:@{NSLocalizedDescriptionKey: @"category is required"}];
        return NO;
    }
    NSMutableDictionary *categories = [self.pausedByCategory mutableCopy] ?: [NSMutableDictionary dictionary];
    if (paused) categories[upper] = @YES;
    else [categories removeObjectForKey:upper];
    return [self updateFromDictionary:@{@"paused_by_category": categories} error:error];
}

- (BOOL)captureEnabledForCategory:(NSString *)category {
    NSString *upper = category.uppercaseString;
    if (self.paused && ![upper isEqualToString:@"DIAGNOSTIC"]) return NO;
    if ([self.pausedByCategory[upper] boolValue] && ![upper isEqualToString:@"DIAGNOSTIC"]) return NO;
    if ([upper isEqualToString:@"NETWORK"]) return self.networkEnabled;
    if ([upper isEqualToString:@"KEYCHAIN"]) return self.keychainEnabled;
    if ([upper hasPrefix:@"FILE_"]) return self.fileEnabled;
    if ([upper isEqualToString:@"SYS_DYNAMIC"]) return self.dynamicEnabled;
    if ([upper isEqualToString:@"CRYPTO"] || [upper isEqualToString:@"DIGEST"] ||
        [upper isEqualToString:@"HMAC"] || [upper isEqualToString:@"ASYMMETRIC"] ||
        [upper isEqualToString:@"EVP"] || [upper isEqualToString:@"RNG"]) return self.cryptoEnabled;
    if ([upper isEqualToString:@"ENV_PROBE"]) return self.environmentProbeEnabled;
    return YES;
}

- (NSString *)noiseActionForEvent:(NSDictionary<NSString *,id> *)event matchedRuleName:(NSString **)ruleName {
    if (![event isKindOfClass:NSDictionary.class]) return nil;
    for (NSDictionary *rule in self.noiseRules ?: @[]) {
        if (![rule[@"enabled"] boolValue]) continue;
        if (!DHRuleTextEquals(rule[@"category"], event[@"category"])) continue;
        if (!DHRuleTextEquals(rule[@"algorithm"], event[@"algorithm"])) continue;
        if (!DHRuleTextEquals(rule[@"operation"], event[@"operation"])) continue;
        if (!DHRuleTextEquals(rule[@"requestId"], event[@"requestId"])) continue;
        if (!DHRuleTextEquals(rule[@"contextId"], event[@"contextId"])) continue;
        if (!DHRuleTextContains(rule[@"detailContains"], event[@"detail"])) continue;
        NSString *stack = [event[@"callStack"] isKindOfClass:NSArray.class] ? [event[@"callStack"] componentsJoinedByString:@"\n"] : @"";
        if (!DHRuleTextContains(rule[@"stackContains"], stack)) continue;
        if (ruleName) *ruleName = rule[@"name"];
        return rule[@"action"];
    }
    return nil;
}

- (NSString *)spoofValueForKey:(NSString *)key {
    id value = self.deviceValues[key];
    return [value isKindOfClass:NSString.class] ? value : nil;
}

- (BOOL)updateSpoofRuleOperation:(NSString *)operation
                            kind:(NSString *)kind
                           value:(NSString *)value
                           error:(NSError **)error {
    NSString *op = [operation isKindOfClass:NSString.class] ? operation.lowercaseString : @"";
    NSString *ruleKind = [kind isKindOfClass:NSString.class] ? kind.lowercaseString : @"";
    NSString *rule = [value isKindOfClass:NSString.class] ? [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] : @"";
    NSDictionary *keys = @{@"path": @"hiddenPaths", @"paths": @"hiddenPaths", @"image": @"hiddenImages", @"images": @"hiddenImages", @"scheme": @"hiddenSchemes", @"schemes": @"hiddenSchemes"};
    NSString *property = keys[ruleKind];
    if (![op isEqualToString:@"add"] && ![op isEqualToString:@"remove"]) {
        if (error) *error = [NSError errorWithDomain:@"DHConfig" code:5 userInfo:@{NSLocalizedDescriptionKey: @"operation must be add or remove"}];
        return NO;
    }
    NSData *encodedRule = [rule dataUsingEncoding:NSUTF8StringEncoding];
    NSData *nulByte = [NSData dataWithBytes:"\0" length:1];
    BOOL hasNUL = encodedRule && [encodedRule rangeOfData:nulByte options:0 range:NSMakeRange(0, encodedRule.length)].location != NSNotFound;
    if (!property.length || !rule.length || rule.length > 512 || hasNUL) {
        if (error) *error = [NSError errorWithDomain:@"DHConfig" code:6 userInfo:@{NSLocalizedDescriptionKey: @"kind and a bounded value are required"}];
        return NO;
    }
    @synchronized (self) {
        NSMutableArray *rules = [[self valueForKey:property] mutableCopy] ?: [NSMutableArray array];
        NSUInteger index = [rules indexOfObjectPassingTest:^BOOL(NSString *candidate, NSUInteger idx, BOOL *stop) {
            return [candidate caseInsensitiveCompare:rule] == NSOrderedSame;
        }];
        if ([op isEqualToString:@"add"]) {
            if (index == NSNotFound) [rules addObject:rule];
        } else if (index != NSNotFound) {
            [rules removeObjectAtIndex:index];
        }
        [self setValue:[rules copy] forKey:property];
        return [self writeConfiguration:error];
    }
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
        @"environment_probe": @(self.environmentProbeEnabled),
        @"floating_ui": @(self.floatingUIEnabled),
        @"webkit_probe": @(self.webkitProbeEnabled),
        @"webkit_probe_redact": @(self.webkitProbeRedact),
        @"webkit_probe_max_bytes": @(self.webkitProbeMaxBytes),
        @"webkit_probe_allow_domains": self.webkitProbeAllowDomains ?: @[],
        @"webkit_probe_deny_domains": self.webkitProbeDenyDomains ?: @[],
        @"paused": @(self.paused),
        @"paused_by_category": self.pausedByCategory ?: @{},
        @"noise_rules": self.noiseRules ?: @[],
        @"http_port": @(self.httpPort),
        @"device": self.deviceValues ?: @{},
        @"hidden_paths": self.hiddenPaths ?: @[],
        @"hidden_images": self.hiddenImages ?: @[],
        @"hidden_schemes": self.hiddenSchemes ?: @[]
    };
}

@end
