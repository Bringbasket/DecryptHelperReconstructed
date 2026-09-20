#import "DHSpoof.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <mach-o/dyld.h>
#import <errno.h>
#import <stdint.h>
#import <string.h>
#import <strings.h>
#import <sys/types.h>
#import <unistd.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000u
#endif
#ifndef P_TRACED
#define P_TRACED 0x00000800u
#endif

static __thread int gSpoofGuard;
static __thread int gEnvironmentLogGuard;
static NSUInteger gDHEnvironmentProbeCount;

NSUInteger DHEnvironmentProbeCount(void) {
    @synchronized ([DHConfig class]) { return gDHEnvironmentProbeCount; }
}

static const char *kHiddenPaths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
    "/Applications/Filza.app", "/Library/MobileSubstrate", "/usr/sbin/sshd",
    "/usr/bin/ssh", "/usr/libexec/cydia", "/usr/libexec/sftp-server",
    "/usr/lib/libjailbreak.dylib", "/bin/bash", "/etc/apt",
    "/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/stash",
    "/private/var/tmp/cydia.log", "/var/jb", "/var/binpack"
};

static const char *kHiddenImages[] = {
    "decrypt_helper", "MobileSubstrate", "SubstrateLoader", "SubstrateInserter",
    "TweakInject", "libhooker", "libsubstitute", "substitute", "ellekit",
    "RocketBootstrap", "cynject", "libjailbreak", "Cephei", "Choicy",
    "DynamicLibraries"
};

static const char *kHiddenSchemes[] = {
    "cydia", "sileo", "zbra", "filza", "undecimus", "activator", "apt-repo"
};

static BOOL DHContainsCaseInsensitive(const char *text, const char *needle) {
    if (!text || !needle) return NO;
    size_t textLength = strlen(text), needleLength = strlen(needle);
    if (!needleLength || needleLength > textLength) return NO;
    for (size_t i = 0; i + needleLength <= textLength; i++) {
        if (strncasecmp(text + i, needle, needleLength) == 0) return YES;
    }
    return NO;
}

static BOOL DHShouldHidePath(const char *path) {
    if (!path || ![DHConfig shared].jailbreakHideEnabled) return NO;
    NSArray<NSString *> *rules = [DHConfig shared].hiddenPaths;
    if (!rules.count) for (size_t i = 0; i < sizeof(kHiddenPaths) / sizeof(kHiddenPaths[0]); i++) {
        if (DHContainsCaseInsensitive(path, kHiddenPaths[i])) return YES;
    }
    for (NSString *rule in rules) {
        if (DHContainsCaseInsensitive(path, rule.UTF8String)) return YES;
    }
    return NO;
}

static BOOL DHShouldHideImage(const char *path) {
    if (!path || ![DHConfig shared].jailbreakHideEnabled) return NO;
    NSArray<NSString *> *rules = [DHConfig shared].hiddenImages;
    if (!rules.count) for (size_t i = 0; i < sizeof(kHiddenImages) / sizeof(kHiddenImages[0]); i++) {
        if (DHContainsCaseInsensitive(path, kHiddenImages[i])) return YES;
    }
    for (NSString *rule in rules) {
        if (DHContainsCaseInsensitive(path, rule.UTF8String)) return YES;
    }
    return NO;
}

BOOL DHSpoofMatchesImagePath(const char *path) {
    return DHShouldHideImage(path);
}

static BOOL DHShouldHideScheme(NSString *scheme) {
    if (!scheme.length || ![DHConfig shared].jailbreakHideEnabled) return NO;
    NSArray *rules = [DHConfig shared].hiddenSchemes;
    if (!rules.count) for (size_t i = 0; i < sizeof(kHiddenSchemes) / sizeof(kHiddenSchemes[0]); i++) {
        if ([scheme rangeOfString:[NSString stringWithUTF8String:kHiddenSchemes[i]] options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    for (NSString *rule in rules) if ([scheme rangeOfString:rule options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static BOOL DHMatchesJailbreakEnvironmentName(const char *name) {
    if (!name || ![DHConfig shared].jailbreakHideEnabled) return NO;
    static const char *names[] = {"DYLD_INSERT_LIBRARIES", "_MSSafeMode", "JB_ROOT_PATH", "LIBHOOKER_CONFIGURATOR_PATH"};
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (strcasecmp(name, names[index]) == 0) return YES;
    }
    return NO;
}

static BOOL DHHasDeviceRule(NSString *key) {
    return [DHConfig shared].deviceSpoofEnabled && [[DHConfig shared] spoofValueForKey:key].length > 0;
}

static BOOL DHIgnoreEnvironmentPath(const char *path) {
    if (!path) return NO;
    return strstr(path, "/Library/Caches/IOSDecryptHub/") != NULL ||
           strstr(path, "/Library/Preferences/com.decrypthelper.reconstructed.plist") != NULL ||
           strstr(path, "/usr/lib/IOSDecryptHub/") != NULL;
}

static void DHRecordEnvironmentProbeImpl(NSString *name, NSString *detail) {
    if (gEnvironmentLogGuard) return;
    gEnvironmentLogGuard++;
    @synchronized ([DHConfig class]) { gDHEnvironmentProbeCount++; }
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"ENV_PROBE"
                                            algorithm:name
                                            operation:@"observe"];
    entry.detail = detail;
    [[DHLogStore shared] append:entry];
    gEnvironmentLogGuard--;
}

#define DHRecordEnvironmentProbe(name, ...) do { \
    if ([DHConfig shared].environmentProbeEnabled) DHRecordEnvironmentProbeImpl((name), (__VA_ARGS__)); \
} while (0)

typedef int (*DHPTraceFn)(int, pid_t, caddr_t, int);
typedef int (*DHCSOpsFn)(pid_t, unsigned int, void *, size_t);
typedef int (*DHSysctlFn)(int *, u_int, void *, size_t *, void *, size_t);
typedef int (*DHSysctlByNameFn)(const char *, void *, size_t *, void *, size_t);

static DHPTraceFn gOriginalPtrace;
static DHCSOpsFn gOriginalCSOps;
static DHSysctlFn gOriginalSysctl;
static DHSysctlByNameFn gOriginalSysctlByName;

static int DHHookedPtrace(int request, pid_t pid, caddr_t address, int data) {
    int result = gOriginalPtrace ? gOriginalPtrace(request, pid, address, data) : -1;
    BOOL matched = [DHConfig shared].antiDebugEnabled && request == PT_DENY_ATTACH;
    DHRecordEnvironmentProbe(@"ptrace", [NSString stringWithFormat:@"request=%d result=%d matchedRule=%@", request, result, matched ? @YES : @NO]);
    return result;
}

static int DHHookedCSOps(pid_t pid, unsigned int operation, void *userAddress, size_t size) {
    int result = gOriginalCSOps ? gOriginalCSOps(pid, operation, userAddress, size) : -1;
    BOOL matched = [DHConfig shared].antiDebugEnabled && operation == CS_OPS_STATUS;
    DHRecordEnvironmentProbe(@"csops", [NSString stringWithFormat:@"operation=%u result=%d size=%lu matchedRule=%@", operation, result, (unsigned long)size, matched ? @YES : @NO]);
    return result;
}

static int DHHookedSysctl(int *name, u_int count, void *oldValue, size_t *oldLength,
                          void *newValue, size_t newLength) {
    int result = gOriginalSysctl ? gOriginalSysctl(name, count, oldValue, oldLength, newValue, newLength) : -1;
    BOOL matched = [DHConfig shared].antiDebugEnabled && name && count >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC;
    DHRecordEnvironmentProbe(@"sysctl", [NSString stringWithFormat:@"count=%u result=%d matchedRule=%@", count, result, matched ? @YES : @NO]);
    return result;
}

static int DHHookedSysctlByName(const char *name, void *oldValue, size_t *oldLength,
                                void *newValue, size_t newLength) {
    int result = gOriginalSysctlByName ? gOriginalSysctlByName(name, oldValue, oldLength, newValue, newLength) : -1;
    NSString *key = name ? [NSString stringWithUTF8String:name] : @"";
    NSDictionary *mapping = @{@"hw.machine": @"hw_machine", @"hw.model": @"hw_model", @"kern.osversion": @"os_version"};
    NSString *mappedKey = [mapping[key] isKindOfClass:NSString.class] ? mapping[key] : nil;
    BOOL matched = mappedKey.length > 0 && DHHasDeviceRule(mappedKey);
    DHRecordEnvironmentProbe(@"sysctlbyname", [NSString stringWithFormat:@"name=%@ result=%d matchedRule=%@", key, result, matched ? @YES : @NO]);
    return result;
}

typedef int (*DHStatFn)(const char *, struct stat *);
typedef int (*DHFStatAtFn)(int, const char *, struct stat *, int);
typedef int (*DHAccessFn)(const char *, int);
typedef int (*DHFaccessAtFn)(int, const char *, int, int);
typedef char *(*DHGetenvFn)(const char *);
typedef int (*DHUnameFn)(struct utsname *);
typedef const char *(*DHDyldImageNameFn)(uint32_t);

static DHStatFn gOriginalStat, gOriginalLstat;
static DHFStatAtFn gOriginalFstatat;
static DHAccessFn gOriginalAccess;
static DHFaccessAtFn gOriginalFaccessat;
static DHGetenvFn gOriginalGetenv;
static DHUnameFn gOriginalUname;
static DHDyldImageNameFn gOriginalDyldImageName;

static BOOL DHBeginHideCheck(const char *path) {
    if (gSpoofGuard) return NO;
    gSpoofGuard++;
    BOOL hidden = DHShouldHidePath(path);
    gSpoofGuard--;
    return hidden;
}

static BOOL DHBeginImageHideCheck(const char *path) {
    if (gSpoofGuard) return NO;
    gSpoofGuard++;
    BOOL hidden = DHShouldHideImage(path);
    gSpoofGuard--;
    return hidden;
}

static int DHHookedStat(const char *path, struct stat *buffer) {
    int result = gOriginalStat ? gOriginalStat(path, buffer) : -1;
    if (DHIgnoreEnvironmentPath(path)) return result;
    DHRecordEnvironmentProbe(@"stat", [NSString stringWithFormat:@"path=%@ result=%d matchedRule=%@", path ? [NSString stringWithUTF8String:path] : @"", result, DHBeginHideCheck(path) ? @YES : @NO]);
    return result;
}

static int DHHookedLstat(const char *path, struct stat *buffer) {
    int result = gOriginalLstat ? gOriginalLstat(path, buffer) : -1;
    if (DHIgnoreEnvironmentPath(path)) return result;
    DHRecordEnvironmentProbe(@"lstat", [NSString stringWithFormat:@"path=%@ result=%d matchedRule=%@", path ? [NSString stringWithUTF8String:path] : @"", result, DHBeginHideCheck(path) ? @YES : @NO]);
    return result;
}

static int DHHookedAccess(const char *path, int mode) {
    int result = gOriginalAccess ? gOriginalAccess(path, mode) : -1;
    if (DHIgnoreEnvironmentPath(path)) return result;
    DHRecordEnvironmentProbe(@"access", [NSString stringWithFormat:@"path=%@ mode=%d result=%d matchedRule=%@", path ? [NSString stringWithUTF8String:path] : @"", mode, result, DHBeginHideCheck(path) ? @YES : @NO]);
    return result;
}

static int DHHookedFaccessat(int fd, const char *path, int mode, int flags) {
    int result = gOriginalFaccessat ? gOriginalFaccessat(fd, path, mode, flags) : -1;
    if (DHIgnoreEnvironmentPath(path)) return result;
    DHRecordEnvironmentProbe(@"faccessat", [NSString stringWithFormat:@"path=%@ result=%d matchedRule=%@", path ? [NSString stringWithUTF8String:path] : @"", result, DHBeginHideCheck(path) ? @YES : @NO]);
    return result;
}

static int DHHookedFstatat(int fd, const char *path, struct stat *buffer, int flags) {
    int result = gOriginalFstatat ? gOriginalFstatat(fd, path, buffer, flags) : -1;
    if (DHIgnoreEnvironmentPath(path)) return result;
    DHRecordEnvironmentProbe(@"fstatat", [NSString stringWithFormat:@"path=%@ result=%d matchedRule=%@", path ? [NSString stringWithUTF8String:path] : @"", result, DHBeginHideCheck(path) ? @YES : @NO]);
    return result;
}

static char *DHHookedGetenv(const char *name) {
    char *value = gOriginalGetenv ? gOriginalGetenv(name) : NULL;
    DHRecordEnvironmentProbe(@"getenv", [NSString stringWithFormat:@"name=%@ present=%@ matchedRule=%@", name ? [NSString stringWithUTF8String:name] : @"", value ? @YES : @NO, DHMatchesJailbreakEnvironmentName(name) ? @YES : @NO]);
    return value;
}

static int DHHookedUname(struct utsname *name) {
    int result = gOriginalUname ? gOriginalUname(name) : -1;
    BOOL matched = DHHasDeviceRule(@"hw_machine") || DHHasDeviceRule(@"os_version");
    DHRecordEnvironmentProbe(@"uname", [NSString stringWithFormat:@"result=%d machine=%@ matchedRule=%@", result, (result == 0 && name) ? [NSString stringWithUTF8String:name->machine] : @"", matched ? @YES : @NO]);
    return result;
}

static const char *DHHookedDyldImageName(uint32_t index) {
    const char *path = gOriginalDyldImageName ? gOriginalDyldImageName(index) : NULL;
    DHRecordEnvironmentProbe(@"dyld_image_name", [NSString stringWithFormat:@"index=%u path=%@ matchedRule=%@", index, path ? [NSString stringWithUTF8String:path] : @"", DHBeginImageHideCheck(path) ? @YES : @NO]);
    return path;
}

static BOOL DHInstallMethod(Class cls, SEL selector, IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NO;
    IMP previous = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (class_addMethod(cls, selector, replacement, types)) {
        if (original) *original = previous;
        return YES;
    }
    if (original) *original = method_setImplementation(method, replacement);
    else method_setImplementation(method, replacement);
    return YES;
}

static NSString *(*gOriginalSystemVersion)(id, SEL);
static NSString *(*gOriginalDeviceName)(id, SEL);
static NSUUID *(*gOriginalIDFV)(id, SEL);
static NSOperatingSystemVersion (*gOriginalOSVersion)(id, SEL);
static NSUUID *(*gOriginalIDFA)(id, SEL);
static BOOL (*gOriginalCanOpenURL)(id, SEL, NSURL *);

static NSString *DHSpoofedSystemVersion(id self, SEL cmd) {
    NSString *value = gOriginalSystemVersion ? gOriginalSystemVersion(self, cmd) : @"";
    DHRecordEnvironmentProbe(@"UIDevice.systemVersion", [NSString stringWithFormat:@"value=%@ matchedRule=%@", value ?: @"", DHHasDeviceRule(@"os_version") ? @YES : @NO]);
    return value;
}

static NSString *DHSpoofedDeviceName(id self, SEL cmd) {
    NSString *value = gOriginalDeviceName ? gOriginalDeviceName(self, cmd) : @"";
    DHRecordEnvironmentProbe(@"UIDevice.name", [NSString stringWithFormat:@"value=%@ matchedRule=%@", value ?: @"", DHHasDeviceRule(@"device_name") ? @YES : @NO]);
    return value;
}

static NSUUID *DHSpoofedIDFV(id self, SEL cmd) {
    NSUUID *value = gOriginalIDFV ? gOriginalIDFV(self, cmd) : nil;
    DHRecordEnvironmentProbe(@"UIDevice.identifierForVendor", [NSString stringWithFormat:@"value=%@ matchedRule=%@", value.UUIDString ?: @"", DHHasDeviceRule(@"idfv") ? @YES : @NO]);
    return value;
}

static NSOperatingSystemVersion DHSpoofedOSVersion(id self, SEL cmd) {
    NSOperatingSystemVersion value = gOriginalOSVersion ? gOriginalOSVersion(self, cmd) : (NSOperatingSystemVersion){0, 0, 0};
    DHRecordEnvironmentProbe(@"NSProcessInfo.operatingSystemVersion", [NSString stringWithFormat:@"value=%ld.%ld.%ld matchedRule=%@", (long)value.majorVersion, (long)value.minorVersion, (long)value.patchVersion, DHHasDeviceRule(@"os_version") ? @YES : @NO]);
    return value;
}

static NSUUID *DHSpoofedIDFA(id self, SEL cmd) {
    NSUUID *value = gOriginalIDFA ? gOriginalIDFA(self, cmd) : nil;
    DHRecordEnvironmentProbe(@"ASIdentifierManager.advertisingIdentifier", [NSString stringWithFormat:@"value=%@ matchedRule=%@", value.UUIDString ?: @"", DHHasDeviceRule(@"idfa") ? @YES : @NO]);
    return value;
}

static BOOL DHSpoofedCanOpenURL(id self, SEL cmd, NSURL *url) {
    BOOL result = gOriginalCanOpenURL ? gOriginalCanOpenURL(self, cmd, url) : NO;
    DHRecordEnvironmentProbe(@"UIApplication.canOpenURL", [NSString stringWithFormat:@"url=%@ result=%@ matchedRule=%@", url.absoluteString ?: @"", result ? @YES : @NO, DHShouldHideScheme(url.scheme) ? @YES : @NO]);
    return result;
}

void DHInstallSpoofHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"ptrace", (void *)DHHookedPtrace, (void **)&gOriginalPtrace},
            {"csops", (void *)DHHookedCSOps, (void **)&gOriginalCSOps},
            {"sysctl", (void *)DHHookedSysctl, (void **)&gOriginalSysctl},
            {"sysctlbyname", (void *)DHHookedSysctlByName, (void **)&gOriginalSysctlByName},
            {"stat", (void *)DHHookedStat, (void **)&gOriginalStat},
            {"lstat", (void *)DHHookedLstat, (void **)&gOriginalLstat},
            {"access", (void *)DHHookedAccess, (void **)&gOriginalAccess},
            {"faccessat", (void *)DHHookedFaccessat, (void **)&gOriginalFaccessat},
            {"fstatat", (void *)DHHookedFstatat, (void **)&gOriginalFstatat},
            {"getenv", (void *)DHHookedGetenv, (void **)&gOriginalGetenv},
            {"uname", (void *)DHHookedUname, (void **)&gOriginalUname},
            {"_dyld_get_image_name", (void *)DHHookedDyldImageName, (void **)&gOriginalDyldImageName},
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");

        DHRegisterHook(@"UIDevice.systemVersion", @"objc", DHInstallMethod(UIDevice.class, @selector(systemVersion), (IMP)DHSpoofedSystemVersion, (IMP *)&gOriginalSystemVersion));
        DHRegisterHook(@"UIDevice.name", @"objc", DHInstallMethod(UIDevice.class, @selector(name), (IMP)DHSpoofedDeviceName, (IMP *)&gOriginalDeviceName));
        DHRegisterHook(@"UIDevice.identifierForVendor", @"objc", DHInstallMethod(UIDevice.class, @selector(identifierForVendor), (IMP)DHSpoofedIDFV, (IMP *)&gOriginalIDFV));
        DHRegisterHook(@"NSProcessInfo.operatingSystemVersion", @"objc", DHInstallMethod(NSProcessInfo.class, @selector(operatingSystemVersion), (IMP)DHSpoofedOSVersion, (IMP *)&gOriginalOSVersion));
        DHRegisterHook(@"UIApplication.canOpenURL:", @"objc", DHInstallMethod(UIApplication.class, @selector(canOpenURL:), (IMP)DHSpoofedCanOpenURL, (IMP *)&gOriginalCanOpenURL));

        Class advertisingManager = NSClassFromString(@"ASIdentifierManager");
        if (advertisingManager) {
            DHRegisterHook(@"ASIdentifierManager.advertisingIdentifier", @"objc", DHInstallMethod(advertisingManager, NSSelectorFromString(@"advertisingIdentifier"), (IMP)DHSpoofedIDFA, (IMP *)&gOriginalIDFA));
        }
    });
}
