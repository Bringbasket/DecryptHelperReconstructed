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

static void DHRecordEnvironmentProbe(NSString *name, NSString *detail) {
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"ENV_PROBE"
                                            algorithm:name
                                            operation:@"observe"];
    entry.detail = detail;
    [[DHLogStore shared] append:entry];
}

typedef int (*DHPTraceFn)(int, pid_t, caddr_t, int);
typedef int (*DHCSOpsFn)(pid_t, unsigned int, void *, size_t);
typedef int (*DHSysctlFn)(int *, u_int, void *, size_t *, void *, size_t);
typedef int (*DHSysctlByNameFn)(const char *, void *, size_t *, void *, size_t);

static DHPTraceFn gOriginalPtrace;
static DHCSOpsFn gOriginalCSOps;
static DHSysctlFn gOriginalSysctl;
static DHSysctlByNameFn gOriginalSysctlByName;

static int DHHookedPtrace(int request, pid_t pid, caddr_t address, int data) {
    if (request == PT_DENY_ATTACH && [DHConfig shared].antiDebugEnabled) {
        DHRecordEnvironmentProbe(@"ptrace", @"PT_DENY_ATTACH hidden");
        return 0;
    }
    return gOriginalPtrace ? gOriginalPtrace(request, pid, address, data) : 0;
}

static int DHHookedCSOps(pid_t pid, unsigned int operation, void *userAddress, size_t size) {
    int result = gOriginalCSOps ? gOriginalCSOps(pid, operation, userAddress, size) : -1;
    if (result == 0 && operation == CS_OPS_STATUS && userAddress && size >= sizeof(uint32_t) &&
        [DHConfig shared].antiDebugEnabled) {
        uint32_t *flags = userAddress;
        if (*flags & CS_DEBUGGED) {
            *flags &= ~CS_DEBUGGED;
            DHRecordEnvironmentProbe(@"csops", @"CS_DEBUGGED cleared");
        }
    }
    return result;
}

static int DHHookedSysctl(int *name, u_int count, void *oldValue, size_t *oldLength,
                          void *newValue, size_t newLength) {
    int result = gOriginalSysctl ? gOriginalSysctl(name, count, oldValue, oldLength, newValue, newLength) : -1;
    if (result == 0 && [DHConfig shared].antiDebugEnabled && name && count >= 3 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldValue && oldLength && *oldLength >= 0x24) {
        uint32_t *processFlags = (uint32_t *)((uint8_t *)oldValue + 0x20);
        if (*processFlags & P_TRACED) {
            *processFlags &= ~P_TRACED;
            DHRecordEnvironmentProbe(@"sysctl", @"P_TRACED cleared");
        }
    }
    return result;
}

static int DHCopySysctlString(NSString *value, void *oldValue, size_t *oldLength) {
    if (!oldLength || !value.length) return -1;
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    size_t required = data.length + 1;
    if (!oldValue) {
        *oldLength = required;
        return 0;
    }
    if (*oldLength < required) {
        *oldLength = required;
        errno = ENOMEM;
        return -1;
    }
    memcpy(oldValue, data.bytes, data.length);
    ((char *)oldValue)[data.length] = '\0';
    *oldLength = required;
    return 0;
}

static int DHHookedSysctlByName(const char *name, void *oldValue, size_t *oldLength,
                                void *newValue, size_t newLength) {
    if ([DHConfig shared].deviceSpoofEnabled && !newValue && name) {
        NSString *key = nil;
        if (strcmp(name, "hw.machine") == 0) key = @"hw_machine";
        else if (strcmp(name, "hw.model") == 0) key = @"hw_model";
        else if (strcmp(name, "kern.osproductversion") == 0) key = @"os_version";
        NSString *value = key ? [[DHConfig shared] spoofValueForKey:key] : nil;
        if (value.length) return DHCopySysctlString(value, oldValue, oldLength);
    }
    return gOriginalSysctlByName ? gOriginalSysctlByName(name, oldValue, oldLength, newValue, newLength) : -1;
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
    if (DHBeginHideCheck(path)) { errno = ENOENT; return -1; }
    return gOriginalStat ? gOriginalStat(path, buffer) : -1;
}

static int DHHookedLstat(const char *path, struct stat *buffer) {
    if (DHBeginHideCheck(path)) { errno = ENOENT; return -1; }
    return gOriginalLstat ? gOriginalLstat(path, buffer) : -1;
}

static int DHHookedAccess(const char *path, int mode) {
    if (DHBeginHideCheck(path)) { errno = ENOENT; return -1; }
    return gOriginalAccess ? gOriginalAccess(path, mode) : -1;
}

static int DHHookedFaccessat(int fd, const char *path, int mode, int flags) {
    if (DHBeginHideCheck(path)) { errno = ENOENT; return -1; }
    return gOriginalFaccessat ? gOriginalFaccessat(fd, path, mode, flags) : -1;
}

static int DHHookedFstatat(int fd, const char *path, struct stat *buffer, int flags) {
    if (DHBeginHideCheck(path)) { errno = ENOENT; return -1; }
    return gOriginalFstatat ? gOriginalFstatat(fd, path, buffer, flags) : -1;
}

static char *DHHookedGetenv(const char *name) {
    if ([DHConfig shared].jailbreakHideEnabled && name &&
        (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
         strcmp(name, "_MSSafeMode") == 0 ||
         strcmp(name, "_SafeMode") == 0)) return NULL;
    return gOriginalGetenv ? gOriginalGetenv(name) : NULL;
}

static int DHHookedUname(struct utsname *name) {
    int result = gOriginalUname ? gOriginalUname(name) : -1;
    NSString *machine = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"hw_machine"] : nil;
    if (result == 0 && name && machine.length) {
        strlcpy(name->machine, machine.UTF8String, sizeof(name->machine));
    }
    return result;
}

static const char *DHHookedDyldImageName(uint32_t index) {
    const char *path = gOriginalDyldImageName ? gOriginalDyldImageName(index) : NULL;
    if (path && DHBeginImageHideCheck(path)) return "/usr/lib/libSystem.B.dylib";
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
    NSString *value = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"os_version"] : nil;
    return value.length ? value : (gOriginalSystemVersion ? gOriginalSystemVersion(self, cmd) : @"");
}

static NSString *DHSpoofedDeviceName(id self, SEL cmd) {
    NSString *value = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"device_name"] : nil;
    return value.length ? value : (gOriginalDeviceName ? gOriginalDeviceName(self, cmd) : @"");
}

static NSUUID *DHSpoofedIDFV(id self, SEL cmd) {
    NSString *value = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"idfv"] : nil;
    NSUUID *uuid = value.length ? [[NSUUID alloc] initWithUUIDString:value] : nil;
    return uuid ?: (gOriginalIDFV ? gOriginalIDFV(self, cmd) : nil);
}

static NSOperatingSystemVersion DHSpoofedOSVersion(id self, SEL cmd) {
    NSString *value = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"os_version"] : nil;
    if (!value.length) return gOriginalOSVersion ? gOriginalOSVersion(self, cmd) : (NSOperatingSystemVersion){0, 0, 0};
    NSArray<NSString *> *parts = [value componentsSeparatedByString:@"."];
    return (NSOperatingSystemVersion){
        parts.count > 0 ? parts[0].integerValue : 0,
        parts.count > 1 ? parts[1].integerValue : 0,
        parts.count > 2 ? parts[2].integerValue : 0
    };
}

static NSUUID *DHSpoofedIDFA(id self, SEL cmd) {
    NSString *value = [DHConfig shared].deviceSpoofEnabled ? [[DHConfig shared] spoofValueForKey:@"idfa"] : nil;
    NSUUID *uuid = value.length ? [[NSUUID alloc] initWithUUIDString:value] : nil;
    return uuid ?: (gOriginalIDFA ? gOriginalIDFA(self, cmd) : nil);
}

static BOOL DHSpoofedCanOpenURL(id self, SEL cmd, NSURL *url) {
    if ([DHConfig shared].jailbreakHideEnabled) {
        const char *scheme = url.scheme.UTF8String;
        NSArray<NSString *> *rules = [DHConfig shared].hiddenSchemes;
        if (!rules.count) {
            for (size_t i = 0; scheme && i < sizeof(kHiddenSchemes) / sizeof(kHiddenSchemes[0]); i++) {
                if (strcasecmp(scheme, kHiddenSchemes[i]) == 0) return NO;
            }
        }
        for (NSString *rule in rules) {
            if (scheme && strcasecmp(scheme, rule.UTF8String) == 0) return NO;
        }
    }
    return gOriginalCanOpenURL ? gOriginalCanOpenURL(self, cmd, url) : NO;
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
