#import "DHDynamic.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "fishhook.h"
#import <dlfcn.h>

static __thread int gDynamicGuard;
typedef void *(*DHDlopenFn)(const char *, int);
typedef void *(*DHDlsymFn)(void *, const char *);
typedef int (*DHdladdrFn)(const void *, Dl_info *);

static DHDlopenFn gOriginalDlopen;
static DHDlsymFn gOriginalDlsym;
static DHdladdrFn gOriginalDladdr;

static NSString *DHPathString(const char *value) {
    return value ? [NSString stringWithUTF8String:value] ?: @"" : @"";
}

static void DHLogDynamic(NSString *operation, NSDictionary *detail) {
    if (gDynamicGuard || ![DHConfig shared].dynamicEnabled) return;
    gDynamicGuard++;
    @autoreleasepool {
        DHLogEntry *entry = [DHLogEntry entryWithCategory:@"SYS_DYNAMIC"
                                                algorithm:@"dyld"
                                                operation:operation];
        NSData *json = [NSJSONSerialization dataWithJSONObject:detail ?: @{} options:0 error:nil];
        entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gDynamicGuard--;
}

static void *DHHookedDlopen(const char *path, int mode) {
    void *handle = gOriginalDlopen ? gOriginalDlopen(path, mode) : NULL;
    DHLogDynamic(@"dlopen", @{
        @"path": DHPathString(path),
        @"mode": @(mode),
        @"handle": [NSString stringWithFormat:@"%p", handle],
        @"success": @(handle != NULL)
    });
    return handle;
}

static void *DHHookedDlsym(void *handle, const char *symbol) {
    void *address = gOriginalDlsym ? gOriginalDlsym(handle, symbol) : NULL;
    DHLogDynamic(@"dlsym", @{
        @"symbol": DHPathString(symbol),
        @"handle": [NSString stringWithFormat:@"%p", handle],
        @"address": [NSString stringWithFormat:@"%p", address],
        @"success": @(address != NULL)
    });
    return address;
}

static int DHHookedDladdr(const void *address, Dl_info *info) {
    int result = gOriginalDladdr ? gOriginalDladdr(address, info) : 0;
    DHLogDynamic(@"dladdr", @{
        @"address": [NSString stringWithFormat:@"%p", address],
        @"image": info && info->dli_fname ? DHPathString(info->dli_fname) : @"",
        @"symbol": info && info->dli_sname ? DHPathString(info->dli_sname) : @"",
        @"success": @(result != 0)
    });
    return result;
}

void DHInstallDynamicHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"dlopen", (void *)DHHookedDlopen, (void **)&gOriginalDlopen},
            {"dlsym", (void *)DHHookedDlsym, (void **)&gOriginalDlsym},
            {"dladdr", (void *)DHHookedDladdr, (void **)&gOriginalDladdr}
        };
        rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
    });
}
