#import "DHDynamic.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "DHSpoof.h"
#import "fishhook.h"
#import <dlfcn.h>

static __thread int gDynamicGuard;
typedef void *(*DHDlopenFn)(const char *, int);
typedef void *(*DHDlsymFn)(void *, const char *);
typedef int (*DHdladdrFn)(const void *, Dl_info *);

static DHDlopenFn gOriginalDlopen;
static DHDlsymFn gOriginalDlsym;
static DHdladdrFn gOriginalDladdr;
static __thread int gDlsymRouteGuard;

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
    if (gDynamicGuard || gDlsymRouteGuard) {
        return gOriginalDlsym ? gOriginalDlsym(handle, symbol) : NULL;
    }

    gDlsymRouteGuard++;
    void *resolvedAddress = gOriginalDlsym ? gOriginalDlsym(handle, symbol) : NULL;
    BOOL routed = NO;
    void *returnedAddress = DHRouteResolvedSymbol(symbol, resolvedAddress, &routed);
    gDlsymRouteGuard--;

    DHLogDynamic(@"dlsym", @{
        @"symbol": DHPathString(symbol),
        @"handle": [NSString stringWithFormat:@"%p", handle],
        @"resolvedAddress": [NSString stringWithFormat:@"%p", resolvedAddress],
        @"returnedAddress": [NSString stringWithFormat:@"%p", returnedAddress],
        @"routedToWrapper": @(routed),
        @"success": @(returnedAddress != NULL)
    });
    return returnedAddress;
}

static int DHHookedDladdr(const void *address, Dl_info *info) {
    int result = gOriginalDladdr ? gOriginalDladdr(address, info) : 0;
    const char *imagePath = info && info->dli_fname ? info->dli_fname : NULL;
    DHLogDynamic(@"dladdr", @{
        @"address": [NSString stringWithFormat:@"%p", address],
        @"image": imagePath ? DHPathString(imagePath) : @"",
        @"symbol": info && info->dli_sname ? DHPathString(info->dli_sname) : @"",
        @"matchedRule": @(DHSpoofMatchesImagePath(imagePath)),
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
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
