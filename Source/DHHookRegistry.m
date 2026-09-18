#import "DHHookRegistry.h"

static dispatch_queue_t gDHHookRegistryQueue;
static NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *gDHHookRegistry;

static void DHEnsureHookRegistry(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gDHHookRegistryQueue = dispatch_queue_create("com.decrypthelper.reconstructed.hooks", DISPATCH_QUEUE_SERIAL);
        gDHHookRegistry = [NSMutableDictionary dictionary];
    });
}

void DHRegisterHook(NSString *name, NSString *type, BOOL installed) {
    if (!name.length) return;
    DHEnsureHookRegistry();
    dispatch_sync(gDHHookRegistryQueue, ^{
        gDHHookRegistry[name] = @{
            @"name": name,
            @"type": type.length ? type : @"unknown",
            @"installed": @(installed),
            @"timestampMs": @((unsigned long long)([[NSDate date] timeIntervalSince1970] * 1000.0))
        };
    });
}

NSArray<NSDictionary<NSString *, id> *> *DHHookRegistrySnapshot(void) {
    DHEnsureHookRegistry();
    __block NSArray *result;
    dispatch_sync(gDHHookRegistryQueue, ^{
        result = [[gDHHookRegistry.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"name"] compare:b[@"name"]];
        }] copy];
    });
    return result ?: @[];
}
