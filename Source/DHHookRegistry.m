#import "DHHookRegistry.h"
#import "fishhook.h"

static dispatch_queue_t gDHHookRegistryQueue;
static NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *gDHHookRegistry;
static NSMutableDictionary<NSString *, NSMutableDictionary<NSString *, id> *> *gDHSymbolRegistry;

static void DHEnsureHookRegistry(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gDHHookRegistryQueue = dispatch_queue_create("com.decrypthelper.reconstructed.hooks", DISPATCH_QUEUE_SERIAL);
        gDHHookRegistry = [NSMutableDictionary dictionary];
        gDHSymbolRegistry = [NSMutableDictionary dictionary];
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
        NSMutableArray *snapshots = [NSMutableArray arrayWithCapacity:gDHHookRegistry.count];
        for (NSDictionary *hook in gDHHookRegistry.allValues) {
            NSMutableDictionary *snapshot = [hook mutableCopy];
            NSDictionary *symbol = gDHSymbolRegistry[hook[@"name"]];
            if (symbol) {
                snapshot[@"dlsymHits"] = symbol[@"dlsymHits"] ?: @0;
                id slotValue = symbol[@"originalSlot"];
                void **slot = slotValue == NSNull.null ? NULL : [slotValue pointerValue];
                snapshot[@"originalResolved"] = @(slot && *slot != NULL);
            }
            [snapshots addObject:snapshot];
        }
        result = [[snapshots sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"name"] compare:b[@"name"]];
        }] copy];
    });
    return result ?: @[];
}

int DHRebindSymbols(const struct rebinding *bindings, size_t count, NSString *type) {
    if (!bindings || !count) return -1;
    DHEnsureHookRegistry();

    int status = rebind_symbols((struct rebinding *)bindings, count);
    dispatch_sync(gDHHookRegistryQueue, ^{
        for (size_t index = 0; index < count; index++) {
            const struct rebinding *binding = &bindings[index];
            if (!binding->name || !binding->replacement) continue;
            NSString *name = [NSString stringWithUTF8String:binding->name];
            if (!name.length) continue;
            gDHSymbolRegistry[name] = [@{
                @"replacement": [NSValue valueWithPointer:binding->replacement],
                @"originalSlot": binding->replaced ? [NSValue valueWithPointer:binding->replaced] : NSNull.null,
                @"dlsymHits": @0
            } mutableCopy];
        }
    });

    for (size_t index = 0; index < count; index++) {
        if (!bindings[index].name) continue;
        DHRegisterHook([NSString stringWithUTF8String:bindings[index].name],
                       type.length ? type : @"fishhook", status == 0);
    }
    return status;
}

void *DHRouteResolvedSymbol(const char *symbol, void *resolvedAddress, BOOL *routed) {
    if (routed) *routed = NO;
    if (!symbol || !*symbol || !resolvedAddress) return resolvedAddress;
    DHEnsureHookRegistry();

    NSString *name = [NSString stringWithUTF8String:symbol];
    if (!name.length) return resolvedAddress;

    __block void *result = resolvedAddress;
    dispatch_sync(gDHHookRegistryQueue, ^{
        NSMutableDictionary<NSString *, id> *record = gDHSymbolRegistry[name];
        if (!record) return;

        void *replacement = [record[@"replacement"] pointerValue];
        id slotValue = record[@"originalSlot"];
        void **originalSlot = slotValue == NSNull.null ? NULL : [slotValue pointerValue];
        if (originalSlot && (!*originalSlot || *originalSlot == replacement)) {
            *originalSlot = resolvedAddress;
        }
        if (replacement && replacement != resolvedAddress) {
            result = replacement;
            record[@"dlsymHits"] = @([record[@"dlsymHits"] unsignedLongLongValue] + 1);
            if (routed) *routed = YES;
        }
    });
    return result;
}
