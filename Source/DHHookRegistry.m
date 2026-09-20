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
    NSString *message = installed ? nil : @"hook installation returned false";
    DHRegisterHookDiagnosticWithStatus(name, type, installed, message, installed ? 0 : -1);
}

void DHRegisterHookDiagnostic(NSString *name,
                              NSString *type,
                              BOOL installed,
                              NSString *errorMessage) {
    DHRegisterHookDiagnosticWithStatus(name, type, installed, errorMessage, installed ? 0 : -1);
}

void DHRegisterHookDiagnosticWithStatus(NSString *name,
                                        NSString *type,
                                        BOOL installed,
                                        NSString *errorMessage,
                                        NSInteger statusCode) {
    if (!name.length) return;
    DHEnsureHookRegistry();
    NSString *normalizedError = [errorMessage isKindOfClass:NSString.class] ? errorMessage : @"";
    if (!installed && !normalizedError.length) normalizedError = @"hook installation failed";
    dispatch_sync(gDHHookRegistryQueue, ^{
        gDHHookRegistry[name] = @{
            @"name": name,
            @"type": type.length ? type : @"unknown",
            @"installed": @(installed),
            @"success": @(installed),
            @"status": installed ? @"installed" : @"failed",
            @"statusCode": @(statusCode),
            @"error": normalizedError,
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
            // Keep legacy fields while making failure state explicit for diagnostics.
            if (!snapshot[@"status"]) snapshot[@"status"] = [snapshot[@"installed"] boolValue] ? @"installed" : @"failed";
            if (!snapshot[@"success"]) snapshot[@"success"] = snapshot[@"installed"] ?: @NO;
            if (!snapshot[@"statusCode"]) snapshot[@"statusCode"] = [snapshot[@"installed"] boolValue] ? @0 : @(-1);
            if (!snapshot[@"error"]) snapshot[@"error"] = [snapshot[@"installed"] boolValue] ? @"" : @"hook installation failed";
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

NSDictionary<NSString *, id> *DHHookRegistryDiagnosticSnapshot(void) {
    NSArray<NSDictionary<NSString *, id> *> *hooks = DHHookRegistrySnapshot();
    NSMutableArray *failures = [NSMutableArray array];
    NSUInteger installedCount = 0;
    for (NSDictionary *hook in hooks) {
        if ([hook[@"installed"] boolValue] && [hook[@"success"] boolValue]) {
            installedCount++;
        } else {
            [failures addObject:hook];
        }
    }
    return @{
        @"ok": @(failures.count == 0),
        @"hookCount": @(hooks.count),
        @"installedHookCount": @(installedCount),
        @"failedHookCount": @(failures.count),
        @"hooks": hooks,
        @"failures": failures
    };
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
        NSString *name = [NSString stringWithUTF8String:bindings[index].name];
        BOOL installed = status == 0;
        NSString *error = installed ? nil : [NSString stringWithFormat:@"rebind_symbols returned %d", status];
        DHRegisterHookDiagnosticWithStatus(name,
                                           type.length ? type : @"fishhook",
                                           installed,
                                           error,
                                           status);
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
