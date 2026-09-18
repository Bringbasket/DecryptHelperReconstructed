#import "DHKeychain.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <Security/Security.h>

static __thread int gKeychainGuard;

static id DHSafeObject(id value, NSUInteger depth) {
    if (!value) return NSNull.null;
    if (depth > 6) return @"<maximum depth>";
    if ([value isKindOfClass:NSString.class] ||
        [value isKindOfClass:NSNumber.class] ||
        [value isKindOfClass:NSNull.class]) return value;
    if ([value isKindOfClass:NSData.class]) {
        NSData *data = value;
        return @{
            @"type": @"data",
            @"length": @(data.length),
            @"base64": [data base64EncodedStringWithOptions:0]
        };
    }
    if ([value isKindOfClass:NSDate.class]) return [value description];
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *items = [NSMutableArray array];
        for (id item in value) [items addObject:DHSafeObject(item, depth + 1)];
        return items;
    }
    if ([value isKindOfClass:NSSet.class]) {
        NSMutableArray *items = [NSMutableArray array];
        for (id item in value) [items addObject:DHSafeObject(item, depth + 1)];
        return items;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [(NSDictionary *)value enumerateKeysAndObjectsUsingBlock:^(id key, id object, BOOL *stop) {
            (void)stop;
            NSString *safeKey = [key isKindOfClass:NSString.class] ? key : [key description];
            if (safeKey) dictionary[safeKey] = DHSafeObject(object, depth + 1);
        }];
        return dictionary;
    }
    return @{
        @"type": NSStringFromClass([value class]) ?: @"unknown",
        @"description": [value description] ?: @""
    };
}

static void DHLogKeychain(NSString *operation,
                          OSStatus status,
                          CFDictionaryRef query,
                          CFTypeRef value) {
    if (gKeychainGuard || ![DHConfig shared].keychainEnabled) return;
    gKeychainGuard++;
    @autoreleasepool {
        NSDictionary *metadata = @{
            @"status": @(status),
            @"query": DHSafeObject((__bridge id)query, 0),
            @"result": DHSafeObject((__bridge id)value, 0)
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
        DHLogEntry *entry = [DHLogEntry entryWithCategory:@"KEYCHAIN"
                                                algorithm:@"SecItem"
                                                operation:operation];
        entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gKeychainGuard--;
}

typedef OSStatus (*DHSecItemCopyMatchingFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*DHSecItemAddFn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*DHSecItemUpdateFn)(CFDictionaryRef, CFDictionaryRef);
typedef OSStatus (*DHSecItemDeleteFn)(CFDictionaryRef);

static DHSecItemCopyMatchingFn gOriginalSecItemCopyMatching;
static DHSecItemAddFn gOriginalSecItemAdd;
static DHSecItemUpdateFn gOriginalSecItemUpdate;
static DHSecItemDeleteFn gOriginalSecItemDelete;

static OSStatus DHHookedSecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = gOriginalSecItemCopyMatching ?
        gOriginalSecItemCopyMatching(query, result) : errSecUnimplemented;
    CFTypeRef value = result ? *result : NULL;
    DHLogKeychain(@"copy-matching", status, query, value);
    return status;
}

static OSStatus DHHookedSecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus status = gOriginalSecItemAdd ?
        gOriginalSecItemAdd(attributes, result) : errSecUnimplemented;
    CFTypeRef value = result ? *result : NULL;
    DHLogKeychain(@"add", status, attributes, value);
    return status;
}

static OSStatus DHHookedSecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus status = gOriginalSecItemUpdate ?
        gOriginalSecItemUpdate(query, attributesToUpdate) : errSecUnimplemented;
    NSDictionary *combined = @{
        @"query": DHSafeObject((__bridge id)query, 0),
        @"attributes": DHSafeObject((__bridge id)attributesToUpdate, 0)
    };
    DHLogKeychain(@"update", status, (__bridge CFDictionaryRef)combined, NULL);
    return status;
}

static OSStatus DHHookedSecItemDelete(CFDictionaryRef query) {
    OSStatus status = gOriginalSecItemDelete ? gOriginalSecItemDelete(query) : errSecUnimplemented;
    DHLogKeychain(@"delete", status, query, NULL);
    return status;
}

void DHInstallKeychainHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"SecItemCopyMatching", (void *)DHHookedSecItemCopyMatching,
             (void **)&gOriginalSecItemCopyMatching},
            {"SecItemAdd", (void *)DHHookedSecItemAdd, (void **)&gOriginalSecItemAdd},
            {"SecItemUpdate", (void *)DHHookedSecItemUpdate, (void **)&gOriginalSecItemUpdate},
            {"SecItemDelete", (void *)DHHookedSecItemDelete, (void **)&gOriginalSecItemDelete}
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
