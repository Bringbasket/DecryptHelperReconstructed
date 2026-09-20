#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <Network/Network.h>

typedef void (*DHNWConnectionSendFn)(nw_connection_t, dispatch_data_t, nw_content_context_t, bool, nw_connection_send_completion_t);
typedef void (*DHNWConnectionReceiveFn)(nw_connection_t, uint32_t, uint32_t, nw_connection_receive_completion_t);
static DHNWConnectionSendFn gOriginalNWConnectionSend;
static DHNWConnectionReceiveFn gOriginalNWConnectionReceive;
static const NSUInteger kDHNetworkFrameworkLimit = 1024 * 1024;

static NSData *DHDispatchDataPreview(dispatch_data_t content) {
    if (!content) return nil;
    NSMutableData *result = [NSMutableData data];
    dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
        if (!buffer || !size || result.length >= kDHNetworkFrameworkLimit) return result.length < kDHNetworkFrameworkLimit;
        [result appendBytes:buffer length:MIN(size, kDHNetworkFrameworkLimit - result.length)];
        return result.length < kDHNetworkFrameworkLimit;
    });
    return result.length ? result : nil;
}

static void DHLogNW(NSString *operation, nw_connection_t connection, NSData *input, NSData *output, nw_error_t error) {
    if (![DHConfig shared].networkEnabled) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK" algorithm:@"Network.framework" operation:operation];
    entry.detail = [NSString stringWithFormat:@"connection=%p error=%@", connection, error ? (__bridge id)error : @""];
    entry.input = input; entry.output = output; entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static void DHHookedNWConnectionSend(nw_connection_t connection, dispatch_data_t content,
                                     nw_content_context_t context, bool complete,
                                     nw_connection_send_completion_t completion) {
    DHLogNW(@"send", connection, DHDispatchDataPreview(content), nil, NULL);
    nw_connection_send_completion_t wrapped = ^(nw_error_t error) {
        if (error) DHLogNW(@"send.error", connection, nil, nil, error);
        if (completion) completion(error);
    };
    if (gOriginalNWConnectionSend) gOriginalNWConnectionSend(connection, content, context, complete, wrapped);
}

static void DHHookedNWConnectionReceive(nw_connection_t connection, uint32_t minimum,
                                        uint32_t maximum, nw_connection_receive_completion_t completion) {
    nw_connection_receive_completion_t wrapped = ^(dispatch_data_t content, nw_content_context_t context, bool complete, nw_error_t error) {
        DHLogNW(@"receive", connection, nil, DHDispatchDataPreview(content), error);
        if (completion) completion(content, context, complete, error);
    };
    if (gOriginalNWConnectionReceive) gOriginalNWConnectionReceive(connection, minimum, maximum, wrapped);
}

void DHInstallNetworkFrameworkHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"nw_connection_send", (void *)DHHookedNWConnectionSend, (void **)&gOriginalNWConnectionSend},
            {"nw_connection_receive", (void *)DHHookedNWConnectionReceive, (void **)&gOriginalNWConnectionReceive}
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
