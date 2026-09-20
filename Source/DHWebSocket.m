#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

typedef void (*DHWebSocketSendFn)(id, SEL, id, void (^)(NSError *));
typedef void (*DHWebSocketReceiveFn)(id, SEL, void (^)(id, NSError *));
typedef void (*DHWebSocketPingFn)(id, SEL, void (^)(NSError *));
static DHWebSocketSendFn gOriginalWebSocketSend;
static DHWebSocketReceiveFn gOriginalWebSocketReceive;
static DHWebSocketPingFn gOriginalWebSocketPing;

static NSData *DHWebSocketData(id message) {
    if ([message respondsToSelector:@selector(string)]) {
        NSString *string = [message string];
        if (string.length) return [string dataUsingEncoding:NSUTF8StringEncoding];
    }
    id data = [message respondsToSelector:@selector(data)] ? [message data] : nil;
    return [data isKindOfClass:NSData.class] ? data : nil;
}

static NSString *DHWebSocketURL(id task) {
    NSURLRequest *request = [task respondsToSelector:@selector(currentRequest)] ? [task currentRequest] : nil;
    return request.URL.absoluteString ?: @"";
}

static void DHLogWebSocket(id task, NSString *operation, NSData *input, NSData *output, NSError *error) {
    if (![DHConfig shared].networkEnabled) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK" algorithm:@"WebSocket" operation:operation];
    entry.detail = [NSString stringWithFormat:@"url=%@ error=%@", DHWebSocketURL(task), error.localizedDescription ?: @""];
    entry.input = input; entry.output = output; entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static void DHHookedWebSocketSend(id self, SEL selector, id message, void (^completion)(NSError *)) {
    DHLogWebSocket(self, @"send", DHWebSocketData(message), nil, nil);
    void (^wrapped)(NSError *) = ^(NSError *error) { if (error) DHLogWebSocket(self, @"send.error", nil, nil, error); if (completion) completion(error); };
    if (gOriginalWebSocketSend) gOriginalWebSocketSend(self, selector, message, wrapped);
}

static void DHHookedWebSocketReceive(id self, SEL selector, void (^completion)(id, NSError *)) {
    void (^wrapped)(id, NSError *) = ^(id message, NSError *error) {
        DHLogWebSocket(self, @"receive", nil, DHWebSocketData(message), error);
        if (completion) completion(message, error);
    };
    if (gOriginalWebSocketReceive) gOriginalWebSocketReceive(self, selector, wrapped);
}

static void DHHookedWebSocketPing(id self, SEL selector, void (^completion)(NSError *)) {
    DHLogWebSocket(self, @"ping", nil, nil, nil);
    if (gOriginalWebSocketPing) gOriginalWebSocketPing(self, selector, completion);
}

static BOOL DHInstallWebSocketMethod(Class cls, SEL selector, IMP replacement, IMP *original) {
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method) return NO;
    if (original) *original = method_getImplementation(method);
    method_setImplementation(method, replacement);
    return YES;
}

void DHInstallWebSocketHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = NSClassFromString(@"NSURLSessionWebSocketTask");
        DHRegisterHook(@"NSURLSessionWebSocketTask.sendMessage:", @"objc", DHInstallWebSocketMethod(cls, @selector(sendMessage:completionHandler:), (IMP)DHHookedWebSocketSend, (IMP *)&gOriginalWebSocketSend));
        DHRegisterHook(@"NSURLSessionWebSocketTask.receiveMessage", @"objc", DHInstallWebSocketMethod(cls, @selector(receiveMessageWithCompletionHandler:), (IMP)DHHookedWebSocketReceive, (IMP *)&gOriginalWebSocketReceive));
        DHRegisterHook(@"NSURLSessionWebSocketTask.sendPing", @"objc", DHInstallWebSocketMethod(cls, @selector(sendPingWithPongReceiveHandler:), (IMP)DHHookedWebSocketPing, (IMP *)&gOriginalWebSocketPing));
    });
}
