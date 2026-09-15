#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "fishhook.h"
#import <objc/runtime.h>

static const void *kDHObservedTaskKey = &kDHObservedTaskKey;

typedef NSURLSessionDataTask *(*DHDataTaskRequestCompletionIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDataTask *(*DHDataTaskURLCompletionIMP)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef void (*DHTaskResumeIMP)(id, SEL);
typedef NSData *(*DHSynchronousRequestIMP)(Class, SEL, NSURLRequest *, NSURLResponse **, NSError **);
typedef void (*DHAsynchronousRequestIMP)(Class, SEL, NSURLRequest *, NSOperationQueue *,
                                         void (^)(NSURLResponse *, NSData *, NSError *));

static DHDataTaskRequestCompletionIMP gOriginalDataTaskRequestCompletion;
static DHDataTaskURLCompletionIMP gOriginalDataTaskURLCompletion;
static DHTaskResumeIMP gOriginalTaskResume;
static DHSynchronousRequestIMP gOriginalSynchronousRequest;
static DHAsynchronousRequestIMP gOriginalAsynchronousRequest;

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

static BOOL DHInstallClassMethod(Class cls, SEL selector, IMP replacement, IMP *original) {
    Method method = class_getClassMethod(cls, selector);
    if (!method) return NO;
    IMP previous = method_getImplementation(method);
    if (original) *original = previous;
    method_setImplementation(method, replacement);
    return YES;
}

static NSString *DHJSONString(id object) {
    if (!object || ![NSJSONSerialization isValidJSONObject:object]) return nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
}

static NSDictionary *DHRequestMetadata(NSURLRequest *request, NSDictionary *additionalHeaders) {
    if (!request) return @{};
    NSMutableDictionary *metadata = [NSMutableDictionary dictionary];
    metadata[@"method"] = request.HTTPMethod ?: @"GET";
    metadata[@"url"] = request.URL.absoluteString ?: @"";
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    if ([additionalHeaders isKindOfClass:NSDictionary.class]) [headers addEntriesFromDictionary:additionalHeaders];
    if (request.allHTTPHeaderFields) [headers addEntriesFromDictionary:request.allHTTPHeaderFields];
    metadata[@"headers"] = headers;
    if (request.HTTPBodyStream && !request.HTTPBody.length) metadata[@"bodyNote"] = @"HTTPBodyStream present";
    return metadata;
}

static NSDictionary *DHResponseMetadata(NSURLResponse *response, NSError *error) {
    NSMutableDictionary *metadata = [NSMutableDictionary dictionary];
    if (response.URL.absoluteString) metadata[@"responseURL"] = response.URL.absoluteString;
    if (response.MIMEType) metadata[@"mimeType"] = response.MIMEType;
    if ([response isKindOfClass:NSHTTPURLResponse.class]) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
        metadata[@"status"] = @(http.statusCode);
        metadata[@"responseHeaders"] = http.allHeaderFields ?: @{};
    }
    if (error) {
        metadata[@"error"] = error.localizedDescription ?: @"unknown";
        metadata[@"errorCode"] = @(error.code);
        metadata[@"errorDomain"] = error.domain ?: @"";
    }
    return metadata;
}

static void DHLogURLSession(NSURLRequest *request,
                            NSDictionary *additionalHeaders,
                            NSData *data,
                            NSURLResponse *response,
                            NSError *error) {
    if (![DHConfig shared].networkEnabled) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK"
                                            algorithm:@"NSURLSession"
                                            operation:request.HTTPMethod ?: @"GET"];
    NSMutableDictionary *metadata = [DHRequestMetadata(request, additionalHeaders) mutableCopy];
    if (!metadata) metadata = [NSMutableDictionary dictionary];
    [metadata addEntriesFromDictionary:DHResponseMetadata(response, error)];
    entry.detail = DHJSONString(metadata);
    entry.input = request.HTTPBody;
    entry.output = data;
    entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static NSURLSessionDataTask *DHDataTaskWithRequestCompletion(id self, SEL cmd,
                                                             NSURLRequest *request,
                                                             void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    if (!gOriginalDataTaskRequestCompletion) return nil;
    if (![DHConfig shared].networkEnabled) {
        return gOriginalDataTaskRequestCompletion(self, cmd, request, completion);
    }
    NSURLRequest *capturedRequest = [request copy];
    NSDictionary *additionalHeaders = [[self configuration].HTTPAdditionalHeaders copy];
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        DHLogURLSession(capturedRequest, additionalHeaders, data, response, error);
        if (completion) completion(data, response, error);
    };
    NSURLSessionDataTask *task = gOriginalDataTaskRequestCompletion(self, cmd, request, wrapped);
    if (task) objc_setAssociatedObject(task, kDHObservedTaskKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return task;
}

static NSURLSessionDataTask *DHDataTaskWithURLCompletion(id self, SEL cmd,
                                                         NSURL *url,
                                                         void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    if (!gOriginalDataTaskURLCompletion) return nil;
    if (![DHConfig shared].networkEnabled) {
        return gOriginalDataTaskURLCompletion(self, cmd, url, completion);
    }
    NSURLRequest *request = url ? [NSURLRequest requestWithURL:url] : nil;
    NSDictionary *additionalHeaders = [[self configuration].HTTPAdditionalHeaders copy];
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        DHLogURLSession(request, additionalHeaders, data, response, error);
        if (completion) completion(data, response, error);
    };
    NSURLSessionDataTask *task = gOriginalDataTaskURLCompletion(self, cmd, url, wrapped);
    if (task) objc_setAssociatedObject(task, kDHObservedTaskKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return task;
}

static void DHTaskResume(id self, SEL cmd) {
    if ([DHConfig shared].networkEnabled &&
        ![objc_getAssociatedObject(self, kDHObservedTaskKey) boolValue] &&
        [self respondsToSelector:@selector(currentRequest)]) {
        NSURLRequest *request = [self currentRequest];
        DHLogURLSession(request, nil, nil, nil, nil);
        objc_setAssociatedObject(self, kDHObservedTaskKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    if (gOriginalTaskResume) gOriginalTaskResume(self, cmd);
}

static NSData *DHHookedSynchronousRequest(Class cls,
                                          SEL cmd,
                                          NSURLRequest *request,
                                          NSURLResponse **response,
                                          NSError **error) {
    NSData *data = gOriginalSynchronousRequest ?
        gOriginalSynchronousRequest(cls, cmd, request, response, error) : nil;
    DHLogURLSession(request, nil, data, response ? *response : nil, error ? *error : nil);
    return data;
}

static void DHHookedAsynchronousRequest(Class cls,
                                        SEL cmd,
                                        NSURLRequest *request,
                                        NSOperationQueue *queue,
                                        void (^completion)(NSURLResponse *, NSData *, NSError *)) {
    NSURLRequest *capturedRequest = [request copy];
    void (^wrapped)(NSURLResponse *, NSData *, NSError *) = ^(NSURLResponse *response,
                                                               NSData *data,
                                                               NSError *error) {
        DHLogURLSession(capturedRequest, nil, data, response, error);
        if (completion) completion(response, data, error);
    };
    if (gOriginalAsynchronousRequest) {
        gOriginalAsynchronousRequest(cls, cmd, request, queue, wrapped);
    }
}

typedef int (*DHSSLWrite)(void *, const void *, int);
typedef int (*DHSSLRead)(void *, void *, int);
typedef int (*DHSSLWriteEx)(void *, const void *, size_t, size_t *);
typedef int (*DHSSLReadEx)(void *, void *, size_t, size_t *);

static DHSSLWrite gOriginalSSLWrite;
static DHSSLRead gOriginalSSLRead;
static DHSSLWriteEx gOriginalSSLWriteEx;
static DHSSLReadEx gOriginalSSLReadEx;

static void DHLogSSL(NSString *operation, void *ssl, const void *bytes, size_t length, BOOL outgoing) {
    if (![DHConfig shared].networkEnabled || !bytes || length == 0) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK"
                                            algorithm:operation
                                            operation:outgoing ? @"write" : @"read"];
    entry.detail = [NSString stringWithFormat:@"SSL=%p len=%zu", ssl, length];
    NSData *data = [NSData dataWithBytes:bytes length:length];
    if (outgoing) entry.input = data;
    else entry.output = data;
    entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static int DHHookedSSLWrite(void *ssl, const void *buffer, int length) {
    if (length > 0) DHLogSSL(@"SSL_write", ssl, buffer, (size_t)length, YES);
    return gOriginalSSLWrite ? gOriginalSSLWrite(ssl, buffer, length) : 0;
}

static int DHHookedSSLRead(void *ssl, void *buffer, int length) {
    int result = gOriginalSSLRead ? gOriginalSSLRead(ssl, buffer, length) : 0;
    if (result > 0) DHLogSSL(@"SSL_read", ssl, buffer, (size_t)result, NO);
    return result;
}

static int DHHookedSSLWriteEx(void *ssl, const void *buffer, size_t length, size_t *written) {
    int result = gOriginalSSLWriteEx ? gOriginalSSLWriteEx(ssl, buffer, length, written) : 0;
    size_t actual = result && written ? *written : 0;
    if (actual) DHLogSSL(@"SSL_write_ex", ssl, buffer, actual, YES);
    return result;
}

static int DHHookedSSLReadEx(void *ssl, void *buffer, size_t length, size_t *readBytes) {
    int result = gOriginalSSLReadEx ? gOriginalSSLReadEx(ssl, buffer, length, readBytes) : 0;
    size_t actual = result && readBytes ? *readBytes : 0;
    if (actual) DHLogSSL(@"SSL_read_ex", ssl, buffer, actual, NO);
    return result;
}

void DHInstallNetworkHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        DHInstallMethod(NSURLSession.class,
                        @selector(dataTaskWithRequest:completionHandler:),
                        (IMP)DHDataTaskWithRequestCompletion,
                        (IMP *)&gOriginalDataTaskRequestCompletion);
        DHInstallMethod(NSURLSession.class,
                        @selector(dataTaskWithURL:completionHandler:),
                        (IMP)DHDataTaskWithURLCompletion,
                        (IMP *)&gOriginalDataTaskURLCompletion);
        DHInstallMethod(NSURLSessionTask.class,
                        @selector(resume),
                        (IMP)DHTaskResume,
                        (IMP *)&gOriginalTaskResume);
        DHInstallClassMethod(NSURLConnection.class,
                             @selector(sendSynchronousRequest:returningResponse:error:),
                             (IMP)DHHookedSynchronousRequest,
                             (IMP *)&gOriginalSynchronousRequest);
        DHInstallClassMethod(NSURLConnection.class,
                             @selector(sendAsynchronousRequest:queue:completionHandler:),
                             (IMP)DHHookedAsynchronousRequest,
                             (IMP *)&gOriginalAsynchronousRequest);

        struct rebinding bindings[] = {
            {"SSL_write", (void *)DHHookedSSLWrite, (void **)&gOriginalSSLWrite},
            {"SSL_read", (void *)DHHookedSSLRead, (void **)&gOriginalSSLRead},
            {"SSL_write_ex", (void *)DHHookedSSLWriteEx, (void **)&gOriginalSSLWriteEx},
            {"SSL_read_ex", (void *)DHHookedSSLReadEx, (void **)&gOriginalSSLReadEx},
        };
        rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
    });
}
