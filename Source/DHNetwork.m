#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <objc/runtime.h>
#include <pthread.h>

static const void *kDHObservedTaskKey = &kDHObservedTaskKey;

typedef NSURLSessionDataTask *(*DHDataTaskRequestCompletionIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDataTask *(*DHDataTaskURLCompletionIMP)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDownloadTask *(*DHDownloadRequestCompletionIMP)(id, SEL, NSURLRequest *, void (^)(NSURL *, NSURLResponse *, NSError *));
typedef NSURLSessionDownloadTask *(*DHDownloadURLCompletionIMP)(id, SEL, NSURL *, void (^)(NSURL *, NSURLResponse *, NSError *));
typedef NSURLSessionDownloadTask *(*DHDownloadResumeCompletionIMP)(id, SEL, NSData *, void (^)(NSURL *, NSURLResponse *, NSError *));
typedef NSURLSessionDownloadTask *(*DHDownloadRequestIMP)(id, SEL, NSURLRequest *);
typedef NSURLSessionDownloadTask *(*DHDownloadURLIMP)(id, SEL, NSURL *);
typedef NSURLSessionDownloadTask *(*DHDownloadResumeIMP)(id, SEL, NSData *);
typedef NSURLSessionUploadTask *(*DHUploadDataCompletionIMP)(id, SEL, NSURLRequest *, NSData *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionUploadTask *(*DHUploadFileCompletionIMP)(id, SEL, NSURLRequest *, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionUploadTask *(*DHUploadDataIMP)(id, SEL, NSURLRequest *, NSData *);
typedef NSURLSessionUploadTask *(*DHUploadFileIMP)(id, SEL, NSURLRequest *, NSURL *);
typedef NSURLSessionUploadTask *(*DHUploadStreamIMP)(id, SEL, NSURLRequest *);
typedef NSURLSession *(*DHSessionFactoryIMP)(Class, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
typedef NSURLSession *(*DHSessionInitIMP)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
typedef void (*DHDownloadDelegateIMP)(id, SEL, NSURLSession *, NSURLSessionDownloadTask *, NSURL *);
typedef void (*DHTaskResumeIMP)(id, SEL);
typedef NSData *(*DHSynchronousRequestIMP)(Class, SEL, NSURLRequest *, NSURLResponse **, NSError **);
typedef void (*DHAsynchronousRequestIMP)(Class, SEL, NSURLRequest *, NSOperationQueue *,
                                         void (^)(NSURLResponse *, NSData *, NSError *));

static DHDataTaskRequestCompletionIMP gOriginalDataTaskRequestCompletion;
static DHDataTaskURLCompletionIMP gOriginalDataTaskURLCompletion;
static DHDownloadRequestCompletionIMP gOriginalDownloadRequestCompletion;
static DHDownloadURLCompletionIMP gOriginalDownloadURLCompletion;
static DHDownloadResumeCompletionIMP gOriginalDownloadResumeCompletion;
static DHDownloadRequestIMP gOriginalDownloadRequest;
static DHDownloadURLIMP gOriginalDownloadURL;
static DHDownloadResumeIMP gOriginalDownloadResume;
static DHUploadDataCompletionIMP gOriginalUploadDataCompletion;
static DHUploadFileCompletionIMP gOriginalUploadFileCompletion;
static DHUploadDataIMP gOriginalUploadData;
static DHUploadFileIMP gOriginalUploadFile;
static DHUploadStreamIMP gOriginalUploadStream;
static DHSessionFactoryIMP gOriginalSessionFactory;
static DHSessionInitIMP gOriginalSessionInit;
static DHTaskResumeIMP gOriginalTaskResume;
static DHSynchronousRequestIMP gOriginalSynchronousRequest;
static DHAsynchronousRequestIMP gOriginalAsynchronousRequest;
static __thread NSUInteger gNetworkCreationGuard;
static const NSUInteger kDHNetworkPreviewLimit = 1024 * 1024;
static NSMutableDictionary<NSString *, id> *gDownloadDelegateOriginals;
static pthread_mutex_t gDownloadDelegateLock = PTHREAD_MUTEX_INITIALIZER;

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

static NSData *DHBoundedNetworkData(NSData *data) {
    if (!data.length) return nil;
    if (data.length <= kDHNetworkPreviewLimit) return [data copy];
    return [data subdataWithRange:NSMakeRange(0, kDHNetworkPreviewLimit)];
}

static NSDictionary *DHFileTransferMetadata(NSURL *fileURL, NSString *role, NSData **preview) {
    if (preview) *preview = nil;
    if (!fileURL.isFileURL || !fileURL.path.length) {
        return @{ @"fileRole": role ?: @"file", @"fileURL": fileURL.absoluteString ?: @"" };
    }
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:fileURL.path error:nil];
    uint64_t size = [attributes[NSFileSize] unsignedLongLongValue];
    NSData *captured = nil;
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:fileURL.path];
    if (handle) {
        captured = [handle readDataOfLength:(NSUInteger)MIN((uint64_t)kDHNetworkPreviewLimit, size)];
        [handle closeFile];
    }
    if (preview) *preview = captured;
    return @{
        @"fileRole": role ?: @"file",
        @"filePath": fileURL.path ?: @"",
        @"fileName": fileURL.lastPathComponent ?: @"",
        @"fileSize": @(size),
        @"capturedFileLength": @(captured.length),
        @"filePreviewTruncated": @(size > captured.length)
    };
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
    entry.input = DHBoundedNetworkData(request.HTTPBody);
    entry.output = DHBoundedNetworkData(data);
    entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static void DHLogURLSessionTransfer(NSString *kind,
                                    NSString *phase,
                                    NSURLRequest *request,
                                    NSDictionary *additionalHeaders,
                                    NSData *input,
                                    NSData *output,
                                    NSURLResponse *response,
                                    NSError *error,
                                    NSDictionary *transferMetadata) {
    if (![DHConfig shared].networkEnabled) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK"
                                            algorithm:[NSString stringWithFormat:@"NSURLSession.%@", kind ?: @"transfer"]
                                            operation:phase ?: kind ?: @"transfer"];
    NSMutableDictionary *metadata = [DHRequestMetadata(request, additionalHeaders) mutableCopy];
    if (!metadata) metadata = [NSMutableDictionary dictionary];
    metadata[@"transferKind"] = kind ?: @"transfer";
    metadata[@"phase"] = phase ?: @"unknown";
    if (transferMetadata) [metadata addEntriesFromDictionary:transferMetadata];
    [metadata addEntriesFromDictionary:DHResponseMetadata(response, error)];
    entry.detail = DHJSONString(metadata);
    entry.input = DHBoundedNetworkData(input ?: request.HTTPBody);
    entry.output = DHBoundedNetworkData(output);
    entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}

static NSDictionary *DHSessionHeaders(id session) {
    id configuration = [session respondsToSelector:@selector(configuration)] ? [session configuration] : nil;
    NSDictionary *headers = [configuration respondsToSelector:@selector(HTTPAdditionalHeaders)] ?
        [configuration HTTPAdditionalHeaders] : nil;
    return [headers isKindOfClass:NSDictionary.class] ? [headers copy] : nil;
}

static void DHMarkObservedTask(id task) {
    if (task) objc_setAssociatedObject(task, kDHObservedTaskKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static DHDownloadDelegateIMP DHDownloadDelegateOriginalForClassLocked(Class cls) {
    while (cls) {
        id stored = gDownloadDelegateOriginals[NSStringFromClass(cls)];
        if (stored) return stored == NSNull.null ? NULL : (DHDownloadDelegateIMP)[stored pointerValue];
        cls = class_getSuperclass(cls);
    }
    return NULL;
}

static DHDownloadDelegateIMP DHDownloadDelegateOriginalForObject(id object) {
    pthread_mutex_lock(&gDownloadDelegateLock);
    DHDownloadDelegateIMP original = DHDownloadDelegateOriginalForClassLocked(object_getClass(object));
    pthread_mutex_unlock(&gDownloadDelegateLock);
    return original;
}

static void DHDownloadDelegateDidFinish(id self, SEL cmd, NSURLSession *session,
                                        NSURLSessionDownloadTask *task, NSURL *location) {
    if ([DHConfig shared].networkEnabled) {
        NSData *preview = nil;
        NSMutableDictionary *metadata = [DHFileTransferMetadata(location, @"download-temporary", &preview) mutableCopy];
        metadata[@"temporaryLocation"] = @YES;
        metadata[@"delivery"] = @"delegate";
        NSURLRequest *request = task.currentRequest ?: task.originalRequest;
        DHLogURLSessionTransfer(@"download", @"delegate-file", request, DHSessionHeaders(session),
                                nil, preview, task.response, nil, metadata);
        DHMarkObservedTask(task);
    }
    DHDownloadDelegateIMP original = DHDownloadDelegateOriginalForObject(self);
    if (original && original != DHDownloadDelegateDidFinish) original(self, cmd, session, task, location);
}

static void DHInstallDownloadDelegateHook(id delegate) {
    if (!delegate) return;
    Class cls = object_getClass(delegate);
    NSString *className = NSStringFromClass(cls);
    SEL selector = @selector(URLSession:downloadTask:didFinishDownloadingToURL:);
    pthread_mutex_lock(&gDownloadDelegateLock);
    if (!gDownloadDelegateOriginals) gDownloadDelegateOriginals = [NSMutableDictionary dictionary];
    if (gDownloadDelegateOriginals[className]) {
        pthread_mutex_unlock(&gDownloadDelegateLock);
        return;
    }

    Method method = class_getInstanceMethod(cls, selector);
    if (!method) {
        pthread_mutex_unlock(&gDownloadDelegateLock);
        return;
    }
    IMP original = method_getImplementation(method);
    if (original == (IMP)DHDownloadDelegateDidFinish) {
        original = (IMP)DHDownloadDelegateOriginalForClassLocked(class_getSuperclass(cls));
    }
    const char *types = method_getTypeEncoding(method);
    if (!class_addMethod(cls, selector, (IMP)DHDownloadDelegateDidFinish, types)) {
        Method ownMethod = class_getInstanceMethod(cls, selector);
        if (ownMethod) original = method_setImplementation(ownMethod, (IMP)DHDownloadDelegateDidFinish);
    }
    gDownloadDelegateOriginals[className] = original ? [NSValue valueWithPointer:(const void *)original] : NSNull.null;
    pthread_mutex_unlock(&gDownloadDelegateLock);
}

static NSURLSession *DHSessionWithConfiguration(Class cls, SEL cmd, NSURLSessionConfiguration *configuration,
                                                id delegate, NSOperationQueue *queue) {
    DHInstallDownloadDelegateHook(delegate);
    return gOriginalSessionFactory ? gOriginalSessionFactory(cls, cmd, configuration, delegate, queue) : nil;
}

static NSURLSession *DHSessionInitWithConfiguration(id self, SEL cmd, NSURLSessionConfiguration *configuration,
                                                    id delegate, NSOperationQueue *queue) {
    DHInstallDownloadDelegateHook(delegate);
    return gOriginalSessionInit ? gOriginalSessionInit(self, cmd, configuration, delegate, queue) : nil;
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

static NSURLSessionDownloadTask *DHDownloadWithRequestCompletion(id self, SEL cmd,
                                                                  NSURLRequest *request,
                                                                  void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
    if (!gOriginalDownloadRequestCompletion) return nil;
    if (![DHConfig shared].networkEnabled) return gOriginalDownloadRequestCompletion(self, cmd, request, completion);
    NSURLRequest *capturedRequest = [request copy];
    NSDictionary *headers = DHSessionHeaders(self);
    void (^wrapped)(NSURL *, NSURLResponse *, NSError *) = ^(NSURL *location, NSURLResponse *response, NSError *error) {
        NSData *preview = nil;
        NSMutableDictionary *metadata = [DHFileTransferMetadata(location, @"download-temporary", &preview) mutableCopy];
        metadata[@"temporaryLocation"] = @YES;
        DHLogURLSessionTransfer(@"download", @"completed", capturedRequest, headers, nil, preview,
                                response, error, metadata);
        if (completion) completion(location, response, error);
    };
    gNetworkCreationGuard++;
    NSURLSessionDownloadTask *task = gOriginalDownloadRequestCompletion(self, cmd, request, wrapped);
    gNetworkCreationGuard--;
    DHMarkObservedTask(task);
    return task;
}

static NSURLSessionDownloadTask *DHDownloadWithURLCompletion(id self, SEL cmd, NSURL *url,
                                                              void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
    if (!gOriginalDownloadURLCompletion) return nil;
    if (![DHConfig shared].networkEnabled) return gOriginalDownloadURLCompletion(self, cmd, url, completion);
    NSURLRequest *request = url ? [NSURLRequest requestWithURL:url] : nil;
    NSDictionary *headers = DHSessionHeaders(self);
    void (^wrapped)(NSURL *, NSURLResponse *, NSError *) = ^(NSURL *location, NSURLResponse *response, NSError *error) {
        NSData *preview = nil;
        NSMutableDictionary *metadata = [DHFileTransferMetadata(location, @"download-temporary", &preview) mutableCopy];
        metadata[@"temporaryLocation"] = @YES;
        DHLogURLSessionTransfer(@"download", @"completed", request, headers, nil, preview,
                                response, error, metadata);
        if (completion) completion(location, response, error);
    };
    gNetworkCreationGuard++;
    NSURLSessionDownloadTask *task = gOriginalDownloadURLCompletion(self, cmd, url, wrapped);
    gNetworkCreationGuard--;
    DHMarkObservedTask(task);
    return task;
}

static NSURLSessionDownloadTask *DHDownloadWithResumeCompletion(id self, SEL cmd, NSData *resumeData,
                                                                 void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
    if (!gOriginalDownloadResumeCompletion) return nil;
    if (![DHConfig shared].networkEnabled) return gOriginalDownloadResumeCompletion(self, cmd, resumeData, completion);
    NSDictionary *headers = DHSessionHeaders(self);
    NSData *capturedResumeData = DHBoundedNetworkData(resumeData);
    void (^wrapped)(NSURL *, NSURLResponse *, NSError *) = ^(NSURL *location, NSURLResponse *response, NSError *error) {
        NSData *preview = nil;
        NSMutableDictionary *metadata = [DHFileTransferMetadata(location, @"download-temporary", &preview) mutableCopy];
        metadata[@"temporaryLocation"] = @YES;
        metadata[@"resumeDataLength"] = @(resumeData.length);
        DHLogURLSessionTransfer(@"download", @"completed", nil, headers, capturedResumeData, preview,
                                response, error, metadata);
        if (completion) completion(location, response, error);
    };
    gNetworkCreationGuard++;
    NSURLSessionDownloadTask *task = gOriginalDownloadResumeCompletion(self, cmd, resumeData, wrapped);
    gNetworkCreationGuard--;
    DHMarkObservedTask(task);
    return task;
}

static NSURLSessionUploadTask *DHUploadWithDataCompletion(id self, SEL cmd, NSURLRequest *request,
                                                           NSData *bodyData,
                                                           void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    if (!gOriginalUploadDataCompletion) return nil;
    if (![DHConfig shared].networkEnabled) return gOriginalUploadDataCompletion(self, cmd, request, bodyData, completion);
    NSURLRequest *capturedRequest = [request copy];
    NSDictionary *headers = DHSessionHeaders(self);
    NSData *capturedBody = DHBoundedNetworkData(bodyData);
    NSDictionary *transfer = @{ @"uploadSource": @"data", @"uploadLength": @(bodyData.length),
                                @"uploadPreviewTruncated": @(bodyData.length > capturedBody.length) };
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        DHLogURLSessionTransfer(@"upload", @"completed", capturedRequest, headers, capturedBody,
                                data, response, error, transfer);
        if (completion) completion(data, response, error);
    };
    gNetworkCreationGuard++;
    NSURLSessionUploadTask *task = gOriginalUploadDataCompletion(self, cmd, request, bodyData, wrapped);
    gNetworkCreationGuard--;
    DHMarkObservedTask(task);
    return task;
}

static NSURLSessionUploadTask *DHUploadWithFileCompletion(id self, SEL cmd, NSURLRequest *request,
                                                           NSURL *fileURL,
                                                           void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    if (!gOriginalUploadFileCompletion) return nil;
    if (![DHConfig shared].networkEnabled) return gOriginalUploadFileCompletion(self, cmd, request, fileURL, completion);
    NSURLRequest *capturedRequest = [request copy];
    NSDictionary *headers = DHSessionHeaders(self);
    NSData *preview = nil;
    NSDictionary *transfer = DHFileTransferMetadata(fileURL, @"upload-source", &preview);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        DHLogURLSessionTransfer(@"upload", @"completed", capturedRequest, headers, preview,
                                data, response, error, transfer);
        if (completion) completion(data, response, error);
    };
    gNetworkCreationGuard++;
    NSURLSessionUploadTask *task = gOriginalUploadFileCompletion(self, cmd, request, fileURL, wrapped);
    gNetworkCreationGuard--;
    DHMarkObservedTask(task);
    return task;
}

static NSURLSessionDownloadTask *DHDownloadWithRequest(id self, SEL cmd, NSURLRequest *request) {
    if (!gOriginalDownloadRequest) return nil;
    NSURLSessionDownloadTask *task = gOriginalDownloadRequest(self, cmd, request);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        DHLogURLSessionTransfer(@"download", @"created", request, DHSessionHeaders(self), nil, nil,
                                nil, nil, @{ @"delivery": @"delegate" });
        DHMarkObservedTask(task);
    }
    return task;
}

static NSURLSessionDownloadTask *DHDownloadWithURL(id self, SEL cmd, NSURL *url) {
    if (!gOriginalDownloadURL) return nil;
    NSURLSessionDownloadTask *task = gOriginalDownloadURL(self, cmd, url);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        NSURLRequest *request = url ? [NSURLRequest requestWithURL:url] : nil;
        DHLogURLSessionTransfer(@"download", @"created", request, DHSessionHeaders(self), nil, nil,
                                nil, nil, @{ @"delivery": @"delegate" });
        DHMarkObservedTask(task);
    }
    return task;
}

static NSURLSessionDownloadTask *DHDownloadWithResumeData(id self, SEL cmd, NSData *resumeData) {
    if (!gOriginalDownloadResume) return nil;
    NSURLSessionDownloadTask *task = gOriginalDownloadResume(self, cmd, resumeData);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        DHLogURLSessionTransfer(@"download", @"created", nil, DHSessionHeaders(self),
                                DHBoundedNetworkData(resumeData), nil, nil, nil,
                                @{ @"delivery": @"delegate", @"resumeDataLength": @(resumeData.length) });
        DHMarkObservedTask(task);
    }
    return task;
}

static NSURLSessionUploadTask *DHUploadWithData(id self, SEL cmd, NSURLRequest *request, NSData *bodyData) {
    if (!gOriginalUploadData) return nil;
    NSURLSessionUploadTask *task = gOriginalUploadData(self, cmd, request, bodyData);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        NSData *preview = DHBoundedNetworkData(bodyData);
        DHLogURLSessionTransfer(@"upload", @"created", request, DHSessionHeaders(self), preview, nil,
                                nil, nil, @{ @"delivery": @"delegate", @"uploadSource": @"data",
                                             @"uploadLength": @(bodyData.length),
                                             @"uploadPreviewTruncated": @(bodyData.length > preview.length) });
        DHMarkObservedTask(task);
    }
    return task;
}

static NSURLSessionUploadTask *DHUploadWithFile(id self, SEL cmd, NSURLRequest *request, NSURL *fileURL) {
    if (!gOriginalUploadFile) return nil;
    NSURLSessionUploadTask *task = gOriginalUploadFile(self, cmd, request, fileURL);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        NSData *preview = nil;
        NSDictionary *transfer = DHFileTransferMetadata(fileURL, @"upload-source", &preview);
        DHLogURLSessionTransfer(@"upload", @"created", request, DHSessionHeaders(self), preview, nil,
                                nil, nil, transfer);
        DHMarkObservedTask(task);
    }
    return task;
}

static NSURLSessionUploadTask *DHUploadWithStream(id self, SEL cmd, NSURLRequest *request) {
    if (!gOriginalUploadStream) return nil;
    NSURLSessionUploadTask *task = gOriginalUploadStream(self, cmd, request);
    if ([DHConfig shared].networkEnabled && !gNetworkCreationGuard) {
        DHLogURLSessionTransfer(@"upload", @"created", request, DHSessionHeaders(self), nil, nil,
                                nil, nil, @{ @"delivery": @"delegate", @"uploadSource": @"stream",
                                             @"bodyStreamConsumed": @NO });
        DHMarkObservedTask(task);
    }
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
        DHRegisterHook(@"NSURLSession.sessionWithConfiguration:delegate:delegateQueue:", @"objc",
                       DHInstallClassMethod(NSURLSession.class,
                         @selector(sessionWithConfiguration:delegate:delegateQueue:),
                         (IMP)DHSessionWithConfiguration, (IMP *)&gOriginalSessionFactory));
        DHRegisterHook(@"NSURLSession.initWithConfiguration:delegate:delegateQueue:", @"objc",
                       DHInstallMethod(NSURLSession.class,
                         @selector(initWithConfiguration:delegate:delegateQueue:),
                         (IMP)DHSessionInitWithConfiguration, (IMP *)&gOriginalSessionInit));
        DHRegisterHook(@"NSURLSession.dataTaskWithRequest:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(dataTaskWithRequest:completionHandler:),
                         (IMP)DHDataTaskWithRequestCompletion,
                         (IMP *)&gOriginalDataTaskRequestCompletion));
        DHRegisterHook(@"NSURLSession.dataTaskWithURL:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(dataTaskWithURL:completionHandler:),
                         (IMP)DHDataTaskWithURLCompletion,
                         (IMP *)&gOriginalDataTaskURLCompletion));
        DHRegisterHook(@"NSURLSession.downloadTaskWithRequest:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithRequest:completionHandler:), (IMP)DHDownloadWithRequestCompletion,
                         (IMP *)&gOriginalDownloadRequestCompletion));
        DHRegisterHook(@"NSURLSession.downloadTaskWithURL:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithURL:completionHandler:), (IMP)DHDownloadWithURLCompletion,
                         (IMP *)&gOriginalDownloadURLCompletion));
        DHRegisterHook(@"NSURLSession.downloadTaskWithResumeData:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithResumeData:completionHandler:), (IMP)DHDownloadWithResumeCompletion,
                         (IMP *)&gOriginalDownloadResumeCompletion));
        DHRegisterHook(@"NSURLSession.downloadTaskWithRequest:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithRequest:), (IMP)DHDownloadWithRequest, (IMP *)&gOriginalDownloadRequest));
        DHRegisterHook(@"NSURLSession.downloadTaskWithURL:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithURL:), (IMP)DHDownloadWithURL, (IMP *)&gOriginalDownloadURL));
        DHRegisterHook(@"NSURLSession.downloadTaskWithResumeData:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(downloadTaskWithResumeData:), (IMP)DHDownloadWithResumeData, (IMP *)&gOriginalDownloadResume));
        DHRegisterHook(@"NSURLSession.uploadTaskWithRequest:fromData:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(uploadTaskWithRequest:fromData:completionHandler:), (IMP)DHUploadWithDataCompletion,
                         (IMP *)&gOriginalUploadDataCompletion));
        DHRegisterHook(@"NSURLSession.uploadTaskWithRequest:fromFile:completionHandler:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(uploadTaskWithRequest:fromFile:completionHandler:), (IMP)DHUploadWithFileCompletion,
                         (IMP *)&gOriginalUploadFileCompletion));
        DHRegisterHook(@"NSURLSession.uploadTaskWithRequest:fromData:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(uploadTaskWithRequest:fromData:), (IMP)DHUploadWithData, (IMP *)&gOriginalUploadData));
        DHRegisterHook(@"NSURLSession.uploadTaskWithRequest:fromFile:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(uploadTaskWithRequest:fromFile:), (IMP)DHUploadWithFile, (IMP *)&gOriginalUploadFile));
        DHRegisterHook(@"NSURLSession.uploadTaskWithStreamedRequest:", @"objc", DHInstallMethod(NSURLSession.class,
                         @selector(uploadTaskWithStreamedRequest:), (IMP)DHUploadWithStream, (IMP *)&gOriginalUploadStream));
        DHRegisterHook(@"NSURLSessionTask.resume", @"objc", DHInstallMethod(NSURLSessionTask.class,
                         @selector(resume),
                         (IMP)DHTaskResume,
                         (IMP *)&gOriginalTaskResume));
        DHRegisterHook(@"NSURLConnection.sendSynchronousRequest:returningResponse:error:", @"objc", DHInstallClassMethod(NSURLConnection.class,
                         @selector(sendSynchronousRequest:returningResponse:error:),
                         (IMP)DHHookedSynchronousRequest,
                         (IMP *)&gOriginalSynchronousRequest));
        DHRegisterHook(@"NSURLConnection.sendAsynchronousRequest:queue:completionHandler:", @"objc", DHInstallClassMethod(NSURLConnection.class,
                         @selector(sendAsynchronousRequest:queue:completionHandler:),
                         (IMP)DHHookedAsynchronousRequest,
                         (IMP *)&gOriginalAsynchronousRequest));

        struct rebinding bindings[] = {
            {"SSL_write", (void *)DHHookedSSLWrite, (void **)&gOriginalSSLWrite},
            {"SSL_read", (void *)DHHookedSSLRead, (void **)&gOriginalSSLRead},
            {"SSL_write_ex", (void *)DHHookedSSLWriteEx, (void **)&gOriginalSSLWriteEx},
            {"SSL_read_ex", (void *)DHHookedSSLReadEx, (void **)&gOriginalSSLReadEx},
        };
        int status = rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
        for (size_t i = 0; i < sizeof(bindings) / sizeof(bindings[0]); i++)
            DHRegisterHook([NSString stringWithUTF8String:bindings[i].name], @"fishhook", status == 0);
    });
}
