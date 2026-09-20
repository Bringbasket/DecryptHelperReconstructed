#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <arpa/inet.h>
#import <netdb.h>
#import <sys/socket.h>
#import <sys/uio.h>
#import <dlfcn.h>

static const NSUInteger kDHExtCaptureLimit = 1024 * 1024;
static NSData *DHExtData(const void *bytes, size_t length) {
    if (!bytes || !length) return nil;
    return [NSData dataWithBytes:bytes length:MIN(length, kDHExtCaptureLimit)];
}
static void DHExtLog(NSString *algorithm, NSString *operation, NSString *detail, NSData *input, NSData *output) {
    if (![DHConfig shared].networkEnabled) return;
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"NETWORK" algorithm:algorithm ?: @"network" operation:operation ?: @"observe"];
    entry.detail = detail; entry.input = input; entry.output = output; entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}
static BOOL DHExtIsSocket(int fd) {
    int type = 0; socklen_t length = sizeof(type);
    return fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0;
}
static NSString *DHExtAddress(const struct sockaddr *address, socklen_t length) {
    if (!address || !length) return @"";
    char host[NI_MAXHOST] = {0}; char service[NI_MAXSERV] = {0};
    if (getnameinfo(address, length, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0) return @"";
    return [NSString stringWithFormat:@"%s:%s", host, service];
}

typedef int (*DHSocketFn)(int, int, int); typedef int (*DHConnectFn)(int, const struct sockaddr *, socklen_t);
typedef int (*DHAcceptFn)(int, struct sockaddr *, socklen_t *); typedef ssize_t (*DHReadFn)(int, void *, size_t);
typedef ssize_t (*DHWriteFn)(int, const void *, size_t); typedef ssize_t (*DHSendFn)(int, const void *, size_t, int);
typedef ssize_t (*DHRecvFn)(int, void *, size_t, int); typedef ssize_t (*DHSendToFn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*DHRecvFromFn)(int, void *, size_t, int, struct sockaddr *, socklen_t *); typedef ssize_t (*DHSendMsgFn)(int, const struct msghdr *, int);
typedef ssize_t (*DHRecvMsgFn)(int, struct msghdr *, int); typedef int (*DHCloseFn)(int);
typedef int (*DHGetAddrInfoFn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static DHSocketFn gSocket; static DHConnectFn gConnect; static DHAcceptFn gAccept; static DHReadFn gRead; static DHWriteFn gWrite;
static DHSendFn gSend; static DHRecvFn gRecv; static DHSendToFn gSendTo; static DHRecvFromFn gRecvFrom; static DHSendMsgFn gSendMsg;
static DHRecvMsgFn gRecvMsg; static DHCloseFn gClose; static DHGetAddrInfoFn gGetAddrInfo;

static int HSocket(int d, int t, int p) { int r = gSocket ? gSocket(d,t,p) : -1; if (r >= 0) DHExtLog(@"BSD-SOCKET", @"socket", [NSString stringWithFormat:@"fd=%d domain=%d type=%d protocol=%d",r,d,t,p], nil, nil); return r; }
static int HConnect(int fd, const struct sockaddr *a, socklen_t l) { int r = gConnect ? gConnect(fd,a,l) : -1; if (r == 0 || DHExtIsSocket(fd)) DHExtLog(@"BSD-SOCKET", @"connect", [NSString stringWithFormat:@"fd=%d address=%@ result=%d",fd,DHExtAddress(a,l),r], nil, nil); return r; }
static int HAccept(int fd, struct sockaddr *a, socklen_t *l) { int r = gAccept ? gAccept(fd,a,l) : -1; if (r >= 0) DHExtLog(@"BSD-SOCKET", @"accept", [NSString stringWithFormat:@"listener=%d fd=%d address=%@",fd,r,DHExtAddress(a,l ? *l : 0)], nil, nil); return r; }
static ssize_t HRead(int fd, void *b, size_t n) { ssize_t r = gRead ? gRead(fd,b,n) : -1; if (r > 0 && DHExtIsSocket(fd)) DHExtLog(@"BSD-SOCKET", @"read", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], nil, DHExtData(b,r)); return r; }
static ssize_t HWrite(int fd, const void *b, size_t n) { ssize_t r = gWrite ? gWrite(fd,b,n) : -1; if (r > 0 && DHExtIsSocket(fd)) DHExtLog(@"BSD-SOCKET", @"write", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], DHExtData(b,r), nil); return r; }
static ssize_t HSend(int fd, const void *b, size_t n, int f) { ssize_t r = gSend ? gSend(fd,b,n,f) : -1; if (r > 0) DHExtLog(@"BSD-SOCKET", @"send", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], DHExtData(b,r), nil); return r; }
static ssize_t HRecv(int fd, void *b, size_t n, int f) { ssize_t r = gRecv ? gRecv(fd,b,n,f) : -1; if (r > 0) DHExtLog(@"BSD-SOCKET", @"recv", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], nil, DHExtData(b,r)); return r; }
static ssize_t HSendTo(int fd, const void *b, size_t n, int f, const struct sockaddr *a, socklen_t l) { ssize_t r = gSendTo ? gSendTo(fd,b,n,f,a,l) : -1; if (r > 0) DHExtLog(@"BSD-SOCKET", @"sendto", [NSString stringWithFormat:@"fd=%d address=%@ result=%zd",fd,DHExtAddress(a,l),r], DHExtData(b,r), nil); return r; }
static ssize_t HRecvFrom(int fd, void *b, size_t n, int f, struct sockaddr *a, socklen_t *l) { ssize_t r = gRecvFrom ? gRecvFrom(fd,b,n,f,a,l) : -1; if (r > 0) DHExtLog(@"BSD-SOCKET", @"recvfrom", [NSString stringWithFormat:@"fd=%d address=%@ result=%zd",fd,DHExtAddress(a,l ? *l : 0),r], nil, DHExtData(b,r)); return r; }
static NSData *HVector(const struct iovec *v, size_t count) { NSMutableData *d = [NSMutableData data]; for (size_t i=0;i<count && d.length<kDHExtCaptureLimit;i++) if (v[i].iov_base && v[i].iov_len) [d appendBytes:v[i].iov_base length:MIN(kDHExtCaptureLimit-d.length,v[i].iov_len)]; return d.length ? d : nil; }
static ssize_t HSendMsg(int fd, const struct msghdr *m, int f) { ssize_t r = gSendMsg ? gSendMsg(fd,m,f) : -1; if (r > 0 && m) DHExtLog(@"BSD-SOCKET", @"sendmsg", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], HVector(m->msg_iov,m->msg_iovlen), nil); return r; }
static ssize_t HRecvMsg(int fd, struct msghdr *m, int f) { ssize_t r = gRecvMsg ? gRecvMsg(fd,m,f) : -1; if (r > 0 && m) DHExtLog(@"BSD-SOCKET", @"recvmsg", [NSString stringWithFormat:@"fd=%d result=%zd",fd,r], nil, HVector(m->msg_iov,m->msg_iovlen)); return r; }
static int HClose(int fd) { BOOL socket = DHExtIsSocket(fd); int r = gClose ? gClose(fd) : -1; if (socket) DHExtLog(@"BSD-SOCKET", @"close", [NSString stringWithFormat:@"fd=%d result=%d",fd,r], nil, nil); return r; }
static int HGetAddrInfo(const char *n, const char *s, const struct addrinfo *h, struct addrinfo **r) { int status = gGetAddrInfo ? gGetAddrInfo(n,s,h,r) : EAI_FAIL; DHExtLog(@"BSD-SOCKET", @"getaddrinfo", [NSString stringWithFormat:@"node=%s service=%s status=%d",n ?: "",s ?: "",status], nil, nil); return status; }

typedef int32_t DHTransportFn(void *, const void *, size_t, size_t *); typedef int32_t DHReadTransportFn(void *, void *, size_t, size_t *);
static DHTransportFn *gSSLWrite; static DHReadTransportFn *gSSLRead;
static int32_t HSSLWrite(void *c, const void *b, size_t n, size_t *p) { int32_t r = gSSLWrite ? gSSLWrite(c,b,n,p) : -1; size_t a = p ? *p : (r == 0 ? n : 0); if (a) DHExtLog(@"SecureTransport", @"write", [NSString stringWithFormat:@"context=%p result=%d",c,r], DHExtData(b,a), nil); return r; }
static int32_t HSSLRead(void *c, void *b, size_t n, size_t *p) { int32_t r = gSSLRead ? gSSLRead(c,b,n,p) : -1; size_t a = p ? *p : 0; if (a) DHExtLog(@"SecureTransport", @"read", [NSString stringWithFormat:@"context=%p result=%d",c,r], nil, DHExtData(b,a)); return r; }

static BOOL DHHookInstalled(NSString *name) { for (NSDictionary *h in DHHookRegistrySnapshot()) if ([h[@"name"] isEqualToString:name]) return [h[@"installed"] boolValue] && [h[@"success"] boolValue]; return NO; }

NSDictionary<NSString *, id> *DHNetworkCaptureCoverage(void) {
    BOOL send = dlsym(RTLD_DEFAULT, "nw_send") != NULL || dlsym(RTLD_DEFAULT, "nw_connection_send") != NULL;
    BOOL receive = dlsym(RTLD_DEFAULT, "nw_receive") != NULL || dlsym(RTLD_DEFAULT, "nw_connection_receive") != NULL;
    NSMutableArray *blind = [NSMutableArray array]; if (!send) [blind addObject:@"Network.framework send symbol unavailable or statically linked"]; if (!receive) [blind addObject:@"Network.framework receive symbol unavailable or statically linked"];
    return @{
        @"NSURLSession": @{ @"installed": @YES }, @"NSURLConnection": @{ @"installed": @YES },
        @"OpenSSL/BoringSSL TLS": @{ @"installed": @(DHHookInstalled(@"SSL_write") || DHHookInstalled(@"SSL_write_ex")) },
        @"Apple SecureTransport": @{ @"installed": @(DHHookInstalled(@"SSLWrite") || DHHookInstalled(@"SSLRead")) },
        @"BSD socket": @{ @"installed": @(DHHookInstalled(@"socket") && DHHookInstalled(@"send") && DHHookInstalled(@"recv")) },
        @"Network.framework": @{ @"available": @(send && receive), @"send": @(send), @"receive": @(receive) },
        @"WebSocket": @{ @"installed": @(DHHookInstalled(@"NSURLSessionWebSocketTask.sendMessage:")) },
        @"WebKit": DHWebKitProbeSnapshot(),
        @"Security RSA modern": @{ @"installed": @(DHHookInstalled(@"SecKeyCreateSignature") && DHHookInstalled(@"SecKeyCreateEncryptedData")) },
        @"Security RSA legacy": @{ @"installed": @(DHHookInstalled(@"SecKeyEncrypt") && DHHookInstalled(@"SecKeyRawSign")) },
        @"OpenSSL RSA": @{ @"installed": @(DHHookInstalled(@"RSA_public_encrypt") || DHHookInstalled(@"RSA_private_decrypt")) },
        @"CommonCrypto": @{ @"installed": @(DHHookInstalled(@"CCCrypt") && DHHookInstalled(@"CC_SHA256")) },
        @"CommonCrypto RNG": @{ @"installed": @(DHHookInstalled(@"CCRandomGenerateBytes")) },
        @"Security RNG": @{ @"installed": @(DHHookInstalled(@"SecRandomCopyBytes")) },
        @"available": @YES, @"images_importing": @[], @"blind_spots": blind,
        @"hint": @"When Crypto events are empty, inspect static-library imports in the target image."
    };
}

void DHInstallNetworkExtensions(void) {
    static dispatch_once_t onceToken; dispatch_once(&onceToken, ^{
        struct rebinding b[] = {{"socket",(void *)HSocket,(void **)&gSocket},{"connect",(void *)HConnect,(void **)&gConnect},{"accept",(void *)HAccept,(void **)&gAccept},{"read",(void *)HRead,(void **)&gRead},{"write",(void *)HWrite,(void **)&gWrite},{"send",(void *)HSend,(void **)&gSend},{"recv",(void *)HRecv,(void **)&gRecv},{"sendto",(void *)HSendTo,(void **)&gSendTo},{"recvfrom",(void *)HRecvFrom,(void **)&gRecvFrom},{"sendmsg",(void *)HSendMsg,(void **)&gSendMsg},{"recvmsg",(void *)HRecvMsg,(void **)&gRecvMsg},{"close",(void *)HClose,(void **)&gClose},{"getaddrinfo",(void *)HGetAddrInfo,(void **)&gGetAddrInfo},{"SSLWrite",(void *)HSSLWrite,(void **)&gSSLWrite},{"SSLRead",(void *)HSSLRead,(void **)&gSSLRead}};
        DHRebindSymbols(b, sizeof(b) / sizeof(b[0]), @"fishhook");
    });
}
