#import "DHEVP.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "fishhook.h"
#include <pthread.h>
#include <stdint.h>
#include <dlfcn.h>

typedef struct evp_cipher_ctx_st DH_EVP_CIPHER_CTX;
typedef struct evp_cipher_st DH_EVP_CIPHER;
typedef struct engine_st DH_EVP_ENGINE;

typedef int (*DHEVPInitFn)(DH_EVP_CIPHER_CTX *, const DH_EVP_CIPHER *, DH_EVP_ENGINE *,
                           const unsigned char *, const unsigned char *);
typedef int (*DHEVPCipherInitFn)(DH_EVP_CIPHER_CTX *, const DH_EVP_CIPHER *, DH_EVP_ENGINE *,
                                 const unsigned char *, const unsigned char *, int);
typedef int (*DHEVPUpdateFn)(DH_EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
typedef int (*DHEVPFinalFn)(DH_EVP_CIPHER_CTX *, unsigned char *, int *);
typedef int (*DHEVPResetFn)(DH_EVP_CIPHER_CTX *);
typedef void (*DHEVPFreeFn)(DH_EVP_CIPHER_CTX *);
typedef int (*DHEVPCtrlFn)(DH_EVP_CIPHER_CTX *, int, int, void *);

static DHEVPInitFn gOriginalEVPEncryptInitEx;
static DHEVPInitFn gOriginalEVPDecryptInitEx;
static DHEVPCipherInitFn gOriginalEVPCipherInitEx;
static DHEVPUpdateFn gOriginalEVPEncryptUpdate;
static DHEVPUpdateFn gOriginalEVPDecryptUpdate;
static DHEVPUpdateFn gOriginalEVPCipherUpdate;
static DHEVPFinalFn gOriginalEVPEncryptFinalEx;
static DHEVPFinalFn gOriginalEVPDecryptFinalEx;
static DHEVPFinalFn gOriginalEVPCipherFinalEx;
static DHEVPResetFn gOriginalEVPCtxReset;
static DHEVPFreeFn gOriginalEVPCtxFree;
static DHEVPCtrlFn gOriginalEVPCtxCtrl;

@interface DHEVPCapture : NSObject
@property (nonatomic) NSInteger direction;
@property (nonatomic) const void *cipher;
@property (nonatomic, copy) NSData *key;
@property (nonatomic, copy) NSData *iv;
@property (nonatomic, strong) NSMutableData *input;
@property (nonatomic, strong) NSMutableData *output;
@property (nonatomic) BOOL logged;
@end

@implementation DHEVPCapture
@end

static NSMutableDictionary<NSValue *, DHEVPCapture *> *gEVPCaptures;
static pthread_mutex_t gEVPLock = PTHREAD_MUTEX_INITIALIZER;
static __thread int gEVPLogGuard;
static const NSUInteger kDHEVPCaptureLimit = 1024 * 1024;
typedef int (*DHEVPSizeFn)(DH_EVP_CIPHER_CTX *);
static DHEVPSizeFn gEVPKeyLength;
static DHEVPSizeFn gEVPIVLength;

static void DHEVPResolveSizes(void) {
    if (!gEVPKeyLength) {
        gEVPKeyLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_key_length");
        gEVPIVLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_iv_length");
    }
}

static NSValue *DHEVPPointerKey(const void *pointer) {
    return [NSValue valueWithPointer:pointer];
}

static void DHEVPAppend(NSMutableData *data, const void *bytes, size_t length) {
    if (!data || !bytes || !length || data.length >= kDHEVPCaptureLimit) return;
    NSUInteger remaining = kDHEVPCaptureLimit - data.length;
    [data appendBytes:bytes length:MIN(remaining, (NSUInteger)length)];
}

static void DHEVPStore(DH_EVP_CIPHER_CTX *context,
                       NSInteger direction,
                       const DH_EVP_CIPHER *cipher,
                       const unsigned char *key,
                       const unsigned char *iv) {
    if (!context || ![DHConfig shared].cryptoEnabled) return;
    DHEVPCapture *capture = [DHEVPCapture new];
    capture.direction = direction;
    capture.cipher = cipher;
    DHEVPResolveSizes();
    int keyLength = gEVPKeyLength ? gEVPKeyLength(context) : 0;
    int ivLength = gEVPIVLength ? gEVPIVLength(context) : 0;
    if (key && keyLength > 0 && keyLength <= 4096) {
        capture.key = [NSData dataWithBytes:key length:(NSUInteger)keyLength];
    } else {
        capture.key = NSData.data;
    }
    if (iv && ivLength > 0 && ivLength <= 4096) {
        capture.iv = [NSData dataWithBytes:iv length:(NSUInteger)ivLength];
    } else {
        capture.iv = NSData.data;
    }
    capture.input = [NSMutableData data];
    capture.output = [NSMutableData data];
    pthread_mutex_lock(&gEVPLock);
    if (!gEVPCaptures) gEVPCaptures = [NSMutableDictionary dictionary];
    gEVPCaptures[DHEVPPointerKey(context)] = capture;
    pthread_mutex_unlock(&gEVPLock);
}

static DHEVPCapture *DHEVPRemove(DH_EVP_CIPHER_CTX *context) {
    if (!context) return nil;
    pthread_mutex_lock(&gEVPLock);
    NSValue *key = DHEVPPointerKey(context);
    DHEVPCapture *capture = gEVPCaptures[key];
    [gEVPCaptures removeObjectForKey:key];
    pthread_mutex_unlock(&gEVPLock);
    return capture;
}

static void DHEVPLog(DHEVPCapture *capture, NSString *phase, int status) {
    if (!capture || gEVPLogGuard || ![DHConfig shared].cryptoEnabled) return;
    gEVPLogGuard++;
    @autoreleasepool {
        DHLogEntry *entry = [DHLogEntry entryWithCategory:@"EVP"
                                                algorithm:@"EVP_CIPHER"
                                                operation:capture.direction == 1 ? @"encrypt" : @"decrypt"];
        entry.input = capture.input.length ? [capture.input copy] : nil;
        entry.output = capture.output.length ? [capture.output copy] : nil;
        NSDictionary *metadata = @{
            @"phase": phase ?: @"unknown",
            @"status": @(status),
            @"cipher": [NSString stringWithFormat:@"%p", capture.cipher],
            @"keyBase64": [capture.key base64EncodedStringWithOptions:0],
            @"keyLength": @(capture.key.length),
            @"ivBase64": [capture.iv base64EncodedStringWithOptions:0],
            @"capturedInputLength": @(capture.input.length),
            @"capturedOutputLength": @(capture.output.length)
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
        entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gEVPLogGuard--;
}

static int DHEVPEncryptInit(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                            DH_EVP_ENGINE *engine, const unsigned char *key, const unsigned char *iv) {
    int status = gOriginalEVPEncryptInitEx ?
        gOriginalEVPEncryptInitEx(context, cipher, engine, key, iv) : 0;
    if (status) DHEVPStore(context, 1, cipher, key, iv);
    return status;
}

static int DHEVPDecryptInit(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                            DH_EVP_ENGINE *engine, const unsigned char *key, const unsigned char *iv) {
    int status = gOriginalEVPDecryptInitEx ?
        gOriginalEVPDecryptInitEx(context, cipher, engine, key, iv) : 0;
    if (status) DHEVPStore(context, 0, cipher, key, iv);
    return status;
}

static int DHEVPCipherInit(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                           DH_EVP_ENGINE *engine, const unsigned char *key,
                           const unsigned char *iv, int direction) {
    int status = gOriginalEVPCipherInitEx ?
        gOriginalEVPCipherInitEx(context, cipher, engine, key, iv, direction) : 0;
    if (status) DHEVPStore(context, direction > 0 ? 1 : 0, cipher, key, iv);
    return status;
}

static int DHEVPUpdate(DHEVPUpdateFn original, DH_EVP_CIPHER_CTX *context,
                       unsigned char *output, int *outputLength,
                       const unsigned char *input, int inputLength) {
    int status = original ? original(context, output, outputLength, input, inputLength) : 0;
    pthread_mutex_lock(&gEVPLock);
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (status && capture) {
        DHEVPAppend(capture.input, input, inputLength > 0 ? (size_t)inputLength : 0);
        DHEVPAppend(capture.output, output, outputLength && *outputLength > 0 ? (size_t)*outputLength : 0);
    }
    pthread_mutex_unlock(&gEVPLock);
    return status;
}

static int DHEVPEncryptUpdate(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol, const unsigned char *i, int il) {
    return DHEVPUpdate(gOriginalEVPEncryptUpdate, c, o, ol, i, il);
}
static int DHEVPDecryptUpdate(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol, const unsigned char *i, int il) {
    return DHEVPUpdate(gOriginalEVPDecryptUpdate, c, o, ol, i, il);
}
static int DHEVPCipherUpdate(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol, const unsigned char *i, int il) {
    return DHEVPUpdate(gOriginalEVPCipherUpdate, c, o, ol, i, il);
}

static int DHEVPFinal(DHEVPFinalFn original, DH_EVP_CIPHER_CTX *context,
                      unsigned char *output, int *outputLength) {
    int status = original ? original(context, output, outputLength) : 0;
    pthread_mutex_lock(&gEVPLock);
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (status && capture) {
        DHEVPAppend(capture.output, output, outputLength && *outputLength > 0 ? (size_t)*outputLength : 0);
        capture.logged = YES;
    }
    pthread_mutex_unlock(&gEVPLock);
    if (capture) DHEVPLog(capture, @"final", status);
    return status;
}

static int DHEVPEncryptFinal(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol) {
    return DHEVPFinal(gOriginalEVPEncryptFinalEx, c, o, ol);
}
static int DHEVPDecryptFinal(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol) {
    return DHEVPFinal(gOriginalEVPDecryptFinalEx, c, o, ol);
}
static int DHEVPCipherFinal(DH_EVP_CIPHER_CTX *c, unsigned char *o, int *ol) {
    return DHEVPFinal(gOriginalEVPCipherFinalEx, c, o, ol);
}

static int DHEVPCtxReset(DH_EVP_CIPHER_CTX *context) {
    int status = gOriginalEVPCtxReset ? gOriginalEVPCtxReset(context) : 0;
    pthread_mutex_lock(&gEVPLock);
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    [capture.input setLength:0];
    [capture.output setLength:0];
    capture.logged = NO;
    pthread_mutex_unlock(&gEVPLock);
    return status;
}

static void DHEVPCtxFree(DH_EVP_CIPHER_CTX *context) {
    if (gOriginalEVPCtxFree) gOriginalEVPCtxFree(context);
    DHEVPRemove(context);
}

static int DHEVPCtxCtrl(DH_EVP_CIPHER_CTX *context, int type, int argument, void *pointer) {
    int status = gOriginalEVPCtxCtrl ? gOriginalEVPCtxCtrl(context, type, argument, pointer) : 0;
    return status;
}

void DHInstallEVPHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gEVPCaptures = [NSMutableDictionary dictionary];
        struct rebinding bindings[] = {
            {"EVP_EncryptInit_ex", (void *)DHEVPEncryptInit, (void **)&gOriginalEVPEncryptInitEx},
            {"EVP_DecryptInit_ex", (void *)DHEVPDecryptInit, (void **)&gOriginalEVPDecryptInitEx},
            {"EVP_CipherInit_ex", (void *)DHEVPCipherInit, (void **)&gOriginalEVPCipherInitEx},
            {"EVP_EncryptUpdate", (void *)DHEVPEncryptUpdate, (void **)&gOriginalEVPEncryptUpdate},
            {"EVP_DecryptUpdate", (void *)DHEVPDecryptUpdate, (void **)&gOriginalEVPDecryptUpdate},
            {"EVP_CipherUpdate", (void *)DHEVPCipherUpdate, (void **)&gOriginalEVPCipherUpdate},
            {"EVP_EncryptFinal_ex", (void *)DHEVPEncryptFinal, (void **)&gOriginalEVPEncryptFinalEx},
            {"EVP_DecryptFinal_ex", (void *)DHEVPDecryptFinal, (void **)&gOriginalEVPDecryptFinalEx},
            {"EVP_CipherFinal_ex", (void *)DHEVPCipherFinal, (void **)&gOriginalEVPCipherFinalEx},
            {"EVP_CIPHER_CTX_reset", (void *)DHEVPCtxReset, (void **)&gOriginalEVPCtxReset},
            {"EVP_CIPHER_CTX_free", (void *)DHEVPCtxFree, (void **)&gOriginalEVPCtxFree},
            {"EVP_CIPHER_CTX_ctrl", (void *)DHEVPCtxCtrl, (void **)&gOriginalEVPCtxCtrl}
        };
        rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
    });
}
