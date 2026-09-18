#import "DHEVP.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#include <pthread.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>

typedef struct evp_cipher_ctx_st DH_EVP_CIPHER_CTX;
typedef struct evp_cipher_st DH_EVP_CIPHER;
typedef struct engine_st DH_EVP_ENGINE;
typedef struct {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} DH_OSSL_PARAM;

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
typedef int (*DHEVPInitEx2Fn)(DH_EVP_CIPHER_CTX *, const DH_EVP_CIPHER *,
                              const unsigned char *, const unsigned char *, const DH_OSSL_PARAM *);
typedef int (*DHEVPCipherInitEx2Fn)(DH_EVP_CIPHER_CTX *, const DH_EVP_CIPHER *,
                                    const unsigned char *, const unsigned char *, int,
                                    const DH_OSSL_PARAM *);
typedef int (*DHEVPGetParamsFn)(DH_EVP_CIPHER_CTX *, DH_OSSL_PARAM *);
typedef int (*DHEVPSetParamsFn)(DH_EVP_CIPHER_CTX *, const DH_OSSL_PARAM *);
typedef int (*DHEVPGetTagFn)(DH_EVP_CIPHER_CTX *, void *, size_t);
typedef int (*DHEVPSetTagFn)(DH_EVP_CIPHER_CTX *, const void *, size_t);

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
static DHEVPInitEx2Fn gOriginalEVPEncryptInitEx2;
static DHEVPInitEx2Fn gOriginalEVPDecryptInitEx2;
static DHEVPCipherInitEx2Fn gOriginalEVPCipherInitEx2;
static DHEVPGetParamsFn gOriginalEVPCtxGetParams;
static DHEVPSetParamsFn gOriginalEVPCtxSetParams;
static DHEVPGetTagFn gOriginalEVPCtxGetTag;
static DHEVPSetTagFn gOriginalEVPCtxSetTag;

@interface DHEVPCapture : NSObject
@property (nonatomic) NSInteger direction;
@property (nonatomic) const void *cipher;
@property (nonatomic, copy) NSString *cipherName;
@property (nonatomic, copy) NSData *key;
@property (nonatomic, copy) NSData *iv;
@property (nonatomic, strong) NSMutableData *aad;
@property (nonatomic, copy) NSData *tag;
@property (nonatomic, copy) NSString *tagSource;
@property (nonatomic, strong) NSMutableData *input;
@property (nonatomic, strong) NSMutableData *output;
@property (nonatomic) BOOL paramsSeen;
@property (nonatomic) BOOL finalized;
@property (nonatomic) NSUInteger requestedIVLength;
@property (nonatomic) BOOL logged;
@end

@implementation DHEVPCapture
@end

static NSMutableDictionary<NSValue *, DHEVPCapture *> *gEVPCaptures;
static pthread_mutex_t gEVPLock = PTHREAD_MUTEX_INITIALIZER;
static __thread int gEVPLogGuard;
static const NSUInteger kDHEVPCaptureLimit = 4 * 1024 * 1024;
typedef int (*DHEVPSizeFn)(DH_EVP_CIPHER_CTX *);
static DHEVPSizeFn gEVPKeyLength;
static DHEVPSizeFn gEVPIVLength;
typedef const DH_EVP_CIPHER *(*DHEVPGetCipherFn)(DH_EVP_CIPHER_CTX *);
typedef const char *(*DHEVPCipherNameFn)(const DH_EVP_CIPHER *);
static DHEVPGetCipherFn gEVPGetCipher;
static DHEVPCipherNameFn gEVPCipherName;

static void DHEVPResolveSizes(void) {
    if (!gEVPKeyLength) {
        gEVPKeyLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_get_key_length");
        if (!gEVPKeyLength) gEVPKeyLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_key_length");
        gEVPIVLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_get_iv_length");
        if (!gEVPIVLength) gEVPIVLength = (DHEVPSizeFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_iv_length");
        gEVPGetCipher = (DHEVPGetCipherFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_get0_cipher");
        if (!gEVPGetCipher) gEVPGetCipher = (DHEVPGetCipherFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_CTX_cipher");
        gEVPCipherName = (DHEVPCipherNameFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_get0_name");
        if (!gEVPCipherName) gEVPCipherName = (DHEVPCipherNameFn)dlsym(RTLD_DEFAULT, "EVP_CIPHER_name");
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

static void DHEVPLog(DHEVPCapture *capture, NSString *phase, int status);

static void DHEVPStore(DH_EVP_CIPHER_CTX *context,
                       NSInteger direction,
                       const DH_EVP_CIPHER *cipher,
                       const unsigned char *key,
                       const unsigned char *iv,
                       BOOL paramsSeen) {
    if (!context || ![DHConfig shared].cryptoEnabled) return;
    DHEVPResolveSizes();
    const DH_EVP_CIPHER *resolvedCipher = cipher ?: (gEVPGetCipher ? gEVPGetCipher(context) : NULL);
    const char *resolvedName = resolvedCipher && gEVPCipherName ? gEVPCipherName(resolvedCipher) : NULL;
    NSString *cipherName = resolvedName ? [NSString stringWithUTF8String:resolvedName] : nil;
    int keyLength = gEVPKeyLength ? gEVPKeyLength(context) : 0;
    int ivLength = gEVPIVLength ? gEVPIVLength(context) : 0;
    NSData *keyData = key && keyLength > 0 && keyLength <= 4096 ?
        [NSData dataWithBytes:key length:(NSUInteger)keyLength] : nil;
    NSData *ivData = iv && ivLength > 0 && ivLength <= 4096 ?
        [NSData dataWithBytes:iv length:(NSUInteger)ivLength] : nil;
    pthread_mutex_lock(&gEVPLock);
    if (!gEVPCaptures) gEVPCaptures = [NSMutableDictionary dictionary];
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (!capture) {
        capture = [DHEVPCapture new];
        capture.direction = direction >= 0 ? direction : 0;
        capture.key = NSData.data;
        capture.iv = NSData.data;
        capture.aad = [NSMutableData data];
        capture.tag = NSData.data;
        capture.tagSource = @"";
        capture.input = [NSMutableData data];
        capture.output = [NSMutableData data];
    }
    if (cipher) {
        [capture.input setLength:0];
        [capture.output setLength:0];
        [capture.aad setLength:0];
        capture.tag = NSData.data;
        capture.tagSource = @"";
        capture.logged = NO;
        capture.finalized = NO;
        capture.paramsSeen = NO;
        capture.requestedIVLength = 0;
    }
    if (direction >= 0) capture.direction = direction;
    if (resolvedCipher) capture.cipher = resolvedCipher;
    if (cipherName.length) capture.cipherName = cipherName;
    if (keyData) capture.key = keyData;
    if (ivData) capture.iv = ivData;
    capture.paramsSeen = capture.paramsSeen || paramsSeen;
    if (ivLength > 0) capture.requestedIVLength = (NSUInteger)ivLength;
    gEVPCaptures[DHEVPPointerKey(context)] = capture;
    pthread_mutex_unlock(&gEVPLock);
}

static BOOL DHEVPParameterKey(const char *key, const char *expected) {
    return key && expected && strcasecmp(key, expected) == 0;
}

static void DHEVPCaptureParams(DH_EVP_CIPHER_CTX *context, const DH_OSSL_PARAM *params,
                               BOOL outputParams, NSString *source) {
    if (!context || !params) return;
    BOOL capturedTag = NO;
    BOOL shouldLog = NO;
    pthread_mutex_lock(&gEVPLock);
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (capture) {
        capture.paramsSeen = YES;
        for (NSUInteger index = 0; index < 64 && params[index].key; index++) {
            const DH_OSSL_PARAM *parameter = &params[index];
            size_t length = parameter->data_size;
            if (outputParams && parameter->return_size != SIZE_MAX && parameter->return_size <= length) {
                length = parameter->return_size;
            }
            if (!parameter->data || !length || length > 4096) continue;
            if (DHEVPParameterKey(parameter->key, "tag")) {
                capture.tag = [NSData dataWithBytes:parameter->data length:length];
                capture.tagSource = source ?: (outputParams ? @"get_params" : @"set_params");
                capturedTag = YES;
            } else if (DHEVPParameterKey(parameter->key, "aad") ||
                       DHEVPParameterKey(parameter->key, "tlsaad")) {
                DHEVPAppend(capture.aad, parameter->data, length);
            }
        }
        shouldLog = capturedTag && capture.finalized;
    }
    pthread_mutex_unlock(&gEVPLock);
    if (shouldLog) DHEVPLog(capture, @"tag", 1);
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
                                                algorithm:capture.cipherName.length ? capture.cipherName : @"EVP_CIPHER"
                                                operation:capture.direction == 1 ? @"encrypt" : @"decrypt"];
        entry.input = capture.input.length ? [capture.input copy] : nil;
        entry.output = capture.output.length ? [capture.output copy] : nil;
        NSDictionary *metadata = @{
            @"phase": phase ?: @"unknown",
            @"status": @(status),
            @"cipher": [NSString stringWithFormat:@"%p", capture.cipher],
            @"cipherName": capture.cipherName ?: @"",
            @"keyBase64": [capture.key base64EncodedStringWithOptions:0],
            @"keyLength": @(capture.key.length),
            @"ivBase64": [capture.iv base64EncodedStringWithOptions:0],
            @"ivLength": @(capture.iv.length ?: capture.requestedIVLength),
            @"aadBase64": [capture.aad base64EncodedStringWithOptions:0],
            @"aadLength": @(capture.aad.length),
            @"tagBase64": [capture.tag base64EncodedStringWithOptions:0],
            @"tagLength": @(capture.tag.length),
            @"tagSource": capture.tagSource ?: @"",
            @"paramsSeen": @(capture.paramsSeen),
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
    if (status) DHEVPStore(context, 1, cipher, key, iv, NO);
    return status;
}

static int DHEVPDecryptInit(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                            DH_EVP_ENGINE *engine, const unsigned char *key, const unsigned char *iv) {
    int status = gOriginalEVPDecryptInitEx ?
        gOriginalEVPDecryptInitEx(context, cipher, engine, key, iv) : 0;
    if (status) DHEVPStore(context, 0, cipher, key, iv, NO);
    return status;
}

static int DHEVPCipherInit(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                           DH_EVP_ENGINE *engine, const unsigned char *key,
                           const unsigned char *iv, int direction) {
    int status = gOriginalEVPCipherInitEx ?
        gOriginalEVPCipherInitEx(context, cipher, engine, key, iv, direction) : 0;
    if (status) DHEVPStore(context, direction < 0 ? -1 : (direction > 0 ? 1 : 0), cipher, key, iv, NO);
    return status;
}

static int DHEVPEncryptInitEx2(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                               const unsigned char *key, const unsigned char *iv,
                               const DH_OSSL_PARAM *params) {
    int status = gOriginalEVPEncryptInitEx2 ? gOriginalEVPEncryptInitEx2(context, cipher, key, iv, params) : 0;
    if (status) {
        DHEVPStore(context, 1, cipher, key, iv, params != NULL);
        DHEVPCaptureParams(context, params, NO, @"init_ex2");
    }
    return status;
}

static int DHEVPDecryptInitEx2(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                               const unsigned char *key, const unsigned char *iv,
                               const DH_OSSL_PARAM *params) {
    int status = gOriginalEVPDecryptInitEx2 ? gOriginalEVPDecryptInitEx2(context, cipher, key, iv, params) : 0;
    if (status) {
        DHEVPStore(context, 0, cipher, key, iv, params != NULL);
        DHEVPCaptureParams(context, params, NO, @"init_ex2");
    }
    return status;
}

static int DHEVPCipherInitEx2(DH_EVP_CIPHER_CTX *context, const DH_EVP_CIPHER *cipher,
                              const unsigned char *key, const unsigned char *iv, int direction,
                              const DH_OSSL_PARAM *params) {
    int status = gOriginalEVPCipherInitEx2 ?
        gOriginalEVPCipherInitEx2(context, cipher, key, iv, direction, params) : 0;
    if (status) {
        DHEVPStore(context, direction < 0 ? -1 : (direction > 0 ? 1 : 0), cipher, key, iv, params != NULL);
        DHEVPCaptureParams(context, params, NO, @"init_ex2");
    }
    return status;
}

static int DHEVPUpdate(DHEVPUpdateFn original, DH_EVP_CIPHER_CTX *context,
                       unsigned char *output, int *outputLength,
                       const unsigned char *input, int inputLength) {
    int status = original ? original(context, output, outputLength, input, inputLength) : 0;
    pthread_mutex_lock(&gEVPLock);
    DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (status && capture) {
        if (!output && input && inputLength > 0) {
            DHEVPAppend(capture.aad, input, (size_t)inputLength);
        } else {
            DHEVPAppend(capture.input, input, inputLength > 0 ? (size_t)inputLength : 0);
            DHEVPAppend(capture.output, output, outputLength && *outputLength > 0 ? (size_t)*outputLength : 0);
        }
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
        capture.finalized = YES;
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
    DHEVPCapture *capture = DHEVPRemove(context);
    if (capture && !capture.logged && (capture.input.length || capture.output.length || capture.aad.length)) {
        DHEVPLog(capture, @"reset", status);
    }
    return status;
}

static void DHEVPCtxFree(DH_EVP_CIPHER_CTX *context) {
    DHEVPCapture *capture = DHEVPRemove(context);
    if (capture && !capture.logged && (capture.input.length || capture.output.length || capture.aad.length)) {
        DHEVPLog(capture, @"free", 1);
    }
    if (gOriginalEVPCtxFree) gOriginalEVPCtxFree(context);
}

static int DHEVPCtxCtrl(DH_EVP_CIPHER_CTX *context, int type, int argument, void *pointer) {
    int status = gOriginalEVPCtxCtrl ? gOriginalEVPCtxCtrl(context, type, argument, pointer) : 0;
    enum {
        DHEVP_CTRL_AEAD_SET_IVLEN = 0x9,
        DHEVP_CTRL_AEAD_GET_TAG = 0x10,
        DHEVP_CTRL_AEAD_SET_TAG = 0x11,
        DHEVP_CTRL_AEAD_TLS1_AAD = 0x16
    };
    BOOL shouldLog = NO;
    DHEVPCapture *capture = nil;
    pthread_mutex_lock(&gEVPLock);
    capture = gEVPCaptures[DHEVPPointerKey(context)];
    if (capture && status > 0) {
        if (type == DHEVP_CTRL_AEAD_SET_IVLEN && argument > 0) {
            capture.requestedIVLength = (NSUInteger)argument;
        } else if ((type == DHEVP_CTRL_AEAD_GET_TAG || type == DHEVP_CTRL_AEAD_SET_TAG) &&
                   pointer && argument > 0 && argument <= 4096) {
            capture.tag = [NSData dataWithBytes:pointer length:(NSUInteger)argument];
            capture.tagSource = type == DHEVP_CTRL_AEAD_GET_TAG ? @"ctrl_get_tag" : @"ctrl_set_tag";
            shouldLog = type == DHEVP_CTRL_AEAD_GET_TAG && capture.finalized;
        } else if (type == DHEVP_CTRL_AEAD_TLS1_AAD && pointer && argument > 0) {
            DHEVPAppend(capture.aad, pointer, (size_t)argument);
        }
    }
    pthread_mutex_unlock(&gEVPLock);
    if (shouldLog) DHEVPLog(capture, @"tag", status);
    return status;
}

static int DHEVPCtxGetParams(DH_EVP_CIPHER_CTX *context, DH_OSSL_PARAM *params) {
    int status = gOriginalEVPCtxGetParams ? gOriginalEVPCtxGetParams(context, params) : 0;
    if (status) DHEVPCaptureParams(context, params, YES, @"get_params");
    return status;
}

static int DHEVPCtxSetParams(DH_EVP_CIPHER_CTX *context, const DH_OSSL_PARAM *params) {
    int status = gOriginalEVPCtxSetParams ? gOriginalEVPCtxSetParams(context, params) : 0;
    if (status) DHEVPCaptureParams(context, params, NO, @"set_params");
    return status;
}

static int DHEVPCtxGetTag(DH_EVP_CIPHER_CTX *context, void *tag, size_t length) {
    int status = gOriginalEVPCtxGetTag ? gOriginalEVPCtxGetTag(context, tag, length) : 0;
    BOOL shouldLog = NO;
    DHEVPCapture *capture = nil;
    if (status && tag && length && length <= 4096) {
        pthread_mutex_lock(&gEVPLock);
        capture = gEVPCaptures[DHEVPPointerKey(context)];
        capture.tag = [NSData dataWithBytes:tag length:length];
        capture.tagSource = @"get_tag";
        shouldLog = capture.finalized;
        pthread_mutex_unlock(&gEVPLock);
    }
    if (shouldLog) DHEVPLog(capture, @"tag", status);
    return status;
}

static int DHEVPCtxSetTag(DH_EVP_CIPHER_CTX *context, const void *tag, size_t length) {
    int status = gOriginalEVPCtxSetTag ? gOriginalEVPCtxSetTag(context, tag, length) : 0;
    if (status && tag && length && length <= 4096) {
        pthread_mutex_lock(&gEVPLock);
        DHEVPCapture *capture = gEVPCaptures[DHEVPPointerKey(context)];
        capture.tag = [NSData dataWithBytes:tag length:length];
        capture.tagSource = @"set_tag";
        pthread_mutex_unlock(&gEVPLock);
    }
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
            {"EVP_EncryptInit_ex2", (void *)DHEVPEncryptInitEx2, (void **)&gOriginalEVPEncryptInitEx2},
            {"EVP_DecryptInit_ex2", (void *)DHEVPDecryptInitEx2, (void **)&gOriginalEVPDecryptInitEx2},
            {"EVP_CipherInit_ex2", (void *)DHEVPCipherInitEx2, (void **)&gOriginalEVPCipherInitEx2},
            {"EVP_EncryptUpdate", (void *)DHEVPEncryptUpdate, (void **)&gOriginalEVPEncryptUpdate},
            {"EVP_DecryptUpdate", (void *)DHEVPDecryptUpdate, (void **)&gOriginalEVPDecryptUpdate},
            {"EVP_CipherUpdate", (void *)DHEVPCipherUpdate, (void **)&gOriginalEVPCipherUpdate},
            {"EVP_EncryptFinal_ex", (void *)DHEVPEncryptFinal, (void **)&gOriginalEVPEncryptFinalEx},
            {"EVP_DecryptFinal_ex", (void *)DHEVPDecryptFinal, (void **)&gOriginalEVPDecryptFinalEx},
            {"EVP_CipherFinal_ex", (void *)DHEVPCipherFinal, (void **)&gOriginalEVPCipherFinalEx},
            {"EVP_CIPHER_CTX_reset", (void *)DHEVPCtxReset, (void **)&gOriginalEVPCtxReset},
            {"EVP_CIPHER_CTX_free", (void *)DHEVPCtxFree, (void **)&gOriginalEVPCtxFree},
            {"EVP_CIPHER_CTX_ctrl", (void *)DHEVPCtxCtrl, (void **)&gOriginalEVPCtxCtrl},
            {"EVP_CIPHER_CTX_get_params", (void *)DHEVPCtxGetParams, (void **)&gOriginalEVPCtxGetParams},
            {"EVP_CIPHER_CTX_set_params", (void *)DHEVPCtxSetParams, (void **)&gOriginalEVPCtxSetParams},
            {"EVP_CIPHER_CTX_get_tag", (void *)DHEVPCtxGetTag, (void **)&gOriginalEVPCtxGetTag},
            {"EVP_CIPHER_CTX_set_tag", (void *)DHEVPCtxSetTag, (void **)&gOriginalEVPCtxSetTag}
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
