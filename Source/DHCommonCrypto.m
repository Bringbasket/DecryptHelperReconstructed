#import "DHCommonCrypto.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "fishhook.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <pthread.h>

static __thread int gCryptoLogGuard;

static NSString *DHBase64(const void *bytes, size_t length) {
    if (!bytes || !length) return @"";
    NSData *data = [NSData dataWithBytes:bytes length:length];
    return [data base64EncodedStringWithOptions:0];
}

static NSString *DHMetadataString(NSDictionary *metadata) {
    if (![NSJSONSerialization isValidJSONObject:metadata]) return nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
}

static void DHLogCrypto(NSString *category,
                        NSString *algorithm,
                        NSString *operation,
                        const void *inputBytes,
                        size_t inputLength,
                        const void *outputBytes,
                        size_t outputLength,
                        NSDictionary *metadata) {
    if (gCryptoLogGuard || ![DHConfig shared].cryptoEnabled) return;
    gCryptoLogGuard++;
    @autoreleasepool {
        DHLogEntry *entry = [DHLogEntry entryWithCategory:category
                                                algorithm:algorithm
                                                operation:operation];
        if (inputBytes && inputLength) entry.input = [NSData dataWithBytes:inputBytes length:inputLength];
        if (outputBytes && outputLength) entry.output = [NSData dataWithBytes:outputBytes length:outputLength];
        entry.detail = DHMetadataString(metadata ?: @{});
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gCryptoLogGuard--;
}

typedef unsigned char *(*DHDigestFn)(const void *, CC_LONG, unsigned char *);

#define DH_DEFINE_DIGEST_HOOK(symbol, displayName, digestLength) \
    static DHDigestFn gOriginal##symbol; \
    static unsigned char *DHHooked##symbol(const void *data, CC_LONG length, unsigned char *digest) { \
        unsigned char *result = gOriginal##symbol ? gOriginal##symbol(data, length, digest) : NULL; \
        if (result) DHLogCrypto(@"DIGEST", displayName, @"one-shot", data, (size_t)length, \
                                result, digestLength, nil); \
        return result; \
    }

DH_DEFINE_DIGEST_HOOK(CC_MD2, @"MD2", CC_MD2_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_MD4, @"MD4", CC_MD4_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_MD5, @"MD5", CC_MD5_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_SHA1, @"SHA1", CC_SHA1_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_SHA224, @"SHA224", CC_SHA224_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_SHA256, @"SHA256", CC_SHA256_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_SHA384, @"SHA384", CC_SHA384_DIGEST_LENGTH)
DH_DEFINE_DIGEST_HOOK(CC_SHA512, @"SHA512", CC_SHA512_DIGEST_LENGTH)

typedef int (*DHDigestInitFn)(void *);
typedef int (*DHDigestUpdateFn)(void *, const void *, CC_LONG);
typedef int (*DHDigestFinalFn)(unsigned char *, void *);

@interface DHDigestCapture : NSObject
@property (nonatomic, copy) NSString *algorithm;
@property (nonatomic) NSUInteger digestLength;
@property (nonatomic, strong) NSMutableData *input;
@end

@implementation DHDigestCapture
@end

static pthread_mutex_t gDigestLock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableDictionary<NSValue *, DHDigestCapture *> *gDigestCaptures;

static void DHStoreDigest(void *context, NSString *algorithm, NSUInteger digestLength) {
    if (!context || ![DHConfig shared].cryptoEnabled) return;
    DHDigestCapture *capture = [DHDigestCapture new];
    capture.algorithm = algorithm;
    capture.digestLength = digestLength;
    capture.input = [NSMutableData data];
    pthread_mutex_lock(&gDigestLock);
    gDigestCaptures[[NSValue valueWithPointer:context]] = capture;
    pthread_mutex_unlock(&gDigestLock);
}

static void DHUpdateDigest(void *context, const void *data, size_t length) {
    if (!context || !data || !length || ![DHConfig shared].cryptoEnabled) return;
    pthread_mutex_lock(&gDigestLock);
    DHDigestCapture *capture = gDigestCaptures[[NSValue valueWithPointer:context]];
    if (capture.input.length < 1024 * 1024) {
        NSUInteger available = 1024 * 1024 - capture.input.length;
        [capture.input appendBytes:data length:MIN((NSUInteger)length, available)];
    }
    pthread_mutex_unlock(&gDigestLock);
}

static DHDigestCapture *DHTakeDigest(void *context) {
    if (!context) return nil;
    pthread_mutex_lock(&gDigestLock);
    NSValue *key = [NSValue valueWithPointer:context];
    DHDigestCapture *capture = gDigestCaptures[key];
    [gDigestCaptures removeObjectForKey:key];
    pthread_mutex_unlock(&gDigestLock);
    return capture;
}

#define DH_DEFINE_STREAM_DIGEST_HOOK(symbol, displayName, outputLength) \
    static DHDigestInitFn gOriginal##symbol##_Init; \
    static DHDigestUpdateFn gOriginal##symbol##_Update; \
    static DHDigestFinalFn gOriginal##symbol##_Final; \
    static int DHHooked##symbol##_Init(void *context) { \
        int status = gOriginal##symbol##_Init ? gOriginal##symbol##_Init(context) : 0; \
        if (status) DHStoreDigest(context, displayName, outputLength); \
        return status; \
    } \
    static int DHHooked##symbol##_Update(void *context, const void *data, CC_LONG length) { \
        int status = gOriginal##symbol##_Update ? gOriginal##symbol##_Update(context, data, length) : 0; \
        if (status) DHUpdateDigest(context, data, (size_t)length); \
        return status; \
    } \
    static int DHHooked##symbol##_Final(unsigned char *digest, void *context) { \
        int status = gOriginal##symbol##_Final ? gOriginal##symbol##_Final(digest, context) : 0; \
        DHDigestCapture *capture = DHTakeDigest(context); \
        if (status && capture && digest) { \
            DHLogCrypto(@"DIGEST", capture.algorithm, @"stream", capture.input.bytes, \
                        capture.input.length, digest, capture.digestLength, \
                        @{ @"capturedInputLength": @(capture.input.length) }); \
        } \
        return status; \
    }

DH_DEFINE_STREAM_DIGEST_HOOK(CC_MD2, @"MD2", CC_MD2_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_MD4, @"MD4", CC_MD4_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_MD5, @"MD5", CC_MD5_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_SHA1, @"SHA1", CC_SHA1_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_SHA224, @"SHA224", CC_SHA224_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_SHA256, @"SHA256", CC_SHA256_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_SHA384, @"SHA384", CC_SHA384_DIGEST_LENGTH)
DH_DEFINE_STREAM_DIGEST_HOOK(CC_SHA512, @"SHA512", CC_SHA512_DIGEST_LENGTH)

#define DH_STREAM_DIGEST_BINDINGS(symbol) \
    {#symbol "_Init", (void *)DHHooked##symbol##_Init, (void **)&gOriginal##symbol##_Init}, \
    {#symbol "_Update", (void *)DHHooked##symbol##_Update, (void **)&gOriginal##symbol##_Update}, \
    {#symbol "_Final", (void *)DHHooked##symbol##_Final, (void **)&gOriginal##symbol##_Final}

typedef void (*DHCCHmacFn)(CCHmacAlgorithm, const void *, size_t, const void *, size_t, void *);
typedef void (*DHCCHmacInitFn)(CCHmacContext *, CCHmacAlgorithm, const void *, size_t);
typedef void (*DHCCHmacUpdateFn)(CCHmacContext *, const void *, size_t);
typedef void (*DHCCHmacFinalFn)(CCHmacContext *, void *);
static DHCCHmacFn gOriginalCCHmac;
static DHCCHmacInitFn gOriginalCCHmacInit;
static DHCCHmacUpdateFn gOriginalCCHmacUpdate;
static DHCCHmacFinalFn gOriginalCCHmacFinal;
static size_t DHHmacLength(CCHmacAlgorithm algorithm);
static NSString *DHHmacName(CCHmacAlgorithm algorithm);

@interface DHHmacCapture : NSObject
@property (nonatomic) CCHmacAlgorithm algorithm;
@property (nonatomic, copy) NSData *key;
@property (nonatomic, strong) NSMutableData *input;
@end

@implementation DHHmacCapture
@end

static pthread_mutex_t gHmacLock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableDictionary<NSValue *, DHHmacCapture *> *gHmacCaptures;
static const NSUInteger kDHCaptureLimit = 1024 * 1024;

static void DHAppendLimited(NSMutableData *target, const void *bytes, size_t length) {
    if (!target || !bytes || !length || target.length >= kDHCaptureLimit) return;
    NSUInteger available = kDHCaptureLimit - target.length;
    [target appendBytes:bytes length:MIN((NSUInteger)length, available)];
}

static NSValue *DHPointerKey(const void *pointer) {
    return [NSValue valueWithPointer:pointer];
}

static void DHHookedCCHmacInit(CCHmacContext *context,
                               CCHmacAlgorithm algorithm,
                               const void *key,
                               size_t keyLength) {
    if (gOriginalCCHmacInit) gOriginalCCHmacInit(context, algorithm, key, keyLength);
    if (![DHConfig shared].cryptoEnabled || !context) return;
    DHHmacCapture *capture = [DHHmacCapture new];
    capture.algorithm = algorithm;
    capture.key = key && keyLength ? [NSData dataWithBytes:key length:keyLength] : NSData.data;
    capture.input = [NSMutableData data];
    pthread_mutex_lock(&gHmacLock);
    gHmacCaptures[DHPointerKey(context)] = capture;
    pthread_mutex_unlock(&gHmacLock);
}

static void DHHookedCCHmacUpdate(CCHmacContext *context, const void *data, size_t dataLength) {
    if (gOriginalCCHmacUpdate) gOriginalCCHmacUpdate(context, data, dataLength);
    if (![DHConfig shared].cryptoEnabled || !context || !dataLength) return;
    pthread_mutex_lock(&gHmacLock);
    DHHmacCapture *capture = gHmacCaptures[DHPointerKey(context)];
    DHAppendLimited(capture.input, data, dataLength);
    pthread_mutex_unlock(&gHmacLock);
}

static void DHHookedCCHmacFinal(CCHmacContext *context, void *macOut) {
    if (gOriginalCCHmacFinal) gOriginalCCHmacFinal(context, macOut);
    if (!context) return;
    pthread_mutex_lock(&gHmacLock);
    DHHmacCapture *capture = gHmacCaptures[DHPointerKey(context)];
    [gHmacCaptures removeObjectForKey:DHPointerKey(context)];
    pthread_mutex_unlock(&gHmacLock);
    size_t outputLength = capture ? DHHmacLength(capture.algorithm) : 0;
    if (capture && macOut && outputLength) {
        DHLogCrypto(@"HMAC", DHHmacName(capture.algorithm), @"stream",
                    capture.input.bytes, capture.input.length, macOut, outputLength,
                    @{
                        @"keyBase64": [capture.key base64EncodedStringWithOptions:0],
                        @"keyLength": @(capture.key.length),
                        @"capturedInputLength": @(capture.input.length)
                    });
    }
}

static size_t DHHmacLength(CCHmacAlgorithm algorithm) {
    switch (algorithm) {
        case kCCHmacAlgSHA1: return CC_SHA1_DIGEST_LENGTH;
        case kCCHmacAlgMD5: return CC_MD5_DIGEST_LENGTH;
        case kCCHmacAlgSHA224: return CC_SHA224_DIGEST_LENGTH;
        case kCCHmacAlgSHA256: return CC_SHA256_DIGEST_LENGTH;
        case kCCHmacAlgSHA384: return CC_SHA384_DIGEST_LENGTH;
        case kCCHmacAlgSHA512: return CC_SHA512_DIGEST_LENGTH;
    }
    return 0;
}

static NSString *DHHmacName(CCHmacAlgorithm algorithm) {
    switch (algorithm) {
        case kCCHmacAlgSHA1: return @"HMAC-SHA1";
        case kCCHmacAlgMD5: return @"HMAC-MD5";
        case kCCHmacAlgSHA224: return @"HMAC-SHA224";
        case kCCHmacAlgSHA256: return @"HMAC-SHA256";
        case kCCHmacAlgSHA384: return @"HMAC-SHA384";
        case kCCHmacAlgSHA512: return @"HMAC-SHA512";
    }
    return [NSString stringWithFormat:@"HMAC-%u", (unsigned)algorithm];
}

static void DHHookedCCHmac(CCHmacAlgorithm algorithm,
                           const void *key,
                           size_t keyLength,
                           const void *data,
                           size_t dataLength,
                           void *macOut) {
    if (gOriginalCCHmac) gOriginalCCHmac(algorithm, key, keyLength, data, dataLength, macOut);
    size_t outputLength = DHHmacLength(algorithm);
    if (macOut && outputLength) {
        DHLogCrypto(@"HMAC", DHHmacName(algorithm), @"one-shot",
                    data, dataLength, macOut, outputLength,
                    @{ @"keyBase64": DHBase64(key, keyLength), @"keyLength": @(keyLength) });
    }
}

typedef CCCryptorStatus (*DHCCCryptFn)(CCOperation, CCAlgorithm, CCOptions,
                                      const void *, size_t, const void *,
                                      const void *, size_t, void *, size_t, size_t *);
static DHCCCryptFn gOriginalCCCrypt;

typedef CCCryptorStatus (*DHCCCryptorCreateFn)(CCOperation, CCAlgorithm, CCOptions,
                                               const void *, size_t, const void *, CCCryptorRef *);
typedef CCCryptorStatus (*DHCCCryptorCreateWithModeFn)(CCOperation, CCMode, CCAlgorithm, CCPadding,
                                                       const void *, const void *, size_t,
                                                       const void *, size_t, int, CCModeOptions,
                                                       CCCryptorRef *);
typedef CCCryptorStatus (*DHCCCryptorUpdateFn)(CCCryptorRef, const void *, size_t,
                                               void *, size_t, size_t *);
typedef CCCryptorStatus (*DHCCCryptorFinalFn)(CCCryptorRef, void *, size_t, size_t *);
typedef CCCryptorStatus (*DHCCCryptorResetFn)(CCCryptorRef, const void *);
typedef CCCryptorStatus (*DHCCCryptorReleaseFn)(CCCryptorRef);

static DHCCCryptorCreateFn gOriginalCCCryptorCreate;
static DHCCCryptorCreateWithModeFn gOriginalCCCryptorCreateWithMode;
static DHCCCryptorUpdateFn gOriginalCCCryptorUpdate;
static DHCCCryptorFinalFn gOriginalCCCryptorFinal;
static DHCCCryptorResetFn gOriginalCCCryptorReset;
static DHCCCryptorReleaseFn gOriginalCCCryptorRelease;

@interface DHCryptorCapture : NSObject
@property (nonatomic) CCOperation operation;
@property (nonatomic) CCAlgorithm algorithm;
@property (nonatomic) NSUInteger options;
@property (nonatomic, copy) NSData *key;
@property (nonatomic, copy) NSData *iv;
@property (nonatomic, strong) NSMutableData *input;
@property (nonatomic, strong) NSMutableData *output;
@property (nonatomic) BOOL logged;
@end

@implementation DHCryptorCapture
@end

static pthread_mutex_t gCryptorLock = PTHREAD_MUTEX_INITIALIZER;
static NSMutableDictionary<NSValue *, DHCryptorCapture *> *gCryptorCaptures;

static NSString *DHCipherName(CCAlgorithm algorithm) {
    switch (algorithm) {
        case kCCAlgorithmAES: return @"AES";
        case kCCAlgorithmDES: return @"DES";
        case kCCAlgorithm3DES: return @"3DES";
        case kCCAlgorithmCAST: return @"CAST";
        case kCCAlgorithmRC4: return @"RC4";
        case kCCAlgorithmRC2: return @"RC2";
        case kCCAlgorithmBlowfish: return @"Blowfish";
    }
    return [NSString stringWithFormat:@"algorithm-%u", (unsigned)algorithm];
}

static size_t DHBlockSize(CCAlgorithm algorithm) {
    switch (algorithm) {
        case kCCAlgorithmAES: return kCCBlockSizeAES128;
        case kCCAlgorithmDES: return kCCBlockSizeDES;
        case kCCAlgorithm3DES: return kCCBlockSize3DES;
        case kCCAlgorithmCAST: return kCCBlockSizeCAST;
        case kCCAlgorithmRC2: return kCCBlockSizeRC2;
        case kCCAlgorithmBlowfish: return kCCBlockSizeBlowfish;
        default: return 0;
    }
}

static DHCryptorCapture *DHNewCryptorCapture(CCOperation operation,
                                             CCAlgorithm algorithm,
                                             NSUInteger options,
                                             const void *key,
                                             size_t keyLength,
                                             const void *iv) {
    DHCryptorCapture *capture = [DHCryptorCapture new];
    capture.operation = operation;
    capture.algorithm = algorithm;
    capture.options = options;
    capture.key = key && keyLength ? [NSData dataWithBytes:key length:keyLength] : NSData.data;
    size_t ivLength = DHBlockSize(algorithm);
    capture.iv = iv && ivLength ? [NSData dataWithBytes:iv length:ivLength] : NSData.data;
    capture.input = [NSMutableData data];
    capture.output = [NSMutableData data];
    return capture;
}

static void DHStoreCryptor(CCCryptorRef cryptor, DHCryptorCapture *capture) {
    if (!cryptor || !capture) return;
    pthread_mutex_lock(&gCryptorLock);
    gCryptorCaptures[DHPointerKey(cryptor)] = capture;
    pthread_mutex_unlock(&gCryptorLock);
}

static DHCryptorCapture *DHTakeCryptor(CCCryptorRef cryptor) {
    if (!cryptor) return nil;
    pthread_mutex_lock(&gCryptorLock);
    NSValue *key = DHPointerKey(cryptor);
    DHCryptorCapture *capture = gCryptorCaptures[key];
    [gCryptorCaptures removeObjectForKey:key];
    pthread_mutex_unlock(&gCryptorLock);
    return capture;
}

static void DHLogCryptorCapture(DHCryptorCapture *capture, NSString *phase, CCCryptorStatus status) {
    if (!capture) return;
    DHLogCrypto(@"SYMMETRIC", DHCipherName(capture.algorithm),
                capture.operation == kCCEncrypt ? @"encrypt-stream" : @"decrypt-stream",
                capture.input.bytes, capture.input.length,
                capture.output.bytes, capture.output.length,
                @{
                    @"phase": phase ?: @"unknown",
                    @"status": @(status),
                    @"options": @(capture.options),
                    @"keyBase64": [capture.key base64EncodedStringWithOptions:0],
                    @"keyLength": @(capture.key.length),
                    @"ivBase64": [capture.iv base64EncodedStringWithOptions:0],
                    @"capturedInputLength": @(capture.input.length),
                    @"capturedOutputLength": @(capture.output.length)
                });
}

static CCCryptorStatus DHHookedCCCryptorCreate(CCOperation operation,
                                                CCAlgorithm algorithm,
                                                CCOptions options,
                                                const void *key,
                                                size_t keyLength,
                                                const void *iv,
                                                CCCryptorRef *cryptorOut) {
    CCCryptorStatus status = gOriginalCCCryptorCreate ?
        gOriginalCCCryptorCreate(operation, algorithm, options, key, keyLength, iv, cryptorOut) :
        kCCUnimplemented;
    if (status == kCCSuccess && cryptorOut && *cryptorOut && [DHConfig shared].cryptoEnabled) {
        DHStoreCryptor(*cryptorOut, DHNewCryptorCapture(operation, algorithm, options,
                                                        key, keyLength, iv));
    }
    return status;
}

static CCCryptorStatus DHHookedCCCryptorCreateWithMode(CCOperation operation,
                                                        CCMode mode,
                                                        CCAlgorithm algorithm,
                                                        CCPadding padding,
                                                        const void *iv,
                                                        const void *key,
                                                        size_t keyLength,
                                                        const void *tweak,
                                                        size_t tweakLength,
                                                        int rounds,
                                                        CCModeOptions options,
                                                        CCCryptorRef *cryptorOut) {
    CCCryptorStatus status = gOriginalCCCryptorCreateWithMode ?
        gOriginalCCCryptorCreateWithMode(operation, mode, algorithm, padding, iv, key, keyLength,
                                          tweak, tweakLength, rounds, options, cryptorOut) :
        kCCUnimplemented;
    if (status == kCCSuccess && cryptorOut && *cryptorOut && [DHConfig shared].cryptoEnabled) {
        NSUInteger packedOptions = (NSUInteger)options | ((NSUInteger)mode << 16) | ((NSUInteger)padding << 24);
        DHStoreCryptor(*cryptorOut, DHNewCryptorCapture(operation, algorithm, packedOptions,
                                                        key, keyLength, iv));
    }
    return status;
}

static CCCryptorStatus DHHookedCCCryptorUpdate(CCCryptorRef cryptor,
                                                const void *dataIn,
                                                size_t dataInLength,
                                                void *dataOut,
                                                size_t dataOutAvailable,
                                                size_t *dataOutMoved) {
    CCCryptorStatus status = gOriginalCCCryptorUpdate ?
        gOriginalCCCryptorUpdate(cryptor, dataIn, dataInLength,
                                 dataOut, dataOutAvailable, dataOutMoved) : kCCUnimplemented;
    size_t moved = (status == kCCSuccess && dataOutMoved) ? *dataOutMoved : 0;
    pthread_mutex_lock(&gCryptorLock);
    DHCryptorCapture *capture = gCryptorCaptures[DHPointerKey(cryptor)];
    DHAppendLimited(capture.input, dataIn, dataInLength);
    DHAppendLimited(capture.output, dataOut, moved);
    pthread_mutex_unlock(&gCryptorLock);
    return status;
}

static CCCryptorStatus DHHookedCCCryptorFinal(CCCryptorRef cryptor,
                                               void *dataOut,
                                               size_t dataOutAvailable,
                                               size_t *dataOutMoved) {
    CCCryptorStatus status = gOriginalCCCryptorFinal ?
        gOriginalCCCryptorFinal(cryptor, dataOut, dataOutAvailable, dataOutMoved) : kCCUnimplemented;
    size_t moved = (status == kCCSuccess && dataOutMoved) ? *dataOutMoved : 0;
    pthread_mutex_lock(&gCryptorLock);
    DHCryptorCapture *capture = gCryptorCaptures[DHPointerKey(cryptor)];
    DHAppendLimited(capture.output, dataOut, moved);
    BOOL shouldLog = capture && !capture.logged;
    capture.logged = YES;
    pthread_mutex_unlock(&gCryptorLock);
    if (shouldLog) DHLogCryptorCapture(capture, @"final", status);
    return status;
}

static CCCryptorStatus DHHookedCCCryptorReset(CCCryptorRef cryptor, const void *iv) {
    CCCryptorStatus status = gOriginalCCCryptorReset ?
        gOriginalCCCryptorReset(cryptor, iv) : kCCUnimplemented;
    if (status != kCCSuccess) return status;
    pthread_mutex_lock(&gCryptorLock);
    DHCryptorCapture *capture = gCryptorCaptures[DHPointerKey(cryptor)];
    [capture.input setLength:0];
    [capture.output setLength:0];
    capture.logged = NO;
    size_t ivLength = capture ? DHBlockSize(capture.algorithm) : 0;
    if (capture && iv && ivLength) capture.iv = [NSData dataWithBytes:iv length:ivLength];
    pthread_mutex_unlock(&gCryptorLock);
    return status;
}

static CCCryptorStatus DHHookedCCCryptorRelease(CCCryptorRef cryptor) {
    CCCryptorStatus status = gOriginalCCCryptorRelease ?
        gOriginalCCCryptorRelease(cryptor) : kCCUnimplemented;
    DHCryptorCapture *capture = DHTakeCryptor(cryptor);
    if (capture && !capture.logged && (capture.input.length || capture.output.length)) {
        DHLogCryptorCapture(capture, @"release", status);
    }
    return status;
}

static CCCryptorStatus DHHookedCCCrypt(CCOperation operation,
                                       CCAlgorithm algorithm,
                                       CCOptions options,
                                       const void *key,
                                       size_t keyLength,
                                       const void *iv,
                                       const void *dataIn,
                                       size_t dataInLength,
                                       void *dataOut,
                                       size_t dataOutAvailable,
                                       size_t *dataOutMoved) {
    CCCryptorStatus status = gOriginalCCCrypt ?
        gOriginalCCCrypt(operation, algorithm, options, key, keyLength, iv,
                         dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved) : kCCUnimplemented;
    size_t moved = (status == kCCSuccess && dataOutMoved) ? *dataOutMoved : 0;
    DHLogCrypto(@"SYMMETRIC", DHCipherName(algorithm),
                operation == kCCEncrypt ? @"encrypt" : @"decrypt",
                dataIn, dataInLength, dataOut, moved,
                @{
                    @"status": @(status),
                    @"options": @(options),
                    @"keyBase64": DHBase64(key, keyLength),
                    @"keyLength": @(keyLength),
                    @"ivBase64": DHBase64(iv, DHBlockSize(algorithm))
                });
    return status;
}

typedef int (*DHCCPBKDFFn)(CCPBKDFAlgorithm, const char *, size_t, const uint8_t *, size_t,
                           CCPseudoRandomAlgorithm, unsigned int, uint8_t *, size_t);
static DHCCPBKDFFn gOriginalCCKeyDerivationPBKDF;

static int DHHookedCCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm,
                                        const char *password,
                                        size_t passwordLength,
                                        const uint8_t *salt,
                                        size_t saltLength,
                                        CCPseudoRandomAlgorithm prf,
                                        unsigned int rounds,
                                        uint8_t *derivedKey,
                                        size_t derivedKeyLength) {
    int status = gOriginalCCKeyDerivationPBKDF ?
        gOriginalCCKeyDerivationPBKDF(algorithm, password, passwordLength, salt, saltLength,
                                      prf, rounds, derivedKey, derivedKeyLength) : kCCUnimplemented;
    DHLogCrypto(@"KDF", @"PBKDF2", @"derive",
                password, passwordLength,
                status == kCCSuccess ? derivedKey : NULL,
                status == kCCSuccess ? derivedKeyLength : 0,
                @{
                    @"status": @(status),
                    @"prf": @(prf),
                    @"rounds": @(rounds),
                    @"saltBase64": DHBase64(salt, saltLength)
                });
    return status;
}

void DHInstallCommonCryptoHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"CC_MD2", (void *)DHHookedCC_MD2, (void **)&gOriginalCC_MD2},
            {"CC_MD4", (void *)DHHookedCC_MD4, (void **)&gOriginalCC_MD4},
            {"CC_MD5", (void *)DHHookedCC_MD5, (void **)&gOriginalCC_MD5},
            {"CC_SHA1", (void *)DHHookedCC_SHA1, (void **)&gOriginalCC_SHA1},
            {"CC_SHA224", (void *)DHHookedCC_SHA224, (void **)&gOriginalCC_SHA224},
            {"CC_SHA256", (void *)DHHookedCC_SHA256, (void **)&gOriginalCC_SHA256},
            {"CC_SHA384", (void *)DHHookedCC_SHA384, (void **)&gOriginalCC_SHA384},
            {"CC_SHA512", (void *)DHHookedCC_SHA512, (void **)&gOriginalCC_SHA512},
            DH_STREAM_DIGEST_BINDINGS(CC_MD2),
            DH_STREAM_DIGEST_BINDINGS(CC_MD4),
            DH_STREAM_DIGEST_BINDINGS(CC_MD5),
            DH_STREAM_DIGEST_BINDINGS(CC_SHA1),
            DH_STREAM_DIGEST_BINDINGS(CC_SHA224),
            DH_STREAM_DIGEST_BINDINGS(CC_SHA256),
            DH_STREAM_DIGEST_BINDINGS(CC_SHA384),
            DH_STREAM_DIGEST_BINDINGS(CC_SHA512),
            {"CCHmac", (void *)DHHookedCCHmac, (void **)&gOriginalCCHmac},
            {"CCHmacInit", (void *)DHHookedCCHmacInit, (void **)&gOriginalCCHmacInit},
            {"CCHmacUpdate", (void *)DHHookedCCHmacUpdate, (void **)&gOriginalCCHmacUpdate},
            {"CCHmacFinal", (void *)DHHookedCCHmacFinal, (void **)&gOriginalCCHmacFinal},
            {"CCCrypt", (void *)DHHookedCCCrypt, (void **)&gOriginalCCCrypt},
            {"CCCryptorCreate", (void *)DHHookedCCCryptorCreate, (void **)&gOriginalCCCryptorCreate},
            {"CCCryptorCreateWithMode", (void *)DHHookedCCCryptorCreateWithMode,
             (void **)&gOriginalCCCryptorCreateWithMode},
            {"CCCryptorUpdate", (void *)DHHookedCCCryptorUpdate, (void **)&gOriginalCCCryptorUpdate},
            {"CCCryptorFinal", (void *)DHHookedCCCryptorFinal, (void **)&gOriginalCCCryptorFinal},
            {"CCCryptorReset", (void *)DHHookedCCCryptorReset, (void **)&gOriginalCCCryptorReset},
            {"CCCryptorRelease", (void *)DHHookedCCCryptorRelease, (void **)&gOriginalCCCryptorRelease},
            {"CCKeyDerivationPBKDF", (void *)DHHookedCCKeyDerivationPBKDF,
             (void **)&gOriginalCCKeyDerivationPBKDF}
        };
        gDigestCaptures = [NSMutableDictionary dictionary];
        gHmacCaptures = [NSMutableDictionary dictionary];
        gCryptorCaptures = [NSMutableDictionary dictionary];
        rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
    });
}
