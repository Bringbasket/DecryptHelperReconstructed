#import "DHAsymmetric.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "fishhook.h"
#import <Security/Security.h>

static __thread int gAsymmetricGuard;

static NSString *DHAlgorithmName(SecKeyAlgorithm algorithm) {
    if (!algorithm) return @"unknown";
    return [(__bridge NSString *)algorithm copy];
}

static NSString *DHErrorDescription(CFErrorRef error) {
    if (!error) return @"";
    return [(__bridge NSError *)error description] ?: @"";
}

static void DHLogAsymmetric(NSString *operation,
                            SecKeyAlgorithm algorithm,
                            CFDataRef input,
                            CFDataRef output,
                            BOOL success,
                            CFErrorRef error) {
    if (gAsymmetricGuard || ![DHConfig shared].cryptoEnabled) return;
    gAsymmetricGuard++;
    @autoreleasepool {
        DHLogEntry *entry = [DHLogEntry entryWithCategory:@"ASYMMETRIC"
                                                algorithm:DHAlgorithmName(algorithm)
                                                operation:operation];
        if (input) entry.input = [(__bridge NSData *)input copy];
        if (output) entry.output = [(__bridge NSData *)output copy];
        NSDictionary *metadata = @{
            @"success": @(success),
            @"error": DHErrorDescription(error)
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
        entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gAsymmetricGuard--;
}

typedef CFDataRef (*DHSecKeyCreateSignatureFn)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
typedef Boolean (*DHSecKeyVerifySignatureFn)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
typedef CFDataRef (*DHSecKeyCreateCryptedDataFn)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);

static DHSecKeyCreateSignatureFn gOriginalSecKeyCreateSignature;
static DHSecKeyVerifySignatureFn gOriginalSecKeyVerifySignature;
static DHSecKeyCreateCryptedDataFn gOriginalSecKeyCreateEncryptedData;
static DHSecKeyCreateCryptedDataFn gOriginalSecKeyCreateDecryptedData;

typedef OSStatus (*DHSecKeyLegacyFn)(SecKeyRef, SecPadding, const uint8_t *, size_t, uint8_t *, size_t *);
typedef OSStatus (*DHSecKeyLegacyVerifyFn)(SecKeyRef, SecPadding, const uint8_t *, size_t, const uint8_t *, size_t);
static DHSecKeyLegacyFn gOriginalSecKeyEncrypt;
static DHSecKeyLegacyFn gOriginalSecKeyDecrypt;
static DHSecKeyLegacyFn gOriginalSecKeyRawSign;
static DHSecKeyLegacyVerifyFn gOriginalSecKeyRawVerify;

static void DHLogLegacyKey(NSString *operation, const uint8_t *input, size_t inputLength,
                           const uint8_t *output, size_t outputLength, OSStatus status) {
    NSData *inputData = input && inputLength ? [NSData dataWithBytes:input length:MIN(inputLength, 1024 * 1024)] : nil;
    NSData *outputData = output && outputLength ? [NSData dataWithBytes:output length:MIN(outputLength, 1024 * 1024)] : nil;
    DHLogAsymmetric(operation, nil, (__bridge CFDataRef)inputData, (__bridge CFDataRef)outputData, status == errSecSuccess, NULL);
}

static OSStatus DHHookedSecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText,
                                      size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {
    OSStatus status = gOriginalSecKeyEncrypt ? gOriginalSecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen) : errSecUnimplemented;
    DHLogLegacyKey(@"encrypt_legacy", plainText, plainTextLen, cipherText, cipherTextLen ? *cipherTextLen : 0, status);
    return status;
}

static OSStatus DHHookedSecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText,
                                      size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {
    OSStatus status = gOriginalSecKeyDecrypt ? gOriginalSecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen) : errSecUnimplemented;
    DHLogLegacyKey(@"decrypt_legacy", cipherText, cipherTextLen, plainText, plainTextLen ? *plainTextLen : 0, status);
    return status;
}

static OSStatus DHHookedSecKeyRawSign(SecKeyRef key, SecPadding padding, const uint8_t *dataToSign,
                                      size_t dataToSignLen, uint8_t *sig, size_t *sigLen) {
    OSStatus status = gOriginalSecKeyRawSign ? gOriginalSecKeyRawSign(key, padding, dataToSign, dataToSignLen, sig, sigLen) : errSecUnimplemented;
    DHLogLegacyKey(@"raw_sign", dataToSign, dataToSignLen, sig, sigLen ? *sigLen : 0, status);
    return status;
}

static OSStatus DHHookedSecKeyRawVerify(SecKeyRef key, SecPadding padding, const uint8_t *signedData,
                                        size_t signedDataLen, const uint8_t *sig, size_t sigLen) {
    OSStatus status = gOriginalSecKeyRawVerify ? gOriginalSecKeyRawVerify(key, padding, signedData, signedDataLen, sig, sigLen) : errSecUnimplemented;
    DHLogLegacyKey(@"raw_verify", signedData, signedDataLen, sig, sigLen, status);
    return status;
}

static CFDataRef DHHookedSecKeyCreateSignature(SecKeyRef key,
                                               SecKeyAlgorithm algorithm,
                                               CFDataRef data,
                                               CFErrorRef *error) {
    CFDataRef result = gOriginalSecKeyCreateSignature ?
        gOriginalSecKeyCreateSignature(key, algorithm, data, error) : NULL;
    DHLogAsymmetric(@"sign", algorithm, data, result, result != NULL, error ? *error : NULL);
    return result;
}

static Boolean DHHookedSecKeyVerifySignature(SecKeyRef key,
                                              SecKeyAlgorithm algorithm,
                                              CFDataRef signedData,
                                              CFDataRef signature,
                                              CFErrorRef *error) {
    Boolean result = gOriginalSecKeyVerifySignature ?
        gOriginalSecKeyVerifySignature(key, algorithm, signedData, signature, error) : (Boolean)0;
    DHLogAsymmetric(@"verify", algorithm, signedData, signature, result, error ? *error : NULL);
    return result;
}

static CFDataRef DHHookedSecKeyCreateEncryptedData(SecKeyRef key,
                                                   SecKeyAlgorithm algorithm,
                                                   CFDataRef plaintext,
                                                   CFErrorRef *error) {
    CFDataRef result = gOriginalSecKeyCreateEncryptedData ?
        gOriginalSecKeyCreateEncryptedData(key, algorithm, plaintext, error) : NULL;
    DHLogAsymmetric(@"encrypt", algorithm, plaintext, result, result != NULL, error ? *error : NULL);
    return result;
}

static CFDataRef DHHookedSecKeyCreateDecryptedData(SecKeyRef key,
                                                   SecKeyAlgorithm algorithm,
                                                   CFDataRef ciphertext,
                                                   CFErrorRef *error) {
    CFDataRef result = gOriginalSecKeyCreateDecryptedData ?
        gOriginalSecKeyCreateDecryptedData(key, algorithm, ciphertext, error) : NULL;
    DHLogAsymmetric(@"decrypt", algorithm, ciphertext, result, result != NULL, error ? *error : NULL);
    return result;
}

void DHInstallAsymmetricHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"SecKeyCreateSignature", (void *)DHHookedSecKeyCreateSignature,
             (void **)&gOriginalSecKeyCreateSignature},
            {"SecKeyVerifySignature", (void *)DHHookedSecKeyVerifySignature,
             (void **)&gOriginalSecKeyVerifySignature},
            {"SecKeyCreateEncryptedData", (void *)DHHookedSecKeyCreateEncryptedData,
             (void **)&gOriginalSecKeyCreateEncryptedData},
            {"SecKeyCreateDecryptedData", (void *)DHHookedSecKeyCreateDecryptedData,
             (void **)&gOriginalSecKeyCreateDecryptedData},
            {"SecKeyEncrypt", (void *)DHHookedSecKeyEncrypt, (void **)&gOriginalSecKeyEncrypt},
            {"SecKeyDecrypt", (void *)DHHookedSecKeyDecrypt, (void **)&gOriginalSecKeyDecrypt},
            {"SecKeyRawSign", (void *)DHHookedSecKeyRawSign, (void **)&gOriginalSecKeyRawSign},
            {"SecKeyRawVerify", (void *)DHHookedSecKeyRawVerify, (void **)&gOriginalSecKeyRawVerify}
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
