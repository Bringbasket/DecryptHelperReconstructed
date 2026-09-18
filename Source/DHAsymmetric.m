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
             (void **)&gOriginalSecKeyCreateDecryptedData}
        };
        DHRebindSymbols(bindings, sizeof(bindings) / sizeof(bindings[0]), @"fishhook");
    });
}
