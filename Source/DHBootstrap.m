#import "DHConfig.h"
#import "DHCommonCrypto.h"
#import "DHAsymmetric.h"
#import "DHFileHooks.h"
#import "DHEVP.h"
#import "DHHTTPServer.h"
#import "DHKeychain.h"
#import "DHLogStore.h"
#import "DHNetwork.h"
#import "DHSpoof.h"

__attribute__((constructor))
static void DHBootstrap(void) {
    @autoreleasepool {
        [[DHConfig shared] reload];

        DHLogEntry *entry = [DHLogEntry entryWithCategory:@"DIAGNOSTIC"
                                                algorithm:@"bootstrap"
                                                operation:@"start"];
        entry.detail = @"DecryptHelperReconstructed loaded";
        [[DHLogStore shared] append:entry];

        DHInstallCommonCryptoHooks();
        DHInstallAsymmetricHooks();
        DHInstallKeychainHooks();
        DHInstallFileHooks();
        DHInstallEVPHooks();
        DHInstallSpoofHooks();
        DHInstallNetworkHooks();
        DHStartHTTPServer();
    }
}
