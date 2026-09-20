#import "DHConfig.h"
#import "DHCommonCrypto.h"
#import "DHAsymmetric.h"
#import "DHDynamic.h"
#import "DHFileHooks.h"
#import "DHEVP.h"
#import "DHFloatingUI.h"
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
        DHInstallDynamicHooks();
        DHInstallKeychainHooks();
        DHInstallFileHooks();
        DHInstallEVPHooks();
        DHInstallSpoofHooks();
        DHInstallNetworkHooks();
        DHInstallNetworkExtensions();
        DHInstallWebKitProbeHooks();
        DHInstallWebSocketHooks();
        DHInstallNetworkFrameworkHooks();
        DHStartHTTPServer();
        DHInstallFloatingUI();
    }
}
