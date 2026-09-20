#import <Foundation/Foundation.h>

FOUNDATION_EXPORT void DHInstallNetworkHooks(void);
FOUNDATION_EXPORT void DHInstallNetworkExtensions(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHNetworkCaptureCoverage(void);
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHWebKitProbeSnapshot(void);
FOUNDATION_EXPORT void DHInstallWebKitProbeHooks(void);
FOUNDATION_EXPORT void DHInstallWebSocketHooks(void);
FOUNDATION_EXPORT void DHInstallNetworkFrameworkHooks(void);
