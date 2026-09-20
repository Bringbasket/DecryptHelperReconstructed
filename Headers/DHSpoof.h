#import <Foundation/Foundation.h>

FOUNDATION_EXPORT void DHInstallSpoofHooks(void);
FOUNDATION_EXPORT NSUInteger DHEnvironmentProbeCount(void);
FOUNDATION_EXPORT BOOL DHSpoofMatchesImagePath(const char * _Nullable path);
