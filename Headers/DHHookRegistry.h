#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT void DHRegisterHook(NSString *name, NSString *type, BOOL installed);
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHHookRegistrySnapshot(void);

NS_ASSUME_NONNULL_END
