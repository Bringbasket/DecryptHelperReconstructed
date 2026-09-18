#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

struct rebinding;

FOUNDATION_EXPORT void DHRegisterHook(NSString *name, NSString *type, BOOL installed);
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHHookRegistrySnapshot(void);

/// Installs Fishhook bindings and also records their wrapper/original slots so
/// calls resolved later through dlsym can be routed through the same wrappers.
FOUNDATION_EXPORT int DHRebindSymbols(const struct rebinding *bindings,
                                      size_t count,
                                      NSString *type);

/// Returns the registered wrapper for a symbol resolved through the real
/// dlsym. When Fishhook never saw an import slot, resolvedAddress is also used
/// to initialize the wrapper's original-function slot.
FOUNDATION_EXPORT void * _Nullable DHRouteResolvedSymbol(const char *symbol,
                                                          void * _Nullable resolvedAddress,
                                                          BOOL * _Nullable routed);

NS_ASSUME_NONNULL_END
