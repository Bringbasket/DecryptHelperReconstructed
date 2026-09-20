#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

struct rebinding;

FOUNDATION_EXPORT void DHRegisterHook(NSString *name, NSString *type, BOOL installed);
/// Records installation status with an optional error and implementation status code.
/// The legacy DHRegisterHook entry point remains source-compatible and records a
/// generic failure reason when installed is NO.
FOUNDATION_EXPORT void DHRegisterHookDiagnostic(NSString *name,
                                                NSString *type,
                                                BOOL installed,
                                                NSString * _Nullable errorMessage);
/// Variant used by installers that have a native return/status code.
FOUNDATION_EXPORT void DHRegisterHookDiagnosticWithStatus(NSString *name,
                                                          NSString *type,
                                                          BOOL installed,
                                                          NSString * _Nullable errorMessage,
                                                          NSInteger statusCode);
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHHookRegistrySnapshot(void);
/// Returns a compact health report suitable for diagnostics endpoints.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHHookRegistryDiagnosticSnapshot(void);

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
