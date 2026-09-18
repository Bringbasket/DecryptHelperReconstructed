#import <Foundation/Foundation.h>

/// Lightweight, in-process Mach-O inspection used by the HTTP/MCP diagnostics.
/// All selectors refer to images already loaded in the current process; this API
/// never opens or injects another process.
FOUNDATION_EXPORT NSDictionary *DHImageMachOInfo(NSString *selector);
FOUNDATION_EXPORT NSArray<NSDictionary *> *DHImageImports(NSString *selector, NSUInteger limit);
FOUNDATION_EXPORT NSArray<NSDictionary *> *DHImageFunctions(NSString *selector, NSUInteger limit);
FOUNDATION_EXPORT NSDictionary *DHDisassembleFunction(NSString *selector,
                                                      NSString *symbolOrAddress,
                                                      NSUInteger instructionLimit);
