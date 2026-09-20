#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read a bounded range from this process. The implementation uses vm_read_overwrite
/// and never accepts a task port for another process.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHReadMemory(uint64_t address, NSUInteger length);

/// Search readable segments of a loaded image. `encoding` is `utf8`, `ascii`, or `hex`.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHSearchMemory(NSString * _Nullable selector,
                                                                          NSString *pattern,
                                                                          NSString * _Nullable encoding,
                                                                          NSUInteger limit);

/// Symbolicate an in-process address using dladdr and the loaded image symbol table.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHSymbolicateAddress(uint64_t address,
                                                                     NSString * _Nullable selector);

/// Find pointer or inline-string references in readable segments of a loaded image.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHFindXrefs(NSString * _Nullable selector,
                                                                      NSString *target,
                                                                      NSUInteger limit);

/// Enumerate Objective-C classes currently registered in this process.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHObjCClassList(NSString * _Nullable contains,
                                                                           NSUInteger limit);

/// Return methods, properties, protocols, superclass and image information for a class.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHObjCClassInfo(NSString *className,
                                                                NSUInteger methodLimit);

/// Resolve an Objective-C selector to its current IMP and declaring class.
/// `methodType` accepts `instance`, `class`, or `auto` (default).
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHObjCResolveIMP(NSString *className,
                                                                 NSString *selectorName,
                                                                 NSString * _Nullable methodType);

/// Find Objective-C methods across registered classes. Empty filters match all methods.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHFindObjCMethods(NSString * _Nullable classQuery,
                                                                              NSString * _Nullable selectorQuery,
                                                                              NSString * _Nullable imageQuery,
                                                                              NSString * _Nullable impImageQuery,
                                                                              NSUInteger limit);

NS_ASSUME_NONNULL_END
