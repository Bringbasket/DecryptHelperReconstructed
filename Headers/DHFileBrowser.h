#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Lists entries below the current host application's sandbox only.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> *DHListSandboxFiles(NSString * _Nullable relativePath,
                                                                               NSUInteger limit);

/// Reads a bounded preview from a regular file in the current host application's sandbox.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *DHReadSandboxFile(NSString *relativePath,
                                                                  NSUInteger maxBytes);

/// Returns a validated absolute path for a regular sandbox file, or nil on rejection.
FOUNDATION_EXPORT NSString * _Nullable DHSandboxFilePath(NSString *relativePath,
                                                         NSError * _Nullable * _Nullable error);

NS_ASSUME_NONNULL_END
