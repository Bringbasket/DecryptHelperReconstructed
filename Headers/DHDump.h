#import <Foundation/Foundation.h>

FOUNDATION_EXPORT BOOL DHDumpLoadedImage(NSString * _Nullable imageName,
                                         NSString * _Nonnull outputPath,
                                         NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable DHDumpImageToCache(NSString * _Nullable imageName,
                                                          NSString * _Nullable outputName,
                                                          NSError * _Nullable * _Nullable error);
