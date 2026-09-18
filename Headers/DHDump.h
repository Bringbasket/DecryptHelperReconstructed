#import <Foundation/Foundation.h>

FOUNDATION_EXPORT BOOL DHDumpLoadedImage(NSString * _Nullable imageName,
                                         NSString * _Nonnull outputPath,
                                         NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT NSString * _Nullable DHDumpImageToCache(NSString * _Nullable imageName,
                                                          NSString * _Nullable outputName,
                                                          NSError * _Nullable * _Nullable error);

/// Serial, in-process dump queue. Tasks are retained in memory for status queries;
/// their completed files remain in Library/Caches/IOSDecryptHub/Dumps.
@interface DHDumpManager : NSObject

+ (instancetype)sharedManager;
- (nullable NSDictionary<NSString *, id> *)startDumpWithImage:(nullable NSString *)imageName
                                                        format:(NSString *)format
                                                    outputName:(nullable NSString *)outputName
                                                         error:(NSError **)error;
- (nullable NSDictionary<NSString *, id> *)taskStatus:(NSString *)taskIdentifier;
- (NSArray<NSDictionary<NSString *, id> *> *)taskSnapshots;
- (NSUInteger)clearCompletedTasks;

@end
