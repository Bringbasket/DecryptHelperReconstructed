#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^DHZipProgressBlock)(uint64_t completedBytes, uint64_t totalBytes);

/// Minimal streaming ZIP writer using the STORE method. It supports regular files,
/// directories and symbolic links without depending on zlib or a third-party archive library.
@interface DHZipWriter : NSObject

- (nullable instancetype)initWithPath:(NSString *)path
                                 error:(NSError * _Nullable * _Nullable)error;
- (BOOL)addDirectory:(NSString *)archivePath
                error:(NSError * _Nullable * _Nullable)error;
- (BOOL)addData:(NSData *)data
    archivePath:(NSString *)archivePath
          error:(NSError * _Nullable * _Nullable)error;
- (BOOL)addFileAtPath:(NSString *)sourcePath
          archivePath:(NSString *)archivePath
             progress:(nullable DHZipProgressBlock)progress
                error:(NSError * _Nullable * _Nullable)error;
- (BOOL)close:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, readonly) uint64_t bytesWritten;

@end

NS_ASSUME_NONNULL_END
