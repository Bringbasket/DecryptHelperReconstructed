#import "DHZipWriter.h"
#import <sys/stat.h>

static NSString * const DHZipErrorDomain = @"com.decrypthelper.reconstructed.zip";

static NSError *DHZipError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:DHZipErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"ZIP error"}];
}

static void DHZipAppend16(NSMutableData *data, uint16_t value) {
    uint8_t bytes[] = {(uint8_t)value, (uint8_t)(value >> 8)};
    [data appendBytes:bytes length:sizeof(bytes)];
}

static void DHZipAppend32(NSMutableData *data, uint32_t value) {
    uint8_t bytes[] = {
        (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)
    };
    [data appendBytes:bytes length:sizeof(bytes)];
}

static uint32_t DHZipCRC32(uint32_t crc, const uint8_t *bytes, NSUInteger length) {
    static uint32_t table[256];
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        for (uint32_t index = 0; index < 256; index++) {
            uint32_t value = index;
            for (NSUInteger bit = 0; bit < 8; bit++) {
                value = (value >> 1) ^ ((value & 1) ? 0xedb88320U : 0U);
            }
            table[index] = value;
        }
    });
    crc ^= 0xffffffffU;
    for (NSUInteger index = 0; index < length; index++) {
        crc = table[(crc ^ bytes[index]) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xffffffffU;
}

static NSString *DHZipNormalizedPath(NSString *path, BOOL directory) {
    NSString *normalized = [path stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
    while ([normalized hasPrefix:@"/"]) normalized = [normalized substringFromIndex:1];
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (NSString *part in [normalized componentsSeparatedByString:@"/"]) {
        if (!part.length || [part isEqualToString:@"."]) continue;
        if ([part isEqualToString:@".."]) return nil;
        [parts addObject:part];
    }
    normalized = [parts componentsJoinedByString:@"/"];
    if (!normalized.length) return nil;
    if (directory && ![normalized hasSuffix:@"/"]) normalized = [normalized stringByAppendingString:@"/"];
    return normalized;
}

static void DHZipDate(NSDate *date, uint16_t *timeValue, uint16_t *dateValue) {
    NSCalendar *calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
    NSDateComponents *components = [calendar components:(NSCalendarUnitYear | NSCalendarUnitMonth |
                                                          NSCalendarUnitDay | NSCalendarUnitHour |
                                                          NSCalendarUnitMinute | NSCalendarUnitSecond)
                                                fromDate:date ?: NSDate.date];
    NSInteger year = MIN(MAX(components.year, 1980), 2107);
    if (timeValue) {
        *timeValue = (uint16_t)((components.hour << 11) | (components.minute << 5) |
                                (components.second / 2));
    }
    if (dateValue) {
        *dateValue = (uint16_t)(((year - 1980) << 9) | (components.month << 5) | components.day);
    }
}

@interface DHZipEntry : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic) uint32_t crc;
@property (nonatomic) uint32_t size;
@property (nonatomic) uint32_t localOffset;
@property (nonatomic) uint32_t externalAttributes;
@property (nonatomic) uint16_t flags;
@property (nonatomic) uint16_t modifiedTime;
@property (nonatomic) uint16_t modifiedDate;
@end

@implementation DHZipEntry
@end

@interface DHZipWriter ()
@property (nonatomic, strong) NSFileHandle *handle;
@property (nonatomic, strong) NSMutableArray<DHZipEntry *> *entries;
@property (nonatomic, readwrite) uint64_t bytesWritten;
@property (nonatomic) BOOL finished;
@end

@implementation DHZipWriter

- (instancetype)initWithPath:(NSString *)path error:(NSError **)error {
    self = [super init];
    if (!self) return nil;
    if (!path.length) {
        if (error) *error = DHZipError(1, @"archive path is empty");
        return nil;
    }
    NSString *directory = path.stringByDeletingLastPathComponent;
    NSError *directoryError = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory
                                   withIntermediateDirectories:YES
                                                    attributes:nil
                                                         error:&directoryError]) {
        if (error) *error = directoryError;
        return nil;
    }
    if (![[NSFileManager defaultManager] createFileAtPath:path contents:NSData.data attributes:nil]) {
        if (error) *error = DHZipError(2, @"could not create archive");
        return nil;
    }
    _handle = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!_handle) {
        if (error) *error = DHZipError(3, @"could not open archive for writing");
        return nil;
    }
    [_handle truncateFileAtOffset:0];
    _entries = [NSMutableArray array];
    return self;
}

- (BOOL)writeData:(NSData *)data error:(NSError **)error {
    if (self.finished || !self.handle) {
        if (error) *error = DHZipError(4, @"archive is already closed");
        return NO;
    }
    if (UINT64_MAX - self.bytesWritten < data.length) {
        if (error) *error = DHZipError(5, @"archive size overflow");
        return NO;
    }
    [self.handle writeData:data];
    self.bytesWritten += data.length;
    return YES;
}

- (BOOL)writeLocalHeaderForName:(NSData *)name
                          flags:(uint16_t)flags
                           time:(uint16_t)time
                           date:(uint16_t)date
                            crc:(uint32_t)crc
                           size:(uint32_t)size
                          error:(NSError **)error {
    NSMutableData *header = [NSMutableData dataWithCapacity:30 + name.length];
    DHZipAppend32(header, 0x04034b50U);
    DHZipAppend16(header, 20);
    DHZipAppend16(header, flags);
    DHZipAppend16(header, 0);
    DHZipAppend16(header, time);
    DHZipAppend16(header, date);
    DHZipAppend32(header, crc);
    DHZipAppend32(header, size);
    DHZipAppend32(header, size);
    DHZipAppend16(header, (uint16_t)name.length);
    DHZipAppend16(header, 0);
    [header appendData:name];
    return [self writeData:header error:error];
}

- (BOOL)addKnownData:(NSData *)data
          archivePath:(NSString *)archivePath
                 mode:(mode_t)mode
                 date:(NSDate *)date
                error:(NSError **)error {
    NSString *name = DHZipNormalizedPath(archivePath, S_ISDIR(mode));
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    if (!name.length || !nameData.length || nameData.length > UINT16_MAX ||
        data.length > UINT32_MAX || self.bytesWritten > UINT32_MAX) {
        if (error) *error = DHZipError(6, @"ZIP entry path or size is unsupported");
        return NO;
    }
    uint16_t time = 0, dosDate = 0;
    DHZipDate(date, &time, &dosDate);
    uint32_t crc = data.length ? DHZipCRC32(0, data.bytes, data.length) : 0;
    uint16_t flags = 0x0800;
    uint32_t offset = (uint32_t)self.bytesWritten;
    if (![self writeLocalHeaderForName:nameData flags:flags time:time date:dosDate
                                    crc:crc size:(uint32_t)data.length error:error] ||
        (data.length && ![self writeData:data error:error])) return NO;
    DHZipEntry *entry = [DHZipEntry new];
    entry.name = name;
    entry.crc = crc;
    entry.size = (uint32_t)data.length;
    entry.localOffset = offset;
    entry.flags = flags;
    entry.modifiedTime = time;
    entry.modifiedDate = dosDate;
    entry.externalAttributes = ((uint32_t)mode << 16) | (S_ISDIR(mode) ? 0x10U : 0U);
    [self.entries addObject:entry];
    return YES;
}

- (BOOL)addDirectory:(NSString *)archivePath error:(NSError **)error {
    return [self addKnownData:NSData.data archivePath:archivePath
                         mode:(S_IFDIR | 0755) date:NSDate.date error:error];
}

- (BOOL)addData:(NSData *)data archivePath:(NSString *)archivePath error:(NSError **)error {
    return [self addKnownData:data ?: NSData.data archivePath:archivePath
                         mode:(S_IFREG | 0644) date:NSDate.date error:error];
}

- (BOOL)addFileAtPath:(NSString *)sourcePath
          archivePath:(NSString *)archivePath
             progress:(DHZipProgressBlock)progress
                error:(NSError **)error {
    NSError *attributesError = nil;
    NSDictionary<NSFileAttributeKey, id> *attributes =
        [[NSFileManager defaultManager] attributesOfItemAtPath:sourcePath error:&attributesError];
    if (!attributes) {
        if (error) *error = attributesError ?: DHZipError(7, @"source file is unavailable");
        return NO;
    }
    NSString *type = attributes[NSFileType];
    NSDate *date = attributes[NSFileModificationDate] ?: NSDate.date;
    NSUInteger permissions = [attributes[NSFilePosixPermissions] unsignedIntegerValue] & 0777;
    if ([type isEqualToString:NSFileTypeDirectory]) {
        return [self addKnownData:NSData.data archivePath:archivePath
                             mode:(S_IFDIR | (permissions ?: 0755)) date:date error:error];
    }
    if ([type isEqualToString:NSFileTypeSymbolicLink]) {
        NSError *linkError = nil;
        NSString *destination = [[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:sourcePath
                                                                                          error:&linkError];
        NSData *data = [destination dataUsingEncoding:NSUTF8StringEncoding];
        if (!data) {
            if (error) *error = linkError ?: DHZipError(8, @"symbolic link target is unavailable");
            return NO;
        }
        BOOL success = [self addKnownData:data archivePath:archivePath mode:(S_IFLNK | 0777)
                                     date:date error:error];
        if (success && progress) progress(data.length, data.length);
        return success;
    }

    uint64_t expectedSize = [attributes[NSFileSize] unsignedLongLongValue];
    NSString *name = DHZipNormalizedPath(archivePath, NO);
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    if (!name.length || !nameData.length || nameData.length > UINT16_MAX ||
        expectedSize > UINT32_MAX || self.bytesWritten > UINT32_MAX) {
        if (error) *error = DHZipError(9, @"ZIP entry path or file size is unsupported");
        return NO;
    }
    NSFileHandle *input = [NSFileHandle fileHandleForReadingAtPath:sourcePath];
    if (!input) {
        if (error) *error = DHZipError(10, @"could not open source file");
        return NO;
    }
    uint16_t time = 0, dosDate = 0;
    DHZipDate(date, &time, &dosDate);
    uint16_t flags = 0x0808;
    uint32_t localOffset = (uint32_t)self.bytesWritten;
    if (![self writeLocalHeaderForName:nameData flags:flags time:time date:dosDate
                                    crc:0 size:0 error:error]) {
        [input closeFile];
        return NO;
    }
    uint64_t completed = 0;
    uint32_t crc = 0;
    while (completed < expectedSize) {
        @autoreleasepool {
            NSUInteger request = (NSUInteger)MIN((uint64_t)(1024 * 1024), expectedSize - completed);
            NSData *chunk = [input readDataOfLength:request];
            if (!chunk.length) break;
            crc = DHZipCRC32(crc, chunk.bytes, chunk.length);
            if (![self writeData:chunk error:error]) {
                completed = UINT64_MAX;
                break;
            }
            completed += chunk.length;
            if (progress) progress(completed, expectedSize);
        }
    }
    [input closeFile];
    if (completed != expectedSize) {
        if (error && !*error) *error = DHZipError(11, @"source file changed or could not be read completely");
        return NO;
    }
    NSMutableData *descriptor = [NSMutableData dataWithCapacity:16];
    DHZipAppend32(descriptor, 0x08074b50U);
    DHZipAppend32(descriptor, crc);
    DHZipAppend32(descriptor, (uint32_t)expectedSize);
    DHZipAppend32(descriptor, (uint32_t)expectedSize);
    if (![self writeData:descriptor error:error]) return NO;

    DHZipEntry *entry = [DHZipEntry new];
    entry.name = name;
    entry.crc = crc;
    entry.size = (uint32_t)expectedSize;
    entry.localOffset = localOffset;
    entry.flags = flags;
    entry.modifiedTime = time;
    entry.modifiedDate = dosDate;
    entry.externalAttributes = (uint32_t)(S_IFREG | (permissions ?: 0644)) << 16;
    [self.entries addObject:entry];
    return YES;
}

- (BOOL)close:(NSError **)error {
    if (self.finished) return YES;
    if (self.entries.count > UINT16_MAX || self.bytesWritten > UINT32_MAX) {
        if (error) *error = DHZipError(12, @"ZIP64 archives are not supported");
        return NO;
    }
    uint32_t centralOffset = (uint32_t)self.bytesWritten;
    for (DHZipEntry *entry in self.entries) {
        NSData *name = [entry.name dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableData *header = [NSMutableData dataWithCapacity:46 + name.length];
        DHZipAppend32(header, 0x02014b50U);
        DHZipAppend16(header, (uint16_t)((3 << 8) | 20));
        DHZipAppend16(header, 20);
        DHZipAppend16(header, entry.flags);
        DHZipAppend16(header, 0);
        DHZipAppend16(header, entry.modifiedTime);
        DHZipAppend16(header, entry.modifiedDate);
        DHZipAppend32(header, entry.crc);
        DHZipAppend32(header, entry.size);
        DHZipAppend32(header, entry.size);
        DHZipAppend16(header, (uint16_t)name.length);
        DHZipAppend16(header, 0);
        DHZipAppend16(header, 0);
        DHZipAppend16(header, 0);
        DHZipAppend16(header, 0);
        DHZipAppend32(header, entry.externalAttributes);
        DHZipAppend32(header, entry.localOffset);
        [header appendData:name];
        if (![self writeData:header error:error]) return NO;
    }
    uint64_t centralSize64 = self.bytesWritten - centralOffset;
    if (centralSize64 > UINT32_MAX) {
        if (error) *error = DHZipError(13, @"ZIP central directory is too large");
        return NO;
    }
    NSMutableData *footer = [NSMutableData dataWithCapacity:22];
    DHZipAppend32(footer, 0x06054b50U);
    DHZipAppend16(footer, 0);
    DHZipAppend16(footer, 0);
    DHZipAppend16(footer, (uint16_t)self.entries.count);
    DHZipAppend16(footer, (uint16_t)self.entries.count);
    DHZipAppend32(footer, (uint32_t)centralSize64);
    DHZipAppend32(footer, centralOffset);
    DHZipAppend16(footer, 0);
    if (![self writeData:footer error:error]) return NO;
    [self.handle synchronizeFile];
    [self.handle closeFile];
    self.handle = nil;
    self.finished = YES;
    return YES;
}

- (void)dealloc {
    if (self.handle) [self.handle closeFile];
}

@end
