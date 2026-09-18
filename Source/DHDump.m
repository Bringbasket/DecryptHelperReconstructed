#import "DHDump.h"
#import "DHZipWriter.h"
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <libkern/OSByteOrder.h>
#import <stddef.h>
#import <stdint.h>

static NSError *DHDumpError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:@"com.decrypthelper.reconstructed.dump"
                                code:code
                            userInfo:@{NSLocalizedDescriptionKey: message ?: @"dump error"}];
}

static const struct load_command *DHEncryptionCommand(const struct mach_header *header) {
    if (!header) return NULL;
    uintptr_t cursor = (uintptr_t)header;
    BOOL is64 = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
    uint32_t commandBytes = header->sizeofcmds;
    uintptr_t commandsStart = cursor + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    uintptr_t commandsEnd = commandsStart + commandBytes;
    cursor = commandsStart;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (cursor > commandsEnd || commandsEnd - cursor < sizeof(struct load_command)) return NULL;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > commandsEnd - cursor) return NULL;
        if ((command->cmd == LC_ENCRYPTION_INFO_64 && is64) ||
            (command->cmd == LC_ENCRYPTION_INFO && !is64)) return command;
        cursor += command->cmdsize;
    }
    return NULL;
}

static NSUInteger DHImageIndexForName(NSString *imageName) {
    uint32_t count = _dyld_image_count();
    if (!imageName.length) return 0;
    for (uint32_t index = 0; index < count; index++) {
        const char *name = _dyld_get_image_name(index);
        NSString *path = name ? [NSString stringWithUTF8String:name] : nil;
        if ([path isEqualToString:imageName] || [path.lastPathComponent isEqualToString:imageName]) return index;
    }
    return NSNotFound;
}

static uint64_t DHCurrentSliceOffset(NSData *fileData, const struct mach_header *header) {
    if (fileData.length < sizeof(uint32_t) || !header) return 0;
    uint32_t magic = 0;
    [fileData getBytes:&magic length:sizeof(magic)];
    magic = OSSwapBigToHostInt32(magic);
    if (magic != FAT_MAGIC && magic != FAT_MAGIC_64 &&
        magic != FAT_CIGAM && magic != FAT_CIGAM_64) return 0;
    if (fileData.length < sizeof(struct fat_header)) return 0;
    struct fat_header fatHeader = {0};
    [fileData getBytes:&fatHeader length:sizeof(fatHeader)];
    BOOL swapped = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    uint32_t count = swapped ? fatHeader.nfat_arch : OSSwapBigToHostInt32(fatHeader.nfat_arch);
    BOOL is64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    NSUInteger tableOffset = sizeof(struct fat_header);
    NSUInteger entrySize = is64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    if (count > 32 || tableOffset > fileData.length ||
        (uint64_t)entrySize * count > fileData.length - tableOffset) return 0;
    uint64_t fallback = 0;
    for (uint32_t index = 0; index < count; index++) {
        cpu_type_t cpuType = 0;
        cpu_subtype_t cpuSubtype = 0;
        uint64_t offset = 0;
        if (is64) {
            struct fat_arch_64 arch = {0};
            [fileData getBytes:&arch range:NSMakeRange(tableOffset + index * entrySize, entrySize)];
            cpuType = (cpu_type_t)(swapped ? arch.cputype : OSSwapBigToHostInt32(arch.cputype));
            cpuSubtype = (cpu_subtype_t)(swapped ? arch.cpusubtype : OSSwapBigToHostInt32(arch.cpusubtype));
            offset = swapped ? arch.offset : OSSwapBigToHostInt64(arch.offset);
        } else {
            struct fat_arch arch = {0};
            [fileData getBytes:&arch range:NSMakeRange(tableOffset + index * entrySize, entrySize)];
            cpuType = (cpu_type_t)(swapped ? arch.cputype : OSSwapBigToHostInt32(arch.cputype));
            cpuSubtype = (cpu_subtype_t)(swapped ? arch.cpusubtype : OSSwapBigToHostInt32(arch.cpusubtype));
            offset = swapped ? arch.offset : OSSwapBigToHostInt32(arch.offset);
        }
        if (cpuType != header->cputype) continue;
        if (!fallback) fallback = offset;
        if (cpuSubtype == header->cpusubtype) return offset;
    }
    return fallback;
}

BOOL DHDumpLoadedImage(NSString *imageName, NSString *outputPath, NSError **outError) {
    if (outError) *outError = nil;
    if (!outputPath.length) {
        if (outError) *outError = DHDumpError(1, @"outputPath is empty");
        return NO;
    }
    NSUInteger index = DHImageIndexForName(imageName);
    if (index == NSNotFound || index >= _dyld_image_count()) {
        if (outError) *outError = DHDumpError(2, @"loaded image was not found");
        return NO;
    }
    const struct mach_header *header = _dyld_get_image_header((uint32_t)index);
    const char *sourceName = _dyld_get_image_name((uint32_t)index);
    if (!header || !sourceName) {
        if (outError) *outError = DHDumpError(3, @"image metadata is unavailable");
        return NO;
    }
    NSData *fileData = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:sourceName]];
    if (!fileData.length) {
        if (outError) *outError = DHDumpError(4, @"source image could not be read");
        return NO;
    }
    const struct load_command *command = DHEncryptionCommand(header);
    // Some self-signed or previously decrypted binaries do not retain an encryption
    // command. They are already exportable, so preserve the file instead of failing.
    if (!command) return [fileData writeToFile:outputPath options:NSDataWritingAtomic error:outError];
    uint64_t sliceOffset = DHCurrentSliceOffset(fileData, header);
    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    if (command->cmd == LC_ENCRYPTION_INFO_64) {
        const struct encryption_info_command_64 *info = (const struct encryption_info_command_64 *)command;
        cryptoff = info->cryptoff; cryptsize = info->cryptsize; cryptid = info->cryptid;
    } else {
        const struct encryption_info_command *info = (const struct encryption_info_command *)command;
        cryptoff = info->cryptoff; cryptsize = info->cryptsize; cryptid = info->cryptid;
    }
    if (!cryptid || !cryptsize) {
        return [fileData writeToFile:outputPath options:NSDataWritingAtomic error:outError];
    }
    if (sliceOffset + cryptoff + cryptsize > fileData.length) {
        if (outError) *outError = DHDumpError(6, @"encrypted range exceeds source image");
        return NO;
    }
    const uint8_t *decrypted = (const uint8_t *)header + cryptoff;
    NSMutableData *output = [fileData mutableCopy];
    [output replaceBytesInRange:NSMakeRange((NSUInteger)(sliceOffset + cryptoff), cryptsize) withBytes:decrypted];
    uint8_t *bytes = output.mutableBytes;
    if (command->cmd == LC_ENCRYPTION_INFO_64) {
        NSUInteger commandOffset = (NSUInteger)((const uint8_t *)command - (const uint8_t *)header);
        uint64_t outputOffset = sliceOffset + commandOffset + offsetof(struct encryption_info_command_64, cryptid);
        if (outputOffset + sizeof(uint32_t) <= output.length) {
            *(uint32_t *)(bytes + outputOffset) = 0;
        }
    } else {
        NSUInteger commandOffset = (NSUInteger)((const uint8_t *)command - (const uint8_t *)header);
        uint64_t outputOffset = sliceOffset + commandOffset + offsetof(struct encryption_info_command, cryptid);
        if (outputOffset + sizeof(uint32_t) <= output.length) {
            *(uint32_t *)(bytes + outputOffset) = 0;
        }
    }
    return [output writeToFile:outputPath options:NSDataWritingAtomic error:outError];
}

NSString *DHDumpImageToCache(NSString *imageName, NSString *outputName, NSError **outError) {
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:
                           @"Library/Caches/IOSDecryptHub/Dumps"];
    NSError *directoryError = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory
                                   withIntermediateDirectories:YES
                                                    attributes:nil
                                                         error:&directoryError]) {
        if (outError) *outError = directoryError;
        return nil;
    }
    NSString *name = outputName.lastPathComponent;
    if (!name.length) {
        name = imageName.lastPathComponent;
        if (!name.length) name = NSBundle.mainBundle.executablePath.lastPathComponent;
        name = [NSString stringWithFormat:@"%@.decrypted", name ?: @"image"];
    }
    NSString *path = [directory stringByAppendingPathComponent:name];
    if (!DHDumpLoadedImage(imageName, path, outError)) return nil;
    return path;
}

@interface DHDumpTask : NSObject
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *format;
@property (nonatomic, copy) NSString *imageName;
@property (nonatomic, copy) NSString *requestedOutputName;
@property (nonatomic, copy) NSString *state;
@property (nonatomic, copy) NSString *phase;
@property (nonatomic, copy) NSString *outputPath;
@property (nonatomic, copy) NSString *errorMessage;
@property (nonatomic) double progress;
@property (nonatomic) uint64_t completedBytes;
@property (nonatomic) uint64_t totalBytes;
@property (nonatomic, strong) NSDate *createdAt;
@property (nonatomic, strong) NSDate *startedAt;
@property (nonatomic, strong) NSDate *finishedAt;
@end

@implementation DHDumpTask
@end

@interface DHDumpManager ()
@property (nonatomic, strong) dispatch_queue_t workerQueue;
@property (nonatomic, strong) NSMutableDictionary<NSString *, DHDumpTask *> *tasks;
@property (nonatomic, strong) NSMutableArray<NSString *> *taskOrder;
@end

@implementation DHDumpManager

+ (instancetype)sharedManager {
    static DHDumpManager *manager;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ manager = [DHDumpManager new]; });
    return manager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _workerQueue = dispatch_queue_create("com.decrypthelper.reconstructed.dump", DISPATCH_QUEUE_SERIAL);
        _tasks = [NSMutableDictionary dictionary];
        _taskOrder = [NSMutableArray array];
    }
    return self;
}

static NSNumber *DHDumpTimestamp(NSDate *date) {
    return date ? @((long long)(date.timeIntervalSince1970 * 1000.0)) : nil;
}

- (NSDictionary<NSString *, id> *)snapshotForTask:(DHDumpTask *)task {
    if (!task) return nil;
    @synchronized (task) {
        NSMutableDictionary<NSString *, id> *snapshot = [@{
            @"id": task.identifier ?: @"",
            @"format": task.format ?: @"",
            @"image": task.imageName ?: @"main",
            @"state": task.state ?: @"queued",
            @"phase": task.phase ?: @"queued",
            @"progress": @(task.progress),
            @"completedBytes": @(task.completedBytes),
            @"totalBytes": @(task.totalBytes),
            @"outputPath": task.outputPath ?: @"",
            @"outputName": task.outputPath.lastPathComponent ?: task.requestedOutputName ?: @"",
            @"error": task.errorMessage ?: @""
        } mutableCopy];
        NSNumber *created = DHDumpTimestamp(task.createdAt);
        NSNumber *started = DHDumpTimestamp(task.startedAt);
        NSNumber *finished = DHDumpTimestamp(task.finishedAt);
        if (created) snapshot[@"createdAtMs"] = created;
        if (started) snapshot[@"startedAtMs"] = started;
        if (finished) snapshot[@"finishedAtMs"] = finished;
        if (task.outputPath.length) {
            NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:task.outputPath error:nil];
            snapshot[@"fileSize"] = @([attributes[NSFileSize] unsignedLongLongValue]);
            snapshot[@"downloadPath"] = [NSString stringWithFormat:@"/api/dumps/download?id=%@", task.identifier];
        }
        return snapshot;
    }
}

- (DHDumpTask *)taskForIdentifier:(NSString *)identifier {
    if (!identifier.length) return nil;
    @synchronized (self) { return self.tasks[identifier]; }
}

- (NSDictionary<NSString *, id> *)taskStatus:(NSString *)taskIdentifier {
    return [self snapshotForTask:[self taskForIdentifier:taskIdentifier]];
}

- (NSArray<NSDictionary<NSString *, id> *> *)taskSnapshots {
    NSArray<NSString *> *identifiers;
    @synchronized (self) { identifiers = [[self.taskOrder reverseObjectEnumerator] allObjects]; }
    NSMutableArray *snapshots = [NSMutableArray arrayWithCapacity:identifiers.count];
    for (NSString *identifier in identifiers) {
        NSDictionary *snapshot = [self taskStatus:identifier];
        if (snapshot) [snapshots addObject:snapshot];
    }
    return snapshots;
}

- (NSUInteger)clearCompletedTasks {
    NSUInteger removed = 0;
    @synchronized (self) {
        for (NSString *identifier in [self.taskOrder copy]) {
            DHDumpTask *task = self.tasks[identifier];
            NSString *state;
            @synchronized (task) { state = task.state; }
            if ([state isEqualToString:@"succeeded"] || [state isEqualToString:@"failed"]) {
                [self.taskOrder removeObject:identifier];
                [self.tasks removeObjectForKey:identifier];
                removed++;
            }
        }
    }
    return removed;
}

- (void)updateTask:(DHDumpTask *)task
              state:(NSString *)state
              phase:(NSString *)phase
           progress:(double)progress
          completed:(uint64_t)completed
              total:(uint64_t)total {
    @synchronized (task) {
        if (state) task.state = state;
        if (phase) task.phase = phase;
        task.progress = MIN(MAX(progress, 0.0), 1.0);
        task.completedBytes = completed;
        task.totalBytes = total;
    }
}

static NSString *DHDumpDirectory(NSError **error) {
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/IOSDecryptHub/Dumps"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory
                                   withIntermediateDirectories:YES
                                                    attributes:nil
                                                         error:error]) return nil;
    return directory;
}

static NSString *DHDumpOutputPath(DHDumpTask *task, NSError **error) {
    NSString *directory = DHDumpDirectory(error);
    if (!directory) return nil;
    NSString *extension = [task.format isEqualToString:@"ipa"] ? @"ipa" :
                          [task.format isEqualToString:@"zip"] ? @"zip" : @"decrypted";
    NSString *name = task.requestedOutputName.lastPathComponent;
    if (!name.length) {
        NSString *base = NSBundle.mainBundle.bundleIdentifier ?: NSProcessInfo.processInfo.processName ?: @"dump";
        name = [NSString stringWithFormat:@"%@-%@.%@", base,
                [task.identifier substringToIndex:MIN((NSUInteger)8, task.identifier.length)], extension];
    } else if (![name.pathExtension.lowercaseString isEqualToString:extension]) {
        name = [name stringByAppendingPathExtension:extension];
    }
    NSString *path = [directory stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        NSString *stem = name.stringByDeletingPathExtension;
        NSString *suffix = [task.identifier substringToIndex:MIN((NSUInteger)8, task.identifier.length)];
        name = [NSString stringWithFormat:@"%@-%@.%@", stem, suffix, extension];
        path = [directory stringByAppendingPathComponent:name];
    }
    return path;
}

static NSString *DHDumpWorkDirectory(DHDumpTask *task, NSError **error) {
    NSString *directory = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/IOSDecryptHub/DumpWork"]
                           stringByAppendingPathComponent:task.identifier];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:directory
                                   withIntermediateDirectories:YES
                                                    attributes:nil
                                                         error:error]) return nil;
    return directory;
}

static NSString *DHDumpSourcePath(NSString *imageName) {
    NSUInteger index = DHImageIndexForName(imageName);
    if (index == NSNotFound || index >= _dyld_image_count()) return nil;
    const char *name = _dyld_get_image_name((uint32_t)index);
    return name ? [NSString stringWithUTF8String:name] : nil;
}

static NSData *DHDumpManifestData(DHDumpTask *task, NSString *sourcePath) {
    NSDictionary *manifest = @{
        @"taskId": task.identifier ?: @"",
        @"format": task.format ?: @"",
        @"bundleId": NSBundle.mainBundle.bundleIdentifier ?: @"",
        @"process": NSProcessInfo.processInfo.processName ?: @"",
        @"image": task.imageName ?: @"main",
        @"sourcePath": sourcePath ?: @"",
        @"createdAtMs": DHDumpTimestamp(task.createdAt) ?: @0,
        @"generator": @"DecryptHelperReconstructed"
    };
    return [NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:nil] ?: NSData.data;
}

- (BOOL)runMachODump:(DHDumpTask *)task outputPath:(NSString *)outputPath error:(NSError **)error {
    [self updateTask:task state:@"running" phase:@"dumping" progress:0.1 completed:0 total:0];
    if (!DHDumpLoadedImage(task.imageName, outputPath, error)) return NO;
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:outputPath error:nil];
    uint64_t size = [attributes[NSFileSize] unsignedLongLongValue];
    [self updateTask:task state:@"running" phase:@"finalizing" progress:0.95 completed:size total:size];
    return YES;
}

- (BOOL)runZipDump:(DHDumpTask *)task outputPath:(NSString *)outputPath workPath:(NSString *)workPath error:(NSError **)error {
    NSString *sourcePath = DHDumpSourcePath(task.imageName);
    NSString *sourceName = sourcePath.lastPathComponent ?: NSBundle.mainBundle.executablePath.lastPathComponent ?: @"image";
    NSString *dumpPath = [workPath stringByAppendingPathComponent:[sourceName stringByAppendingString:@".decrypted"]];
    [self updateTask:task state:@"running" phase:@"dumping" progress:0.05 completed:0 total:0];
    if (!DHDumpLoadedImage(task.imageName, dumpPath, error)) return NO;
    NSData *manifest = DHDumpManifestData(task, sourcePath);
    uint64_t fileSize = [[[[NSFileManager defaultManager] attributesOfItemAtPath:dumpPath error:nil]
                          objectForKey:NSFileSize] unsignedLongLongValue];
    uint64_t total = fileSize + manifest.length;
    [self updateTask:task state:@"running" phase:@"packaging" progress:0.45 completed:0 total:total];
    DHZipWriter *writer = [[DHZipWriter alloc] initWithPath:outputPath error:error];
    if (!writer || ![writer addDirectory:@"Dump" error:error]) return NO;
    __block uint64_t fileCompleted = 0;
    BOOL success = [writer addFileAtPath:dumpPath
                            archivePath:[@"Dump" stringByAppendingPathComponent:dumpPath.lastPathComponent]
                               progress:^(uint64_t completed, uint64_t ignoredTotal) {
        (void)ignoredTotal;
        fileCompleted = completed;
        double ratio = total ? (double)completed / (double)total : 1.0;
        [self updateTask:task state:@"running" phase:@"packaging"
                 progress:0.45 + ratio * 0.45 completed:completed total:total];
    } error:error];
    if (!success || ![writer addData:manifest archivePath:@"Dump/manifest.json" error:error]) return NO;
    [self updateTask:task state:@"running" phase:@"packaging" progress:0.92
             completed:fileCompleted + manifest.length total:total];
    return [writer close:error];
}

static NSArray<NSString *> *DHDumpBundleSubpaths(NSString *bundlePath) {
    NSDirectoryEnumerator<NSString *> *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:bundlePath];
    NSMutableArray<NSString *> *subpaths = [NSMutableArray array];
    for (NSString *subpath in enumerator) if (subpath.length) [subpaths addObject:subpath];
    return [subpaths sortedArrayUsingSelector:@selector(compare:)];
}

- (BOOL)runIPADump:(DHDumpTask *)task outputPath:(NSString *)outputPath workPath:(NSString *)workPath error:(NSError **)error {
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundlePath = bundle.bundlePath;
    NSString *executablePath = bundle.executablePath;
    if (!bundlePath.length || !executablePath.length) {
        if (error) *error = DHDumpError(20, @"main App bundle metadata is unavailable");
        return NO;
    }
    NSUInteger mainIndex = DHImageIndexForName(executablePath);
    NSUInteger selectedIndex = DHImageIndexForName(task.imageName.length ? task.imageName : executablePath);
    if (mainIndex == NSNotFound || selectedIndex != mainIndex) {
        if (error) *error = DHDumpError(21, @"IPA export only supports the current App main executable");
        return NO;
    }
    NSString *decryptedPath = [workPath stringByAppendingPathComponent:executablePath.lastPathComponent ?: @"AppExecutable"];
    [self updateTask:task state:@"running" phase:@"dumping" progress:0.03 completed:0 total:0];
    if (!DHDumpLoadedImage(executablePath, decryptedPath, error)) return NO;
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0755}
                                    ofItemAtPath:decryptedPath error:nil];

    NSArray<NSString *> *subpaths = DHDumpBundleSubpaths(bundlePath);
    NSString *archiveRoot = [@"Payload" stringByAppendingPathComponent:bundlePath.lastPathComponent];
    uint64_t total = 0;
    for (NSString *subpath in subpaths) {
        NSString *source = [bundlePath stringByAppendingPathComponent:subpath];
        if ([source isEqualToString:executablePath]) source = decryptedPath;
        NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:source error:nil];
        if (![attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) {
            total += [attributes[NSFileSize] unsignedLongLongValue];
        }
    }
    [self updateTask:task state:@"running" phase:@"packaging" progress:0.35 completed:0 total:total];
    DHZipWriter *writer = [[DHZipWriter alloc] initWithPath:outputPath error:error];
    if (!writer || ![writer addDirectory:@"Payload" error:error] ||
        ![writer addDirectory:archiveRoot error:error]) return NO;
    __block uint64_t completed = 0;
    for (NSString *subpath in subpaths) {
        @autoreleasepool {
            NSString *originalSource = [bundlePath stringByAppendingPathComponent:subpath];
            NSString *source = [originalSource isEqualToString:executablePath] ? decryptedPath : originalSource;
            NSString *archivePath = [archiveRoot stringByAppendingPathComponent:subpath];
            NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:source error:nil];
            if ([attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) {
                if (![writer addDirectory:archivePath error:error]) return NO;
                continue;
            }
            uint64_t base = completed;
            uint64_t entrySize = [attributes[NSFileSize] unsignedLongLongValue];
            if (![writer addFileAtPath:source archivePath:archivePath
                              progress:^(uint64_t entryCompleted, uint64_t ignoredTotal) {
                (void)ignoredTotal;
                uint64_t current = base + entryCompleted;
                double ratio = total ? (double)current / (double)total : 1.0;
                [self updateTask:task state:@"running" phase:@"packaging"
                         progress:0.35 + ratio * 0.6 completed:current total:total];
            } error:error]) return NO;
            completed += entrySize;
        }
    }
    return [writer close:error];
}

- (void)runTask:(DHDumpTask *)task {
    @autoreleasepool {
        @synchronized (task) {
            task.state = @"running";
            task.phase = @"preparing";
            task.startedAt = NSDate.date;
            task.progress = 0.01;
        }
        NSError *error = nil;
        NSString *outputPath = DHDumpOutputPath(task, &error);
        NSString *workPath = DHDumpWorkDirectory(task, &error);
        BOOL success = outputPath.length && workPath.length;
        if (success) {
            if ([task.format isEqualToString:@"ipa"]) {
                success = [self runIPADump:task outputPath:outputPath workPath:workPath error:&error];
            } else if ([task.format isEqualToString:@"zip"]) {
                success = [self runZipDump:task outputPath:outputPath workPath:workPath error:&error];
            } else {
                success = [self runMachODump:task outputPath:outputPath error:&error];
            }
        }
        [[NSFileManager defaultManager] removeItemAtPath:workPath error:nil];
        if (!success && outputPath.length) [[NSFileManager defaultManager] removeItemAtPath:outputPath error:nil];
        @synchronized (task) {
            task.finishedAt = NSDate.date;
            task.state = success ? @"succeeded" : @"failed";
            task.phase = success ? @"finished" : @"failed";
            task.progress = success ? 1.0 : task.progress;
            task.outputPath = success ? outputPath : @"";
            task.errorMessage = success ? @"" : error.localizedDescription ?: @"dump failed";
            if (success) task.completedBytes = task.totalBytes;
        }
    }
}

- (NSDictionary<NSString *, id> *)startDumpWithImage:(NSString *)imageName
                                                format:(NSString *)format
                                            outputName:(NSString *)outputName
                                                 error:(NSError **)error {
    NSString *normalizedFormat = format.lowercaseString ?: @"macho";
    if ([normalizedFormat isEqualToString:@"bin"]) normalizedFormat = @"macho";
    if (![@[@"macho", @"zip", @"ipa"] containsObject:normalizedFormat]) {
        if (error) *error = DHDumpError(30, @"format must be macho, zip, or ipa");
        return nil;
    }
    DHDumpTask *task = [DHDumpTask new];
    task.identifier = NSUUID.UUID.UUIDString.lowercaseString;
    task.format = normalizedFormat;
    task.imageName = imageName ?: @"";
    task.requestedOutputName = outputName ?: @"";
    task.state = @"queued";
    task.phase = @"queued";
    task.createdAt = NSDate.date;
    @synchronized (self) {
        self.tasks[task.identifier] = task;
        [self.taskOrder addObject:task.identifier];
    }
    dispatch_async(self.workerQueue, ^{ [self runTask:task]; });
    return [self snapshotForTask:task];
}

@end
