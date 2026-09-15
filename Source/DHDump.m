#import "DHDump.h"
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
    if (!command) {
        if (outError) *outError = DHDumpError(5, @"LC_ENCRYPTION_INFO was not found");
        return NO;
    }
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
