#import "DHImageInventory.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static NSUInteger DHImageSegmentCount(const struct mach_header *header) {
    if (!header) return 0;
    NSUInteger count = 0;
    BOOL is64 = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
    uintptr_t cursor = (uintptr_t)header + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    uintptr_t commandEnd = cursor + header->sizeofcmds;
    if (commandEnd < cursor) return 0;
    if (is64) {
        const struct mach_header_64 *header64 = (const struct mach_header_64 *)header;
        for (uint32_t index = 0; index < header64->ncmds; index++) {
            if (cursor > commandEnd || commandEnd - cursor < sizeof(struct load_command)) break;
            const struct load_command *command = (const struct load_command *)cursor;
            if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > commandEnd - cursor) break;
            if (command->cmd == LC_SEGMENT_64) count++;
            cursor += command->cmdsize;
        }
    } else {
        for (uint32_t index = 0; index < header->ncmds; index++) {
            if (cursor > commandEnd || commandEnd - cursor < sizeof(struct load_command)) break;
            const struct load_command *command = (const struct load_command *)cursor;
            if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > commandEnd - cursor) break;
            if (command->cmd == LC_SEGMENT) count++;
            cursor += command->cmdsize;
        }
    }
    return count;
}

NSArray<NSDictionary<NSString *, id> *> *DHLoadedImageSnapshot(void) {
    NSMutableArray *images = [NSMutableArray array];
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        const char *name = _dyld_get_image_name(index);
        intptr_t slide = _dyld_get_image_vmaddr_slide(index);
        if (!header) continue;
        NSMutableDictionary *item = [@{
            @"index": @(index),
            @"name": name ? [NSString stringWithUTF8String:name] ?: @"" : @"",
            @"slide": @(slide),
            @"header": [NSString stringWithFormat:@"%p", header],
            @"segments": @(DHImageSegmentCount(header))
        } mutableCopy];
        item[@"is64Bit"] = @(header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64);
        [images addObject:item];
    }
    return images;
}
