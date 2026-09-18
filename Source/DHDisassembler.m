#import "DHDisassembler.h"
#import "DHImageInventory.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>
#import <capstone/capstone.h>

typedef struct {
    uint32_t index;
    const struct mach_header *header;
    intptr_t slide;
    const char *name;
} DHImageRef;

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
    const char *name;
    uint32_t index;
    const struct segment_command_64 *text;
    const struct section_64 *textSection;
    const struct symtab_command *symtab;
    const struct dysymtab_command *dysymtab;
    const struct dyld_info_command *exports;
    const struct encryption_info_command_64 *encryption;
    const struct uuid_command *uuid;
    const struct load_command *commands;
} DHMachO;

static BOOL DHIs64Header(const struct mach_header *header) {
    return header && (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64);
}

static BOOL DHFindImage(NSString *selector, DHImageRef *result) {
    NSString *wanted = selector.length ? selector : nil;
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        const char *name = _dyld_get_image_name(index);
        if (!header || !DHIs64Header(header)) continue;
        NSString *path = name ? [NSString stringWithUTF8String:name] : @"";
        BOOL numericSelector = wanted.length > 0;
        for (NSUInteger c = 0; c < wanted.length; c++) {
            unichar character = [wanted characterAtIndex:c];
            if (character < '0' || character > '9') { numericSelector = NO; break; }
        }
        BOOL match = !wanted || (numericSelector && index == wanted.integerValue) ||
            [path isEqualToString:wanted] || [path.lastPathComponent isEqualToString:wanted] ||
            [path hasSuffix:wanted];
        if (!match) continue;
        if (result) *result = (DHImageRef){ index, header, _dyld_get_image_vmaddr_slide(index), name };
        return YES;
    }
    return NO;
}

static BOOL DHParseImage(DHImageRef image, DHMachO *out) {
    if (!out || !image.header || !DHIs64Header(image.header)) return NO;
    memset(out, 0, sizeof(*out));
    out->header = (const struct mach_header_64 *)image.header;
    out->slide = image.slide;
    out->name = image.name;
    out->index = image.index;
    uintptr_t cursor = (uintptr_t)out->header + sizeof(struct mach_header_64);
    uintptr_t end = cursor + out->header->sizeofcmds;
    if (end < cursor || out->header->ncmds > 4096) return NO;
    out->commands = (const struct load_command *)cursor;
    for (uint32_t i = 0; i < out->header->ncmds; i++) {
        if (cursor > end || end - cursor < sizeof(struct load_command)) return NO;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > end - cursor) return NO;
        switch (command->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
                if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) == 0) {
                    out->text = segment;
                    uintptr_t sectionCursor = cursor + sizeof(struct segment_command_64);
                    uintptr_t sectionEnd = cursor + command->cmdsize;
                    for (uint32_t s = 0; s < segment->nsects; s++) {
                        if (sectionCursor > sectionEnd || sectionEnd - sectionCursor < sizeof(struct section_64)) break;
                        const struct section_64 *section = (const struct section_64 *)sectionCursor;
                        if (strncmp(section->sectname, "__text", sizeof(section->sectname)) == 0) out->textSection = section;
                        sectionCursor += sizeof(struct section_64);
                    }
                }
                break;
            }
            case LC_SYMTAB: out->symtab = (const struct symtab_command *)command; break;
            case LC_DYSYMTAB: out->dysymtab = (const struct dysymtab_command *)command; break;
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY: out->exports = (const struct dyld_info_command *)command; break;
            case LC_UUID: out->uuid = (const struct uuid_command *)command; break;
            case LC_ENCRYPTION_INFO_64: out->encryption = (const struct encryption_info_command_64 *)command; break;
            default: break;
        }
        cursor += command->cmdsize;
    }
    return YES;
}

static const struct segment_command_64 *DHLinkeditSegment(const DHMachO *image) {
    uintptr_t cursor = (uintptr_t)image->commands;
    uintptr_t end = cursor + image->header->sizeofcmds;
    for (uint32_t i = 0; i < image->header->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > end - cursor) break;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__LINKEDIT", sizeof(segment->segname)) == 0) return segment;
        }
        cursor += command->cmdsize;
    }
    return NULL;
}

static uintptr_t DHLinkeditAddress(const DHMachO *image, uint32_t fileOffset) {
    const struct segment_command_64 *segment = DHLinkeditSegment(image);
    if (!segment || fileOffset < segment->fileoff) return 0;
    uint64_t delta = (uint64_t)fileOffset - segment->fileoff;
    if (delta >= segment->filesize) return 0;
    return (uintptr_t)(image->slide + (intptr_t)segment->vmaddr + delta);
}

static NSString *DHSymbolName(const char *strings, uint32_t stringSize, uint32_t index) {
    if (!strings || index >= stringSize) return @"";
    const char *name = strings + index;
    size_t max = stringSize - index;
    size_t length = strnlen(name, max);
    if (length == max) return @"";
    return [NSString stringWithUTF8String:name] ?: @"";
}

static BOOL DHReadSymbols(const DHMachO *image, const struct nlist_64 **symbols, uint32_t *count, const char **strings, uint32_t *stringSize) {
    if (!image || !image->symtab || !symbols || !count || !strings || !stringSize) return NO;
    uintptr_t symAddress = DHLinkeditAddress(image, image->symtab->symoff);
    uintptr_t stringAddress = DHLinkeditAddress(image, image->symtab->stroff);
    if (!symAddress || !stringAddress || image->symtab->nsyms > 1000000 || image->symtab->strsize > 64 * 1024 * 1024) return NO;
    *symbols = (const struct nlist_64 *)symAddress;
    *count = image->symtab->nsyms;
    *strings = (const char *)stringAddress;
    *stringSize = image->symtab->strsize;
    return YES;
}

static NSString *DHHexAddress(uint64_t address) {
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)address];
}

static NSDictionary *DHBasicImageInfo(const DHMachO *image) {
    const struct mach_header_64 *header = image->header;
    NSMutableArray *segments = [NSMutableArray array];
    uintptr_t cursor = (uintptr_t)image->commands;
    uintptr_t end = cursor + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > end - cursor) break;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            [segments addObject:@{ @"name": [NSString stringWithUTF8String:segment->segname] ?: @"",
                                  @"vmAddress": DHHexAddress(segment->vmaddr),
                                  @"vmSize": @(segment->vmsize),
                                  @"fileOffset": @(segment->fileoff),
                                  @"fileSize": @(segment->filesize),
                                  @"maxProt": @(segment->maxprot),
                                  @"initProt": @(segment->initprot) }];
        }
        cursor += command->cmdsize;
    }
    NSMutableDictionary *result = [@{
        @"index": @(image->index),
        @"name": image->name ? [NSString stringWithUTF8String:image->name] ?: @"" : @"",
        @"header": [NSString stringWithFormat:@"%p", image->header],
        @"slide": @(image->slide),
        @"fileType": @(header->filetype),
        @"flags": @(header->flags),
        @"cpuType": @(header->cputype),
        @"cpuSubtype": @(header->cpusubtype),
        @"commandCount": @(header->ncmds),
        @"segments": segments
    } mutableCopy];
    if (image->uuid) {
        NSMutableString *uuid = [NSMutableString stringWithCapacity:36];
        for (NSUInteger i = 0; i < sizeof(image->uuid->uuid); i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) [uuid appendString:@"-"];
            [uuid appendFormat:@"%02x", image->uuid->uuid[i]];
        }
        result[@"uuid"] = uuid;
    }
    if (image->text) result[@"textRange"] = @{ @"start": DHHexAddress(image->slide + image->text->vmaddr), @"size": @(image->text->vmsize) };
    if (image->encryption) result[@"encryption"] = @{ @"cryptoff": @(image->encryption->cryptoff), @"cryptsize": @(image->encryption->cryptsize), @"cryptid": @(image->encryption->cryptid) };
    if (image->symtab) result[@"symbols"] = @{ @"count": @(image->symtab->nsyms), @"stringSize": @(image->symtab->strsize) };
    return result;
}

NSDictionary *DHImageMachOInfo(NSString *selector) {
    DHImageRef ref; DHMachO image;
    return DHFindImage(selector, &ref) && DHParseImage(ref, &image) ? DHBasicImageInfo(&image) : @{ @"error": @"loaded image not found or unsupported" };
}

NSArray<NSDictionary *> *DHImageImports(NSString *selector, NSUInteger limit) {
    DHImageRef ref; DHMachO image; if (!DHFindImage(selector, &ref) || !DHParseImage(ref, &image)) return @[];
    const struct nlist_64 *symbols; uint32_t count; const char *strings; uint32_t stringSize;
    if (!DHReadSymbols(&image, &symbols, &count, &strings, &stringSize)) return @[];
    NSMutableArray *items = [NSMutableArray array]; NSUInteger max = MIN(MAX(limit ?: 1000, 1), 10000);
    for (uint32_t i = 0; i < count && items.count < max; i++) {
        uint8_t type = symbols[i].n_type & N_TYPE;
        if (type != N_UNDF || !(symbols[i].n_type & N_EXT)) continue;
        NSString *name = DHSymbolName(strings, stringSize, symbols[i].n_un.n_strx);
        if (!name.length) continue;
        [items addObject:@{ @"name": name, @"index": @(i), @"type": @(symbols[i].n_type), @"libraryOrdinal": @(symbols[i].n_desc & 0x0fff) }];
    }
    return items;
}

NSArray<NSDictionary *> *DHImageFunctions(NSString *selector, NSUInteger limit) {
    DHImageRef ref; DHMachO image; if (!DHFindImage(selector, &ref) || !DHParseImage(ref, &image)) return @[];
    const struct nlist_64 *symbols; uint32_t count; const char *strings; uint32_t stringSize;
    if (!DHReadSymbols(&image, &symbols, &count, &strings, &stringSize)) return @[];
    NSMutableArray *items = [NSMutableArray array]; NSUInteger max = MIN(MAX(limit ?: 1000, 1), 10000);
    for (uint32_t i = 0; i < count && items.count < max; i++) {
        uint8_t type = symbols[i].n_type & N_TYPE;
        if (type != N_SECT || symbols[i].n_value == 0) continue;
        NSString *name = DHSymbolName(strings, stringSize, symbols[i].n_un.n_strx);
        if (!name.length || [name hasPrefix:@"$"] || [name hasPrefix:@"ltmp"] || [name hasPrefix:@"L"] ) continue;
        uint64_t address = (uint64_t)(image.slide + symbols[i].n_value);
        [items addObject:@{ @"name": name, @"address": DHHexAddress(address), @"symbolIndex": @(i), @"external": @((symbols[i].n_type & N_EXT) != 0) }];
    }
    [items sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        unsigned long long left = strtoull([a[@"address"] UTF8String], NULL, 16);
        unsigned long long right = strtoull([b[@"address"] UTF8String], NULL, 16);
        if (left < right) return NSOrderedAscending;
        if (left > right) return NSOrderedDescending;
        return NSOrderedSame;
    }];
    if (items.count > max) return [items subarrayWithRange:NSMakeRange(0, max)];
    return items;
}

NSDictionary *DHDisassembleFunction(NSString *selector, NSString *symbolOrAddress, NSUInteger instructionLimit) {
    DHImageRef ref; DHMachO image; if (!DHFindImage(selector, &ref) || !DHParseImage(ref, &image)) return @{ @"error": @"loaded image not found or unsupported" };
    uint64_t target = 0; NSString *symbolName = symbolOrAddress;
    if ([symbolOrAddress hasPrefix:@"0x"] || [symbolOrAddress hasPrefix:@"0X"]) target = strtoull(symbolOrAddress.UTF8String, NULL, 16);
    if (!target && symbolOrAddress.length) {
        for (NSDictionary *item in DHImageFunctions(selector, 10000)) if ([item[@"name"] isEqualToString:symbolOrAddress]) { target = strtoull([item[@"address"] UTF8String], NULL, 16); break; }
    }
    if (!target) return @{ @"error": @"symbol or address not found" };
    if (target < (uint64_t)image.slide || !image.text || target < image.slide + image.text->vmaddr || target >= image.slide + image.text->vmaddr + image.text->vmsize) return @{ @"error": @"address is outside the image text segment" };
    NSUInteger max = MIN(MAX(instructionLimit ?: 32, 1), 256);
    NSMutableArray *instructions = [NSMutableArray array]; const uint8_t *bytes = (const uint8_t *)(uintptr_t)target;
    NSUInteger byteLength = MIN(max * 4, (NSUInteger)((image.slide + image.text->vmaddr + image.text->vmsize) - target));
    csh handle = 0;
    cs_insn *decoded = NULL;
    cs_err openError = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
    if (openError != CS_ERR_OK) return @{ @"error": [NSString stringWithFormat:@"Capstone open failed: %u", openError] };
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    size_t count = cs_disasm(handle, bytes, byteLength, target, max, &decoded);
    for (size_t i = 0; i < count; i++) {
        cs_insn *insn = &decoded[i];
        NSMutableString *raw = [NSMutableString stringWithCapacity:insn->size * 2];
        for (uint8_t b = 0; b < insn->size; b++) [raw appendFormat:@"%02x", insn->bytes[b]];
        [instructions addObject:@{ @"address": DHHexAddress(insn->address), @"bytes": raw, @"mnemonic": [NSString stringWithUTF8String:insn->mnemonic] ?: @"", @"opStr": [NSString stringWithUTF8String:insn->op_str] ?: @"" }];
    }
    if (decoded) cs_free(decoded, count);
    cs_close(&handle);
    return @{ @"image": image.name ? [NSString stringWithUTF8String:image.name] ?: @"" : @"", @"symbol": symbolName ?: @"", @"address": DHHexAddress(target), @"instructions": instructions };
}
