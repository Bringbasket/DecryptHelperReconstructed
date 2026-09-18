#import "DHAnalysis.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

typedef struct {
    uint32_t index;
    const struct mach_header_64 *header;
    intptr_t slide;
    const char *name;
} DHAnalysisImage;

typedef struct {
    DHAnalysisImage image;
    const struct symtab_command *symtab;
    const struct segment_command_64 *linkedit;
    const struct segment_command_64 *text;
} DHAnalysisMachO;

static NSString *DHAnalysisString(const char *value) {
    return value ? [NSString stringWithUTF8String:value] ?: @"" : @"";
}

static NSString *DHAnalysisHex(uint64_t value) {
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)value];
}

static BOOL DHAnalysisParseAddress(NSString *value, uint64_t *address) {
    if (!address || ![value isKindOfClass:NSString.class] || !value.length) return NO;
    NSString *trimmed = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!trimmed.length) return NO;
    const char *text = trimmed.UTF8String;
    if (!text || !*text) return NO;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (end == text || (end && *end != '\0') || errno == ERANGE) return NO;
    *address = (uint64_t)parsed;
    return YES;
}

static BOOL DHAnalysisIs64(const struct mach_header *header) {
    return header && (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64);
}

static BOOL DHAnalysisFindImage(NSString *selector, DHAnalysisImage *result) {
    NSString *wanted = selector.length ? selector : nil;
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        const char *name = _dyld_get_image_name(index);
        if (!DHAnalysisIs64(header)) continue;
        NSString *path = DHAnalysisString(name);
        BOOL numeric = wanted.length > 0;
        for (NSUInteger i = 0; i < wanted.length; i++) {
            unichar c = [wanted characterAtIndex:i];
            if (c < '0' || c > '9') { numeric = NO; break; }
        }
        BOOL match = !wanted || (numeric && index == wanted.integerValue) ||
            [path isEqualToString:wanted] || [path.lastPathComponent isEqualToString:wanted] ||
            [path hasSuffix:wanted];
        if (!match) continue;
        if (result) *result = (DHAnalysisImage){ index, (const struct mach_header_64 *)header,
            _dyld_get_image_vmaddr_slide(index), name };
        return YES;
    }
    return NO;
}

static BOOL DHAnalysisParse(DHAnalysisImage image, DHAnalysisMachO *out) {
    if (!out || !image.header) return NO;
    memset(out, 0, sizeof(*out));
    out->image = image;
    uintptr_t cursor = (uintptr_t)image.header + sizeof(struct mach_header_64);
    uintptr_t end = cursor + image.header->sizeofcmds;
    if (end < cursor || image.header->ncmds > 4096) return NO;
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        if (cursor > end || end - cursor < sizeof(struct load_command)) return NO;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > end - cursor) return NO;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__LINKEDIT", sizeof(segment->segname)) == 0) out->linkedit = segment;
            if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) == 0) out->text = segment;
        } else if (command->cmd == LC_SYMTAB) {
            out->symtab = (const struct symtab_command *)command;
        }
        cursor += command->cmdsize;
    }
    return YES;
}

static NSArray<NSValue *> *DHAnalysisSegments(DHAnalysisMachO *image) {
    NSMutableArray *segments = [NSMutableArray array];
    uintptr_t cursor = (uintptr_t)image->image.header + sizeof(struct mach_header_64);
    uintptr_t end = cursor + image->image.header->sizeofcmds;
    for (uint32_t i = 0; i < image->image.header->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > end - cursor) break;
        if (command->cmd == LC_SEGMENT_64) [segments addObject:[NSValue valueWithPointer:command]];
        cursor += command->cmdsize;
    }
    return segments;
}

static const struct segment_command_64 *DHAnalysisFindSegment(DHAnalysisMachO *image, uint64_t address, NSString **name) {
    for (NSValue *value in DHAnalysisSegments(image)) {
        const struct segment_command_64 *segment = value.pointerValue;
        uint64_t start = (uint64_t)(image->image.slide + (intptr_t)segment->vmaddr);
        uint64_t end = start + segment->vmsize;
        if (end >= start && address >= start && address < end) {
            if (name) *name = DHAnalysisString(segment->segname);
            return segment;
        }
    }
    return NULL;
}

static uintptr_t DHAnalysisLinkeditAddress(DHAnalysisMachO *image, uint32_t offset) {
    const struct segment_command_64 *segment = image->linkedit;
    if (!segment || offset < segment->fileoff) return 0;
    uint64_t delta = (uint64_t)offset - segment->fileoff;
    if (delta >= segment->filesize) return 0;
    return (uintptr_t)(image->image.slide + (intptr_t)segment->vmaddr + delta);
}

static BOOL DHAnalysisSymbols(DHAnalysisMachO *image, const struct nlist_64 **symbols,
                              uint32_t *count, const char **strings, uint32_t *stringSize) {
    if (!image->symtab || !symbols || !count || !strings || !stringSize) return NO;
    uintptr_t symbolAddress = DHAnalysisLinkeditAddress(image, image->symtab->symoff);
    uintptr_t stringAddress = DHAnalysisLinkeditAddress(image, image->symtab->stroff);
    if (!symbolAddress || !stringAddress || image->symtab->nsyms > 1000000 || image->symtab->strsize > 64 * 1024 * 1024) return NO;
    *symbols = (const struct nlist_64 *)symbolAddress;
    *count = image->symtab->nsyms;
    *strings = (const char *)stringAddress;
    *stringSize = image->symtab->strsize;
    return YES;
}

static NSString *DHAnalysisSymbolName(const char *strings, uint32_t size, uint32_t index) {
    if (!strings || index >= size) return @"";
    size_t max = size - index;
    size_t length = strnlen(strings + index, max);
    return length < max ? DHAnalysisString(strings + index) : @"";
}

static NSDictionary *DHAnalysisReadBytes(uint64_t address, NSUInteger length) {
    const NSUInteger maxLength = 1024 * 1024;
    if (!address) return @{ @"error": @"address must be non-zero" };
    if (!length || length > maxLength) return @{ @"error": @"length must be between 1 and 1048576" };
    NSMutableData *data = [NSMutableData dataWithLength:length];
    vm_size_t outSize = 0;
    kern_return_t status = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                               (vm_size_t)length, (vm_address_t)data.mutableBytes, &outSize);
    if (status != KERN_SUCCESS || !outSize) {
        return @{ @"address": DHAnalysisHex(address), @"length": @(length),
                  @"read": @0, @"machError": @(status), @"error": @"memory read failed" };
    }
    if (outSize < data.length) [data setLength:outSize];
    const uint8_t *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) [hex appendFormat:@"%02x", bytes[i]];
    NSMutableDictionary *result = [@{
        @"address": DHAnalysisHex(address), @"length": @(length), @"read": @(data.length),
        @"hex": hex, @"base64": [data base64EncodedStringWithOptions:0]
    } mutableCopy];
    if (data.length != length) result[@"partial"] = @YES;
    return result;
}

NSDictionary<NSString *, id> *DHReadMemory(uint64_t address, NSUInteger length) {
    return DHAnalysisReadBytes(address, length);
}

static NSData *DHAnalysisPattern(NSString *pattern, NSString *encoding) {
    if (![pattern isKindOfClass:NSString.class] || !pattern.length) return nil;
    NSString *mode = encoding.lowercaseString ?: @"utf8";
    if ([mode isEqualToString:@"hex"]) {
        NSMutableString *clean = [NSMutableString stringWithCapacity:pattern.length];
        for (NSUInteger i = 0; i < pattern.length; i++) {
            unichar c = [pattern characterAtIndex:i];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                [clean appendFormat:@"%C", c];
            } else if (![[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:c] && c != ':' && c != '-') {
                return nil;
            }
        }
        if (!clean.length || clean.length % 2) return nil;
        NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
        for (NSUInteger i = 0; i < clean.length; i += 2) {
            unichar high = [clean characterAtIndex:i];
            unichar low = [clean characterAtIndex:i + 1];
            unsigned highValue = high <= '9' ? high - '0' : (high | 0x20) - 'a' + 10;
            unsigned lowValue = low <= '9' ? low - '0' : (low | 0x20) - 'a' + 10;
            uint8_t byte = (uint8_t)((highValue << 4) | lowValue);
            [data appendBytes:&byte length:1];
        }
        return data;
    }
    NSStringEncoding stringEncoding = [mode isEqualToString:@"ascii"] ? NSASCIIStringEncoding : NSUTF8StringEncoding;
    return [pattern dataUsingEncoding:stringEncoding allowLossyConversion:NO];
}

static NSUInteger DHAnalysisLimit(NSUInteger limit, NSUInteger fallback, NSUInteger max) {
    return MIN(MAX(limit ?: fallback, 1), max);
}

static void DHAnalysisAppendMatch(NSMutableArray *matches, uint64_t address, NSUInteger offset,
                                  NSString *image, NSString *segment, NSUInteger limit) {
    if (matches.count >= limit) return;
    [matches addObject:@{ @"address": DHAnalysisHex(address), @"offset": @(offset),
                         @"image": image ?: @"", @"segment": segment ?: @"" }];
}

NSArray<NSDictionary<NSString *, id> *> *DHSearchMemory(NSString *selector, NSString *pattern,
                                                         NSString *encoding, NSUInteger limit) {
    NSData *needle = DHAnalysisPattern(pattern, encoding);
    NSUInteger max = DHAnalysisLimit(limit, 100, 2000);
    if (!needle.length || needle.length > 1024) return @[];
    NSMutableArray *matches = [NSMutableArray array];
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount && matches.count < max; index++) {
        DHAnalysisImage ref;
        if (!DHAnalysisFindImage(selector.length ? selector : [NSString stringWithFormat:@"%u", index], &ref)) continue;
        DHAnalysisMachO image;
        if (!DHAnalysisParse(ref, &image)) continue;
        NSString *imageName = DHAnalysisString(ref.name);
        for (NSValue *value in DHAnalysisSegments(&image)) {
            const struct segment_command_64 *segment = value.pointerValue;
            if (!(segment->initprot & VM_PROT_READ) || !segment->vmsize) continue;
            NSUInteger segmentSize = (NSUInteger)MIN((uint64_t)segment->vmsize, (uint64_t)(128 * 1024 * 1024));
            uint64_t start = (uint64_t)(ref.slide + (intptr_t)segment->vmaddr);
            NSMutableData *buffer = [NSMutableData dataWithLength:segmentSize];
            vm_size_t read = 0;
            kern_return_t status = vm_read_overwrite(mach_task_self(), (vm_address_t)start, (vm_size_t)segmentSize,
                                                      (vm_address_t)buffer.mutableBytes, &read);
            if (status != KERN_SUCCESS || read < needle.length) continue;
            const uint8_t *bytes = buffer.bytes;
            NSUInteger end = (NSUInteger)read - needle.length;
            for (NSUInteger offset = 0; offset <= end && matches.count < max; offset++) {
                if (memcmp(bytes + offset, needle.bytes, needle.length) == 0) {
                    DHAnalysisAppendMatch(matches, start + offset, offset, imageName, DHAnalysisString(segment->segname), max);
                }
            }
        }
        if (selector.length) break;
    }
    return matches;
}

static BOOL DHAnalysisResolveSymbol(DHAnalysisMachO *image, NSString *name, uint64_t *address) {
    const struct nlist_64 *symbols; uint32_t count; const char *strings; uint32_t stringSize;
    if (!DHAnalysisSymbols(image, &symbols, &count, &strings, &stringSize)) return NO;
    for (uint32_t i = 0; i < count; i++) {
        NSString *symbol = DHAnalysisSymbolName(strings, stringSize, symbols[i].n_un.n_strx);
        if ([symbol isEqualToString:name] || [symbol hasSuffix:name]) {
            if (address) *address = (uint64_t)(image->image.slide + symbols[i].n_value);
            return symbols[i].n_value != 0;
        }
    }
    return NO;
}

NSDictionary<NSString *, id> *DHSymbolicateAddress(uint64_t address, NSString *selector) {
    if (!address) return @{ @"error": @"address must be non-zero" };
    Dl_info info = {0};
    dladdr((const void *)(uintptr_t)address, &info);
    NSMutableDictionary *result = [@{ @"address": DHAnalysisHex(address) } mutableCopy];
    if (info.dli_fname) result[@"image"] = DHAnalysisString(info.dli_fname);
    if (info.dli_sname) {
        result[@"symbol"] = DHAnalysisString(info.dli_sname);
        result[@"symbolAddress"] = DHAnalysisHex((uint64_t)(uintptr_t)info.dli_saddr);
        result[@"offset"] = @((uint64_t)address - (uint64_t)(uintptr_t)info.dli_saddr);
    }
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        DHAnalysisImage ref;
        if (!DHAnalysisFindImage(selector.length ? selector : [NSString stringWithFormat:@"%u", i], &ref)) continue;
        DHAnalysisMachO image;
        if (!DHAnalysisParse(ref, &image)) continue;
        NSString *segmentName = nil;
        if (!DHAnalysisFindSegment(&image, address, &segmentName)) {
            if (selector.length) break;
            continue;
        }
        result[@"image"] = DHAnalysisString(ref.name);
        result[@"imageIndex"] = @(ref.index);
        result[@"slide"] = @(ref.slide);
        result[@"segment"] = segmentName ?: @"";
        const struct nlist_64 *symbols; uint32_t count; const char *strings; uint32_t stringSize;
        if (DHAnalysisSymbols(&image, &symbols, &count, &strings, &stringSize)) {
            uint64_t unslid = address - ref.slide;
            uint64_t best = 0; NSString *bestName = nil;
            for (uint32_t s = 0; s < count; s++) {
                if (!symbols[s].n_value || symbols[s].n_value > unslid) continue;
                NSString *name = DHAnalysisSymbolName(strings, stringSize, symbols[s].n_un.n_strx);
                if (name.length && symbols[s].n_value >= best) { best = symbols[s].n_value; bestName = name; }
            }
            if (bestName.length) {
                result[@"symbol"] = bestName;
                result[@"symbolAddress"] = DHAnalysisHex((uint64_t)(ref.slide + best));
                result[@"offset"] = @(unslid - best);
            }
        }
        if (selector.length) break;
    }
    if (!result[@"image"]) result[@"error"] = @"address is not in a loaded image";
    return result;
}

static BOOL DHAnalysisTargetAddress(DHAnalysisMachO *image, NSString *target, uint64_t *address) {
    uint64_t parsed = 0;
    if (DHAnalysisParseAddress(target, &parsed)) { if (address) *address = parsed; return YES; }
    return DHAnalysisResolveSymbol(image, target, address);
}

NSArray<NSDictionary<NSString *, id> *> *DHFindXrefs(NSString *selector, NSString *target, NSUInteger limit) {
    NSUInteger max = DHAnalysisLimit(limit, 100, 2000);
    NSMutableArray *matches = [NSMutableArray array];
    uint64_t targetAddress = 0;
    DHAnalysisImage ref;
    if (DHAnalysisFindImage(selector, &ref)) {
        DHAnalysisMachO image;
        if (DHAnalysisParse(ref, &image) && DHAnalysisTargetAddress(&image, target, &targetAddress)) {
            for (NSValue *value in DHAnalysisSegments(&image)) {
                const struct segment_command_64 *segment = value.pointerValue;
                if (!(segment->initprot & VM_PROT_READ) || !segment->vmsize) continue;
                NSUInteger size = (NSUInteger)MIN((uint64_t)segment->vmsize, (uint64_t)(128 * 1024 * 1024));
                uint64_t start = (uint64_t)(ref.slide + (intptr_t)segment->vmaddr);
                NSMutableData *buffer = [NSMutableData dataWithLength:size]; vm_size_t read = 0;
                if (vm_read_overwrite(mach_task_self(), (vm_address_t)start, (vm_size_t)size,
                                      (vm_address_t)buffer.mutableBytes, &read) != KERN_SUCCESS) continue;
                const uint8_t *bytes = buffer.bytes;
                for (NSUInteger offset = 0; offset + sizeof(uint64_t) <= read && matches.count < max; offset++) {
                    uint64_t value64 = 0; memcpy(&value64, bytes + offset, sizeof(value64));
                    if (value64 == targetAddress) {
                        [matches addObject:@{ @"address": DHAnalysisHex(start + offset), @"target": DHAnalysisHex(targetAddress),
                                             @"kind": @"pointer", @"image": DHAnalysisString(ref.name), @"segment": DHAnalysisString(segment->segname) }];
                    }
                }
            }
            return matches;
        }
        NSData *needle = DHAnalysisPattern([target hasPrefix:@"str:"] ? [target substringFromIndex:4] : target, @"utf8");
        if (!needle.length) return @[];
        for (NSValue *value in DHAnalysisSegments(&image)) {
            const struct segment_command_64 *segment = value.pointerValue;
            if (!(segment->initprot & VM_PROT_READ) || !segment->vmsize) continue;
            NSUInteger size = (NSUInteger)MIN((uint64_t)segment->vmsize, (uint64_t)(128 * 1024 * 1024));
            uint64_t start = (uint64_t)(ref.slide + (intptr_t)segment->vmaddr);
            NSMutableData *buffer = [NSMutableData dataWithLength:size]; vm_size_t read = 0;
            if (vm_read_overwrite(mach_task_self(), (vm_address_t)start, (vm_size_t)size,
                                  (vm_address_t)buffer.mutableBytes, &read) != KERN_SUCCESS) continue;
            const uint8_t *bytes = buffer.bytes;
            for (NSUInteger offset = 0; offset + needle.length <= read && matches.count < max; offset++) {
                if (memcmp(bytes + offset, needle.bytes, needle.length) == 0)
                    [matches addObject:@{ @"address": DHAnalysisHex(start + offset), @"kind": @"string",
                                         @"image": DHAnalysisString(ref.name), @"segment": DHAnalysisString(segment->segname) }];
            }
        }
    }
    return matches;
}

static NSDictionary *DHAnalysisMethod(Method method, BOOL classMethod) {
    SEL selector = method_getName(method);
    IMP implementation = method_getImplementation(method);
    Dl_info info = {0}; dladdr((const void *)(uintptr_t)implementation, &info);
    NSMutableDictionary *result = [@{
        @"selector": NSStringFromSelector(selector) ?: @"",
        @"types": [NSString stringWithUTF8String:method_getTypeEncoding(method) ?: ""] ?: @"",
        @"implementation": DHAnalysisHex((uint64_t)(uintptr_t)implementation),
        @"classMethod": @(classMethod)
    } mutableCopy];
    if (info.dli_sname) result[@"symbol"] = DHAnalysisString(info.dli_sname);
    return result;
}

NSArray<NSDictionary<NSString *, id> *> *DHObjCClassList(NSString *contains, NSUInteger limit) {
    NSUInteger max = DHAnalysisLimit(limit, 200, 5000);
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return @[];
    Class *classes = (Class *)malloc(sizeof(Class) * (size_t)count);
    if (!classes) return @[];
    count = objc_getClassList(classes, count);
    NSMutableArray *result = [NSMutableArray array];
    for (int i = 0; i < count && result.count < max; i++) {
        NSString *name = NSStringFromClass(classes[i]);
        if (contains.length && ![name localizedCaseInsensitiveContainsString:contains]) continue;
        [result addObject:@{ @"class": name ?: @"", @"superclass": classes[i] && class_getSuperclass(classes[i]) ? NSStringFromClass(class_getSuperclass(classes[i])) : @"",
                            @"image": DHAnalysisString(class_getImageName(classes[i])), @"instanceSize": @(class_getInstanceSize(classes[i])) }];
    }
    free(classes);
    [result sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [a[@"class"] compare:b[@"class"]]; }];
    return result;
}

static NSArray *DHAnalysisMethodList(Class cls, BOOL classMethod, NSUInteger limit) {
    unsigned int count = 0; Method *methods = class_copyMethodList(classMethod ? object_getClass(cls) : cls, &count);
    NSMutableArray *result = [NSMutableArray array];
    NSUInteger max = DHAnalysisLimit(limit, 500, 2000);
    for (unsigned int i = 0; i < count && result.count < max; i++) [result addObject:DHAnalysisMethod(methods[i], classMethod)];
    if (methods) free(methods);
    [result sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [a[@"selector"] compare:b[@"selector"]]; }];
    return result;
}

NSDictionary<NSString *, id> *DHObjCClassInfo(NSString *className, NSUInteger methodLimit) {
    Class cls = className.length ? NSClassFromString(className) : Nil;
    if (!cls) return @{ @"error": @"Objective-C class not found" };
    NSMutableDictionary *result = [@{
        @"class": NSStringFromClass(cls),
        @"superclass": class_getSuperclass(cls) ? NSStringFromClass(class_getSuperclass(cls)) : @"",
        @"image": DHAnalysisString(class_getImageName(cls)),
        @"instanceSize": @(class_getInstanceSize(cls)),
        @"methods": DHAnalysisMethodList(cls, NO, methodLimit),
        @"classMethods": DHAnalysisMethodList(cls, YES, methodLimit)
    } mutableCopy];
    unsigned int propertyCount = 0; objc_property_t *properties = class_copyPropertyList(cls, &propertyCount);
    NSMutableArray *propertyResult = [NSMutableArray array];
    for (unsigned int i = 0; i < propertyCount; i++) [propertyResult addObject:@{ @"name": DHAnalysisString(property_getName(properties[i])), @"attributes": DHAnalysisString(property_getAttributes(properties[i])) }];
    if (properties) free(properties);
    result[@"properties"] = propertyResult;
    unsigned int protocolCount = 0; Protocol *__unsafe_unretained *protocols = class_copyProtocolList(cls, &protocolCount);
    NSMutableArray *protocolResult = [NSMutableArray array];
    for (unsigned int i = 0; i < protocolCount; i++) [protocolResult addObject:DHAnalysisString(protocol_getName(protocols[i]))];
    if (protocols) free(protocols);
    result[@"protocols"] = protocolResult;
    return result;
}
