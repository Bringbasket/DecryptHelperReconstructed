#import "DHFileBrowser.h"
#import <sys/stat.h>

static NSUInteger const kDHFileBrowserDefaultLimit = 500;
static NSUInteger const kDHFileBrowserMaxLimit = 2000;
static NSUInteger const kDHFileBrowserMaxRead = 1024 * 1024;

static BOOL DHFileBrowserContainsNUL(NSString *value) {
    NSData *encoded = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSData *nulByte = [NSData dataWithBytes:"\0" length:1];
    return encoded && [encoded rangeOfData:nulByte options:0 range:NSMakeRange(0, encoded.length)].location != NSNotFound;
}

static BOOL DHFileBrowserSensitive(NSString *path) {
    NSString *lower = path.lowercaseString;
    NSArray *parts = [lower pathComponents];
    for (NSString *part in parts) {
        if ([part isEqualToString:@".ssh"] || [part isEqualToString:@"keychain"] ||
            [part isEqualToString:@"credentials"] || [part isEqualToString:@"secrets"]) return YES;
    }
    NSString *extension = lower.pathExtension;
    if ([extension isEqualToString:@"pem"] || [extension isEqualToString:@"p12"] ||
        [extension isEqualToString:@"pfx"] || [extension isEqualToString:@"key"] ||
        [extension isEqualToString:@"mobileprovision"]) return YES;
    for (NSString *needle in @[@"password", @"passwd", @"token", @"private_key", @"secret"]) {
        if ([lower.lastPathComponent containsString:needle]) return YES;
    }
    return NO;
}

static NSString *DHFileBrowserRoot(void) {
    return [NSHomeDirectory() stringByStandardizingPath];
}

static NSString *DHFileBrowserPath(NSString *relativePath, BOOL requireExisting, NSError **error) {
    NSString *root = DHFileBrowserRoot();
    NSString *input = [relativePath isKindOfClass:NSString.class] ? relativePath : @"";
    if ([input hasPrefix:@"~"] || DHFileBrowserContainsNUL(input)) {
        if (error) *error = [NSError errorWithDomain:@"DHFileBrowser" code:1 userInfo:@{NSLocalizedDescriptionKey: @"invalid sandbox path"}];
        return nil;
    }
    NSString *candidate = [input hasPrefix:@"/"] ? input : [root stringByAppendingPathComponent:input];
    candidate = [candidate stringByStandardizingPath];
    NSString *resolved = requireExisting ? [candidate stringByResolvingSymlinksInPath] : candidate;
    NSString *prefix = [root stringByAppendingString:@"/"];
    if (![resolved isEqualToString:root] && ![resolved hasPrefix:prefix]) {
        if (error) *error = [NSError errorWithDomain:@"DHFileBrowser" code:2 userInfo:@{NSLocalizedDescriptionKey: @"path escapes the app sandbox"}];
        return nil;
    }
    NSString *relative = [resolved isEqualToString:root] ? @"" : [resolved substringFromIndex:prefix.length];
    if (DHFileBrowserSensitive(relative)) {
        if (error) *error = [NSError errorWithDomain:@"DHFileBrowser" code:3 userInfo:@{NSLocalizedDescriptionKey: @"sensitive sandbox path is restricted"}];
        return nil;
    }
    if (requireExisting && ![[NSFileManager defaultManager] fileExistsAtPath:resolved]) {
        if (error) *error = [NSError errorWithDomain:@"DHFileBrowser" code:4 userInfo:@{NSLocalizedDescriptionKey: @"sandbox path was not found"}];
        return nil;
    }
    return resolved;
}

NSString *DHSandboxFilePath(NSString *relativePath, NSError **error) {
    return DHFileBrowserPath(relativePath, YES, error);
}

NSArray<NSDictionary<NSString *, id> *> *DHListSandboxFiles(NSString *relativePath, NSUInteger limit) {
    NSError *error = nil;
    NSString *path = DHFileBrowserPath(relativePath, YES, &error);
    if (!path) return @[@{ @"error": error.localizedDescription ?: @"invalid path" }];
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&error];
    if (!attributes) return @[@{ @"error": error.localizedDescription ?: @"path is unavailable" }];
    if (![attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) {
        return @[@{ @"path": relativePath ?: @"", @"type": attributes[NSFileType] ?: @"file",
                    @"size": attributes[NSFileSize] ?: @0 }];
    }
    NSUInteger maximum = MIN(MAX(limit ?: kDHFileBrowserDefaultLimit, 1), kDHFileBrowserMaxLimit);
    NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:&error];
    if (!names) return @[@{ @"error": error.localizedDescription ?: @"directory is unavailable" }];
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *name in [names sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *child = [path stringByAppendingPathComponent:name];
        NSString *root = DHFileBrowserRoot();
        NSString *relative = [child isEqualToString:root] ? @"" : [child substringFromIndex:root.length + 1];
        if (DHFileBrowserSensitive(relative)) continue;
        NSDictionary *item = [[NSFileManager defaultManager] attributesOfItemAtPath:child error:nil];
        if (!item) continue;
        [result addObject:@{ @"name": name, @"path": relative, @"type": item[NSFileType] ?: @"unknown",
                            @"size": item[NSFileSize] ?: @0,
                            @"modifiedMs": @([item[NSFileModificationDate] timeIntervalSince1970] * 1000.0) }];
        if (result.count >= maximum) break;
    }
    return result;
}

NSDictionary<NSString *, id> *DHReadSandboxFile(NSString *relativePath, NSUInteger maxBytes) {
    NSError *error = nil;
    NSString *path = DHFileBrowserPath(relativePath, YES, &error);
    if (!path) return @{ @"error": error.localizedDescription ?: @"invalid path" };
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&error];
    if (!attributes || ![attributes[NSFileType] isEqualToString:NSFileTypeRegular]) {
        return @{ @"error": error.localizedDescription ?: @"only regular files can be previewed" };
    }
    NSUInteger length = MIN(maxBytes ?: kDHFileBrowserMaxRead, kDHFileBrowserMaxRead);
    uint64_t fileSize = [attributes[NSFileSize] unsignedLongLongValue];
    if (fileSize > kDHFileBrowserMaxRead * 64ULL) return @{ @"error": @"file exceeds preview size limit" };
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&error];
    if (!data) return @{ @"error": error.localizedDescription ?: @"file could not be read" };
    NSData *preview = data.length > length ? [data subdataWithRange:NSMakeRange(0, length)] : data;
    NSString *text = [[NSString alloc] initWithData:preview encoding:NSUTF8StringEncoding];
    NSMutableDictionary *result = [@{ @"path": relativePath ?: @"", @"size": @(data.length),
                                      @"read": @(preview.length), @"truncated": @(preview.length < data.length),
                                      @"base64": [preview base64EncodedStringWithOptions:0] } mutableCopy];
    if (text) result[@"text"] = text;
    return result;
}
