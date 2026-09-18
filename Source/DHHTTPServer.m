#import "DHHTTPServer.h"
#import "DHConfig.h"
#import "DHImageInventory.h"
#import "DHDisassembler.h"
#import "DHDump.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import "DHAnalysis.h"
#import "DHWebConsole.h"
#import <arpa/inet.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <stdlib.h>

static int gListenSocket = -1;
static uint16_t gHTTPPort;
static NSString * const kDHEngineVersion = @"0.4.0";

static NSDictionary *DHRuntimeSnapshot(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSProcessInfo *processInfo = NSProcessInfo.processInfo;
    return @{
        @"version": kDHEngineVersion,
        @"port": @(gHTTPPort),
        @"process": @{
            @"bundleId": bundle.bundleIdentifier ?: @"",
            @"name": processInfo.processName ?: @"",
            @"pid": @(processInfo.processIdentifier)
        },
        @"eventCount": @([DHLogStore shared].totalCount),
        @"noiseCount": @([DHLogStore shared].noiseCount),
        @"imageCount": @(DHLoadedImageSnapshot().count),
        @"dumpTaskCount": @([DHDumpManager sharedManager].taskSnapshots.count),
        @"config": [[DHConfig shared] publicSnapshot]
    };
}

static NSUInteger DHBoundedLimit(NSString *value, NSUInteger fallback, NSUInteger maximum) {
    NSInteger parsed = value.integerValue;
    if (parsed <= 0) return fallback;
    return MIN((NSUInteger)parsed, maximum);
}

static BOOL DHParseHTTPAddress(NSString *value, uint64_t *address) {
    if (!address || ![value isKindOfClass:NSString.class] || !value.length) return NO;
    NSString *trimmed = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    const char *text = trimmed.UTF8String;
    if (!text || !*text) return NO;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (end == text || (end && *end != '\0')) return NO;
    *address = (uint64_t)parsed;
    return YES;
}

static NSString *DHQueryValue(NSString *target, NSString *key) {
    NSRange question = [target rangeOfString:@"?"];
    if (question.location == NSNotFound) return nil;
    NSString *query = [target substringFromIndex:question.location + 1];
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        NSArray *parts = [pair componentsSeparatedByString:@"="];
        if (parts.count < 2 || ![parts[0] isEqualToString:key]) continue;
        NSArray *valueParts = [parts subarrayWithRange:NSMakeRange(1, parts.count - 1)];
        NSString *encoded = [valueParts componentsJoinedByString:@"="];
        return [encoded stringByRemovingPercentEncoding] ?: encoded;
    }
    return nil;
}

static NSDictionary<NSString *, id> *DHEventFiltersFromTarget(NSString *target, NSUInteger fallbackLimit) {
    NSMutableDictionary *filters = [NSMutableDictionary dictionary];
    for (NSString *key in @[@"category", @"algorithm", @"operation", @"threadId", @"sinceMs", @"untilMs",
                              @"afterSeq", @"beforeSeq", @"stack", @"contains", @"requestId", @"contextId", @"order"]) {
        NSString *value = DHQueryValue(target, key);
        if (value.length) filters[key] = value;
    }
    filters[@"limit"] = @(DHBoundedLimit(DHQueryValue(target, @"limit"), fallbackLimit, 2000));
    return filters;
}

static NSArray<NSDictionary<NSString *, id> *> *DHEventSnapshot(NSString *target) {
    NSMutableDictionary *filters = [DHEventFiltersFromTarget(target, 100) mutableCopy];
    filters[@"order"] = @"desc";
    NSArray *latestFirst = [[DHLogStore shared] queryWithFilters:filters noise:NO][@"events"];
    return [[latestFirst reverseObjectEnumerator] allObjects];
}

static NSData *DHJSONLData(NSArray<NSDictionary<NSString *, id> *> *events) {
    NSMutableData *result = [NSMutableData data];
    for (NSDictionary *event in events) {
        NSData *line = [NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
        if (!line) continue;
        [result appendData:line];
        [result appendBytes:"\n" length:1];
    }
    return result;
}

static NSString *DHJSONLString(NSArray<NSDictionary<NSString *, id> *> *events) {
    return [[NSString alloc] initWithData:DHJSONLData(events) encoding:NSUTF8StringEncoding] ?: @"";
}

static BOOL DHSendAll(int socketFD, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    while (length) {
        ssize_t sent = send(socketFD, cursor, length, 0);
        if (sent <= 0) return NO;
        cursor += sent;
        length -= (size_t)sent;
    }
    return YES;
}

static NSData *DHJSONData(id object);

static void DHSendResponse(int socketFD, NSInteger status, NSString *contentType, NSData *body) {
    NSString *reason = status == 200 ? @"OK" : status == 202 ? @"Accepted" : status == 204 ? @"No Content" :
                       status == 400 ? @"Bad Request" : status == 404 ? @"Not Found" :
                       status == 405 ? @"Method Not Allowed" : status == 409 ? @"Conflict" : @"Internal Server Error";
    NSData *payload = body ?: NSData.data;
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 %ld %@\r\nContent-Type: %@\r\nContent-Length: %lu\r\n"
         "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\n"
         "Connection: close\r\n\r\n",
         (long)status, reason, contentType ?: @"application/octet-stream",
         (unsigned long)payload.length];
    NSData *headerData = [header dataUsingEncoding:NSUTF8StringEncoding];
    DHSendAll(socketFD, headerData.bytes, headerData.length);
    if (payload.length) DHSendAll(socketFD, payload.bytes, payload.length);
}

static void DHSendFileResponse(int socketFD, NSString *path) {
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!handle || !attributes) {
        DHSendResponse(socketFD, 404, @"application/json", DHJSONData(@{ @"error": @"dump file not found" }));
        return;
    }
    uint64_t length = [attributes[NSFileSize] unsignedLongLongValue];
    NSString *fileName = [path.lastPathComponent stringByReplacingOccurrencesOfString:@"\"" withString:@""];
    NSString *contentType = ([path.pathExtension.lowercaseString isEqualToString:@"ipa"] ||
                             [path.pathExtension.lowercaseString isEqualToString:@"zip"])
        ? @"application/zip" : @"application/octet-stream";
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 200 OK\r\nContent-Type: %@\r\nContent-Length: %llu\r\n"
         "Content-Disposition: attachment; filename=\"%@\"\r\n"
         "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
         contentType, (unsigned long long)length, fileName ?: @"dump.bin"];
    NSData *headerData = [header dataUsingEncoding:NSUTF8StringEncoding];
    if (!DHSendAll(socketFD, headerData.bytes, headerData.length)) {
        [handle closeFile];
        return;
    }
    uint64_t sent = 0;
    while (sent < length) {
        @autoreleasepool {
            NSData *chunk = [handle readDataOfLength:(NSUInteger)MIN((uint64_t)(256 * 1024), length - sent)];
            if (!chunk.length || !DHSendAll(socketFD, chunk.bytes, chunk.length)) break;
            sent += chunk.length;
        }
    }
    [handle closeFile];
}

static NSData *DHJSONData(id object) {
    if (!object || ![NSJSONSerialization isValidJSONObject:object]) return nil;
    return [NSJSONSerialization dataWithJSONObject:object options:0 error:nil];
}

static NSDictionary *DHError(id requestID, NSInteger code, NSString *message) {
    return @{
        @"jsonrpc": @"2.0",
        @"id": requestID ?: NSNull.null,
        @"error": @{ @"code": @(code), @"message": message ?: @"Error" }
    };
}

static NSDictionary *DHResult(id requestID, id result) {
    return @{
        @"jsonrpc": @"2.0",
        @"id": requestID ?: NSNull.null,
        @"result": result ?: @{}
    };
}

static NSDictionary *DHMCPTool(NSString *name, NSString *description, NSDictionary *properties) {
    return @{
        @"name": name,
        @"description": description,
        @"inputSchema": @{
            @"type": @"object",
            @"properties": properties ?: @{},
            @"additionalProperties": @NO
        }
    };
}

static NSDictionary *DHMCPEventProperties(void) {
    return @{
        @"category": @{ @"type": @"string" }, @"algorithm": @{ @"type": @"string" },
        @"operation": @{ @"type": @"string" }, @"threadId": @{ @"type": @"integer" },
        @"sinceMs": @{ @"type": @"integer" }, @"untilMs": @{ @"type": @"integer" },
        @"afterSeq": @{ @"type": @"integer" }, @"beforeSeq": @{ @"type": @"integer" },
        @"stack": @{ @"type": @"string" }, @"contains": @{ @"type": @"string" },
        @"requestId": @{ @"type": @"string" }, @"contextId": @{ @"type": @"string" },
        @"order": @{ @"type": @"string", @"enum": @[@"asc", @"desc"] },
        @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @2000 }
    };
}

static NSArray *DHMCPTools(void) {
    return @[
        DHMCPTool(@"get_stats", @"Return event counts and current runtime configuration.", @{}),
        DHMCPTool(@"query_events", @"Query retained events with server-side filters and a sequence cursor.", DHMCPEventProperties()),
        DHMCPTool(@"get_event", @"Return one retained event by its global sequence.", @{
            @"seq": @{ @"type": @"integer", @"minimum": @1 }, @"includeNoise": @{ @"type": @"boolean" }
        }),
        DHMCPTool(@"export_events", @"Export filtered retained events as JSON Lines text.", DHMCPEventProperties()),
        DHMCPTool(@"query_noise", @"Query events routed to the Noise store.", DHMCPEventProperties()),
        DHMCPTool(@"clear_noise", @"Clear retained Noise events and rotated Noise logs.", @{}),
        DHMCPTool(@"set_category_pause", @"Pause or resume capture for one event category.", @{
            @"category": @{ @"type": @"string" }, @"paused": @{ @"type": @"boolean" }
        }),
        DHMCPTool(@"get_spoof", @"Return anti-debug, jailbreak-hide and device-spoof configuration.", @{}),
        DHMCPTool(@"list_images", @"List Mach-O images loaded in the current process.", @{
            @"contains": @{ @"type": @"string" },
            @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @1000 }
        }),
        DHMCPTool(@"dump_image", @"Export a loaded Mach-O image with its in-memory encrypted range restored.", @{
            @"image": @{ @"type": @"string" },
            @"outputName": @{ @"type": @"string" }
        }),
        DHMCPTool(@"start_dump", @"Queue an asynchronous Mach-O, ZIP, or IPA dump task.", @{
            @"image": @{ @"type": @"string" },
            @"format": @{ @"type": @"string", @"enum": @[@"macho", @"zip", @"ipa"] },
            @"outputName": @{ @"type": @"string" }
        }),
        DHMCPTool(@"dump_status", @"Return the progress and result of a dump task.", @{
            @"id": @{ @"type": @"string" }
        }),
        DHMCPTool(@"list_dumps", @"List queued, running, completed, and failed dump tasks.", @{}),
        DHMCPTool(@"clear_dump_history", @"Remove completed and failed tasks from in-memory history.", @{}),
        DHMCPTool(@"get_macho_info", @"Inspect load commands, segments, UUID, encryption state and symbols for a loaded 64-bit Mach-O image.", @{
            @"image": @{ @"type": @"string" }
        }),
        DHMCPTool(@"list_imports", @"List undefined external symbols from a loaded Mach-O image.", @{
            @"image": @{ @"type": @"string" },
            @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @10000 }
        }),
        DHMCPTool(@"list_functions", @"List symbol-backed function candidates from a loaded Mach-O image.", @{
            @"image": @{ @"type": @"string" },
            @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @10000 }
        }),
        DHMCPTool(@"disassemble_function", @"Disassemble a bounded ARM64 function range in the current process.", @{
            @"image": @{ @"type": @"string" },
            @"symbol": @{ @"type": @"string" },
            @"address": @{ @"type": @"string" },
            @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @256 }
        }),
        DHMCPTool(@"reload_config", @"Reload configuration from the host App sandbox.", @{}),
        DHMCPTool(@"clear_events", @"Clear retained events and the JSONL log.", @{}),
        DHMCPTool(@"get_config", @"Return the mutable runtime configuration.", @{}),
        DHMCPTool(@"set_config", @"Update and persist runtime configuration fields.", @{
            @"config": @{ @"type": @"object" }
        }),
        DHMCPTool(@"set_capture", @"Enable or disable one capture category at runtime.", @{
            @"category": @{ @"type": @"string", @"enum": @[@"network", @"crypto", @"keychain", @"file", @"dynamic"] },
            @"enabled": @{ @"type": @"boolean" }
        }),
        DHMCPTool(@"set_pause", @"Pause or resume all event capture without removing hooks.", @{
            @"paused": @{ @"type": @"boolean" }
        }),
        DHMCPTool(@"set_spoof", @"Update anti-debug, jailbreak-hide, device-spoof and hide-rule settings.", @{
            @"anti_debug": @{ @"type": @"boolean" },
            @"jailbreak_hide": @{ @"type": @"boolean" },
            @"device_spoof": @{ @"type": @"boolean" },
            @"device": @{ @"type": @"object" },
            @"hidden_paths": @{ @"type": @"array", @"items": @{ @"type": @"string" } },
            @"hidden_images": @{ @"type": @"array", @"items": @{ @"type": @"string" } },
            @"hidden_schemes": @{ @"type": @"array", @"items": @{ @"type": @"string" } }
        }),
        DHMCPTool(@"list_hooks", @"Return hook installation status recorded during bootstrap.", @{})
		,
		DHMCPTool(@"read_memory", @"Read a bounded byte range from the current process.", @{
			@"address": @{ @"type": @"string" },
			@"length": @{ @"type": @"integer", @"minimum": @1, @"maximum": @1048576 }
		}),
		DHMCPTool(@"search_memory", @"Search readable segments of a loaded image for UTF-8, ASCII, or hex bytes.", @{
			@"image": @{ @"type": @"string" },
			@"pattern": @{ @"type": @"string" },
			@"encoding": @{ @"type": @"string", @"enum": @[@"utf8", @"ascii", @"hex"] },
			@"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @2000 }
		}),
		DHMCPTool(@"symbolicate", @"Resolve an in-process address to its loaded image, segment, and nearest symbol.", @{
			@"address": @{ @"type": @"string" },
			@"image": @{ @"type": @"string" }
		}),
		DHMCPTool(@"find_xrefs", @"Find pointer or string references in a loaded image.", @{
			@"image": @{ @"type": @"string" },
			@"target": @{ @"type": @"string" },
			@"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @2000 }
		}),
		DHMCPTool(@"objc_classes", @"List Objective-C classes registered in the current process.", @{
			@"contains": @{ @"type": @"string" },
			@"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @5000 }
		}),
		DHMCPTool(@"objc_class_info", @"Inspect Objective-C methods, class methods, properties, protocols, and image.", @{
			@"class": @{ @"type": @"string" },
			@"methodLimit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @2000 }
		})
    ];
}

static NSDictionary *DHMCPToolResult(id requestID, id value) {
    NSData *json = DHJSONData(value ?: @{});
    NSString *text = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : @"{}";
    return DHResult(requestID, @{
        @"content": @[ @{ @"type": @"text", @"text": text } ],
        @"isError": @NO
    });
}

static NSDictionary *DHHandleMCP(NSDictionary *request) {
    id requestID = request[@"id"];
    NSString *method = [request[@"method"] isKindOfClass:NSString.class] ? request[@"method"] : nil;
    NSDictionary *params = [request[@"params"] isKindOfClass:NSDictionary.class] ? request[@"params"] : @{};
    if (!method) return DHError(requestID, -32600, @"Invalid Request: missing method");

    if ([method isEqualToString:@"initialize"]) {
        return DHResult(requestID, @{
            @"protocolVersion": @"2025-06-18",
            @"capabilities": @{ @"tools": @{} },
            @"serverInfo": @{ @"name": @"decrypt-helper-reconstructed", @"version": kDHEngineVersion }
        });
    }
    if ([method isEqualToString:@"ping"]) return DHResult(requestID, @{});
    if ([method isEqualToString:@"tools/list"]) return DHResult(requestID, @{ @"tools": DHMCPTools() });
    if (![method isEqualToString:@"tools/call"]) return DHError(requestID, -32601, @"Method not found");

    NSString *name = [params[@"name"] isKindOfClass:NSString.class] ? params[@"name"] : nil;
    NSDictionary *arguments = [params[@"arguments"] isKindOfClass:NSDictionary.class] ? params[@"arguments"] : @{};
    if ([name isEqualToString:@"get_stats"]) {
        return DHMCPToolResult(requestID, DHRuntimeSnapshot());
    }
    if ([name isEqualToString:@"get_spoof"]) {
        return DHMCPToolResult(requestID, [[DHConfig shared] publicSnapshot]);
    }
    if ([name isEqualToString:@"list_images"]) {
        NSString *contains = [arguments[@"contains"] isKindOfClass:NSString.class] ? arguments[@"contains"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ?
            [arguments[@"limit"] unsignedIntegerValue] : 1000;
        limit = MAX(1, MIN(limit, 1000));
        NSMutableArray *images = [NSMutableArray array];
        for (NSDictionary *image in DHLoadedImageSnapshot()) {
            if (contains.length && ![image[@"name"] localizedCaseInsensitiveContainsString:contains]) continue;
            [images addObject:image];
            if (images.count >= limit) break;
        }
        return DHMCPToolResult(requestID, images);
    }
    if ([name isEqualToString:@"dump_image"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSString *outputName = [arguments[@"outputName"] isKindOfClass:NSString.class] ? arguments[@"outputName"] : nil;
        NSError *error = nil;
        NSString *outputPath = DHDumpImageToCache(image, outputName, &error);
        if (!outputPath) return DHMCPToolResult(requestID, @{
            @"success": @NO,
            @"error": error.localizedDescription ?: @"dump failed"
        });
        return DHMCPToolResult(requestID, @{
            @"success": @YES,
            @"image": image ?: @"main",
            @"outputPath": outputPath ?: @""
        });
    }
    if ([name isEqualToString:@"start_dump"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSString *format = [arguments[@"format"] isKindOfClass:NSString.class] ? arguments[@"format"] : @"macho";
        NSString *outputName = [arguments[@"outputName"] isKindOfClass:NSString.class] ? arguments[@"outputName"] : nil;
        NSError *error = nil;
        NSDictionary *task = [[DHDumpManager sharedManager] startDumpWithImage:image format:format
                                                                    outputName:outputName error:&error];
        return DHMCPToolResult(requestID, task ?: @{ @"error": error.localizedDescription ?: @"could not start dump" });
    }
    if ([name isEqualToString:@"dump_status"]) {
        NSString *identifier = [arguments[@"id"] isKindOfClass:NSString.class] ? arguments[@"id"] : nil;
        NSDictionary *task = [[DHDumpManager sharedManager] taskStatus:identifier];
        return DHMCPToolResult(requestID, task ?: @{ @"error": @"dump task not found" });
    }
    if ([name isEqualToString:@"list_dumps"]) {
        return DHMCPToolResult(requestID, [[DHDumpManager sharedManager] taskSnapshots]);
    }
    if ([name isEqualToString:@"clear_dump_history"]) {
        return DHMCPToolResult(requestID, @{ @"removed": @([[DHDumpManager sharedManager] clearCompletedTasks]) });
    }
    if ([name isEqualToString:@"get_macho_info"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        return DHMCPToolResult(requestID, DHImageMachOInfo(image));
    }
    if ([name isEqualToString:@"list_imports"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 1000;
        return DHMCPToolResult(requestID, DHImageImports(image, limit));
    }
    if ([name isEqualToString:@"list_functions"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 1000;
        return DHMCPToolResult(requestID, DHImageFunctions(image, limit));
    }
    if ([name isEqualToString:@"disassemble_function"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSString *symbol = [arguments[@"symbol"] isKindOfClass:NSString.class] ? arguments[@"symbol"] : nil;
        NSString *address = [arguments[@"address"] isKindOfClass:NSString.class] ? arguments[@"address"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 32;
        return DHMCPToolResult(requestID, DHDisassembleFunction(image, symbol ?: address, limit));
    }
    if ([name isEqualToString:@"reload_config"]) {
        [[DHConfig shared] reload];
        return DHMCPToolResult(requestID, [[DHConfig shared] publicSnapshot]);
    }
    if ([name isEqualToString:@"clear_events"]) {
        [[DHLogStore shared] clearAll];
        return DHMCPToolResult(requestID, @{ @"cleared": @YES });
    }
    if ([name isEqualToString:@"get_config"]) {
        return DHMCPToolResult(requestID, [[DHConfig shared] publicSnapshot]);
    }
    if ([name isEqualToString:@"set_config"]) {
        NSDictionary *config = [arguments[@"config"] isKindOfClass:NSDictionary.class] ? arguments[@"config"] : arguments;
        NSError *error = nil;
        BOOL success = [[DHConfig shared] updateFromDictionary:config error:&error];
        return DHMCPToolResult(requestID, @{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"" });
    }
    if ([name isEqualToString:@"set_capture"]) {
        NSString *category = [arguments[@"category"] isKindOfClass:NSString.class] ? arguments[@"category"] : nil;
        BOOL enabled = [arguments[@"enabled"] respondsToSelector:@selector(boolValue)] ? [arguments[@"enabled"] boolValue] : NO;
        NSError *error = nil;
        BOOL success = [[DHConfig shared] setCaptureEnabled:enabled forCategory:category error:&error];
        return DHMCPToolResult(requestID, @{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"" });
    }
    if ([name isEqualToString:@"set_pause"]) {
        BOOL paused = [arguments[@"paused"] respondsToSelector:@selector(boolValue)] ? [arguments[@"paused"] boolValue] : NO;
        NSError *error = nil;
        BOOL success = [[DHConfig shared] setPaused:paused error:&error];
        return DHMCPToolResult(requestID, @{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"" });
    }
    if ([name isEqualToString:@"set_category_pause"]) {
        NSString *category = [arguments[@"category"] isKindOfClass:NSString.class] ? arguments[@"category"] : nil;
        BOOL paused = [arguments[@"paused"] respondsToSelector:@selector(boolValue)] ? [arguments[@"paused"] boolValue] : NO;
        NSError *error = nil;
        BOOL success = category.length && [[DHConfig shared] setPaused:paused forCategory:category error:&error];
        return DHMCPToolResult(requestID, @{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"" });
    }
    if ([name isEqualToString:@"set_spoof"]) {
        NSMutableDictionary *values = [NSMutableDictionary dictionary];
        for (NSString *key in @[@"anti_debug", @"jailbreak_hide", @"device_spoof", @"device", @"hidden_paths", @"hidden_images", @"hidden_schemes"]) if (arguments[key]) values[key] = arguments[key];
        NSError *error = nil;
        BOOL success = [[DHConfig shared] updateFromDictionary:values error:&error];
        return DHMCPToolResult(requestID, @{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"" });
    }
    if ([name isEqualToString:@"list_hooks"]) {
        return DHMCPToolResult(requestID, DHHookRegistrySnapshot());
    }
    if ([name isEqualToString:@"read_memory"]) {
        uint64_t address = 0;
        NSString *addressValue = [arguments[@"address"] isKindOfClass:NSString.class] ? arguments[@"address"] : nil;
        NSUInteger length = [arguments[@"length"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"length"] unsignedIntegerValue] : 0;
        if (!DHParseHTTPAddress(addressValue, &address)) return DHMCPToolResult(requestID, @{ @"error": @"address must be a hexadecimal or decimal string" });
        return DHMCPToolResult(requestID, DHReadMemory(address, length));
    }
    if ([name isEqualToString:@"search_memory"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSString *pattern = [arguments[@"pattern"] isKindOfClass:NSString.class] ? arguments[@"pattern"] : nil;
        NSString *encoding = [arguments[@"encoding"] isKindOfClass:NSString.class] ? arguments[@"encoding"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 100;
        return DHMCPToolResult(requestID, DHSearchMemory(image, pattern, encoding, limit));
    }
    if ([name isEqualToString:@"symbolicate"]) {
        uint64_t address = 0;
        NSString *addressValue = [arguments[@"address"] isKindOfClass:NSString.class] ? arguments[@"address"] : nil;
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        if (!DHParseHTTPAddress(addressValue, &address)) return DHMCPToolResult(requestID, @{ @"error": @"address must be a hexadecimal or decimal string" });
        return DHMCPToolResult(requestID, DHSymbolicateAddress(address, image));
    }
    if ([name isEqualToString:@"find_xrefs"]) {
        NSString *image = [arguments[@"image"] isKindOfClass:NSString.class] ? arguments[@"image"] : nil;
        NSString *target = [arguments[@"target"] isKindOfClass:NSString.class] ? arguments[@"target"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 100;
        return DHMCPToolResult(requestID, DHFindXrefs(image, target, limit));
    }
    if ([name isEqualToString:@"objc_classes"]) {
        NSString *contains = [arguments[@"contains"] isKindOfClass:NSString.class] ? arguments[@"contains"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"limit"] unsignedIntegerValue] : 200;
        return DHMCPToolResult(requestID, DHObjCClassList(contains, limit));
    }
    if ([name isEqualToString:@"objc_class_info"]) {
        NSString *className = [arguments[@"class"] isKindOfClass:NSString.class] ? arguments[@"class"] : nil;
        NSUInteger limit = [arguments[@"methodLimit"] respondsToSelector:@selector(unsignedIntegerValue)] ? [arguments[@"methodLimit"] unsignedIntegerValue] : 500;
        return DHMCPToolResult(requestID, DHObjCClassInfo(className, limit));
    }
    if ([name isEqualToString:@"query_events"]) {
        return DHMCPToolResult(requestID, [[DHLogStore shared] queryWithFilters:arguments noise:NO]);
    }
    if ([name isEqualToString:@"query_noise"]) {
        return DHMCPToolResult(requestID, [[DHLogStore shared] queryWithFilters:arguments noise:YES]);
    }
    if ([name isEqualToString:@"get_event"]) {
        uint64_t sequence = [arguments[@"seq"] unsignedLongLongValue];
        BOOL includeNoise = !arguments[@"includeNoise"] || [arguments[@"includeNoise"] boolValue];
        NSDictionary *event = [[DHLogStore shared] eventForSequence:sequence includeNoise:includeNoise];
        return DHMCPToolResult(requestID, event ?: @{ @"error": @"event not found", @"seq": @(sequence) });
    }
    if ([name isEqualToString:@"export_events"]) {
        NSMutableDictionary *filters = [arguments mutableCopy];
        if (!filters[@"limit"]) filters[@"limit"] = @2000;
        NSDictionary *result = [[DHLogStore shared] queryWithFilters:filters noise:NO];
        NSArray *events = result[@"events"];
        return DHMCPToolResult(requestID, @{ @"format": @"jsonl", @"count": @(events.count), @"data": DHJSONLString(events) });
    }
    if ([name isEqualToString:@"clear_noise"]) {
        [[DHLogStore shared] clearNoise];
        return DHMCPToolResult(requestID, @{ @"cleared": @YES });
    }
    return DHError(requestID, -32602, @"Unknown tool");
}

static NSData *DHReadRequest(int socketFD) {
    NSMutableData *data = [NSMutableData data];
    const NSUInteger maximum = 1024 * 1024;
    NSUInteger expectedLength = NSNotFound;
    while (data.length < maximum) {
        uint8_t buffer[8192];
        ssize_t count = recv(socketFD, buffer, sizeof(buffer), 0);
        if (count <= 0) break;
        [data appendBytes:buffer length:(NSUInteger)count];

        NSData *separator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange headerEnd = [data rangeOfData:separator options:0 range:NSMakeRange(0, data.length)];
        if (headerEnd.location == NSNotFound) continue;
        if (expectedLength == NSNotFound) {
            NSData *headerData = [data subdataWithRange:NSMakeRange(0, headerEnd.location)];
            NSString *header = [[NSString alloc] initWithData:headerData encoding:NSUTF8StringEncoding];
            expectedLength = 0;
            for (NSString *line in [header componentsSeparatedByString:@"\r\n"]) {
                if ([line.lowercaseString hasPrefix:@"content-length:"]) {
                    expectedLength = [[line substringFromIndex:15] stringByTrimmingCharactersInSet:
                                      NSCharacterSet.whitespaceCharacterSet].integerValue;
                    break;
                }
            }
        }
        NSUInteger bodyStart = NSMaxRange(headerEnd);
        if (data.length >= bodyStart + expectedLength) break;
    }
    return data;
}

static void DHHandleClient(int socketFD) {
    @autoreleasepool {
        NSData *requestData = DHReadRequest(socketFD);
        NSData *separator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange headerEnd = [requestData rangeOfData:separator options:0 range:NSMakeRange(0, requestData.length)];
        if (headerEnd.location == NSNotFound) {
            DHSendResponse(socketFD, 400, @"text/plain; charset=utf-8",
                           [@"bad request" dataUsingEncoding:NSUTF8StringEncoding]);
            close(socketFD);
            return;
        }

        NSString *header = [[NSString alloc] initWithData:
                            [requestData subdataWithRange:NSMakeRange(0, headerEnd.location)]
                                                   encoding:NSUTF8StringEncoding];
        NSString *firstLine = [header componentsSeparatedByString:@"\r\n"].firstObject ?: @"";
        NSArray<NSString *> *parts = [firstLine componentsSeparatedByString:@" "];
        NSString *method = parts.count > 0 ? parts[0] : @"";
        NSString *target = parts.count > 1 ? parts[1] : @"/";
        NSString *path = [target componentsSeparatedByString:@"?"].firstObject ?: @"/";
        NSUInteger bodyStart = NSMaxRange(headerEnd);
        NSData *body = requestData.length > bodyStart ?
                       [requestData subdataWithRange:NSMakeRange(bodyStart, requestData.length - bodyStart)] : NSData.data;

        if ([method isEqualToString:@"OPTIONS"]) {
            DHSendResponse(socketFD, 204, @"text/plain", nil);
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/"]) {
            DHSendResponse(socketFD, 200, @"text/html; charset=utf-8",
                           [DHWebConsoleHTML() dataUsingEncoding:NSUTF8StringEncoding]);
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/health"]) {
            NSMutableDictionary *health = [DHRuntimeSnapshot() mutableCopy];
            health[@"ok"] = @YES;
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(health));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/events"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHEventSnapshot(target)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/events/get"]) {
            uint64_t sequence = [DHQueryValue(target, @"seq") unsignedLongLongValue];
            NSString *includeValue = DHQueryValue(target, @"includeNoise");
            BOOL includeNoise = !includeValue.length || includeValue.boolValue;
            NSDictionary *event = [[DHLogStore shared] eventForSequence:sequence includeNoise:includeNoise];
            DHSendResponse(socketFD, event ? 200 : 404, @"application/json", DHJSONData(event ?: @{ @"error": @"event not found", @"seq": @(sequence) }));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/events/export"]) {
            NSMutableDictionary *filters = [DHEventFiltersFromTarget(target, 2000) mutableCopy];
            NSDictionary *result = [[DHLogStore shared] queryWithFilters:filters noise:NO];
            DHSendResponse(socketFD, 200, @"application/x-ndjson; charset=utf-8", DHJSONLData(result[@"events"]));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/noise"]) {
            NSDictionary *result = [[DHLogStore shared] queryWithFilters:DHEventFiltersFromTarget(target, 200) noise:YES];
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(result));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/stats"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHRuntimeSnapshot()));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/config"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData([[DHConfig shared] publicSnapshot]));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/hooks"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHHookRegistrySnapshot()));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/macho"]) {
            DHSendResponse(socketFD, 200, @"application/json",
                           DHJSONData(DHImageMachOInfo(DHQueryValue(target, @"image"))));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/imports"]) {
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 1000, 10000);
            DHSendResponse(socketFD, 200, @"application/json",
                           DHJSONData(DHImageImports(DHQueryValue(target, @"image"), limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/functions"]) {
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 1000, 10000);
            DHSendResponse(socketFD, 200, @"application/json",
                           DHJSONData(DHImageFunctions(DHQueryValue(target, @"image"), limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/disassemble"]) {
            NSString *symbolOrAddress = DHQueryValue(target, @"symbol") ?: DHQueryValue(target, @"address");
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 32, 256);
            DHSendResponse(socketFD, 200, @"application/json",
                           DHJSONData(DHDisassembleFunction(DHQueryValue(target, @"image"), symbolOrAddress, limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/memory"]) {
            uint64_t address = 0;
            NSUInteger length = DHBoundedLimit(DHQueryValue(target, @"length"), 0, 1024 * 1024);
            BOOL success = DHParseHTTPAddress(DHQueryValue(target, @"address"), &address) && length > 0;
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json",
                           DHJSONData(success ? DHReadMemory(address, length) : @{ @"error": @"address and length are required" }));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/symbolicate"]) {
            uint64_t address = 0;
            BOOL success = DHParseHTTPAddress(DHQueryValue(target, @"address"), &address);
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json",
                           DHJSONData(success ? DHSymbolicateAddress(address, DHQueryValue(target, @"image")) : @{ @"error": @"address is required" }));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/search"]) {
            NSString *pattern = DHQueryValue(target, @"pattern");
            NSString *image = DHQueryValue(target, @"image");
            NSString *encoding = DHQueryValue(target, @"encoding");
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 100, 2000);
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHSearchMemory(image, pattern, encoding, limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/xrefs"]) {
            NSString *targetValue = DHQueryValue(target, @"target");
            NSString *image = DHQueryValue(target, @"image");
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 100, 2000);
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHFindXrefs(image, targetValue, limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/objc/classes"]) {
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"limit"), 200, 5000);
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHObjCClassList(DHQueryValue(target, @"contains"), limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/objc/class"]) {
            NSUInteger limit = DHBoundedLimit(DHQueryValue(target, @"methodLimit"), 500, 2000);
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHObjCClassInfo(DHQueryValue(target, @"class"), limit)));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/images"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHLoadedImageSnapshot()));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/dumps"]) {
            DHSendResponse(socketFD, 200, @"application/json",
                           DHJSONData([[DHDumpManager sharedManager] taskSnapshots]));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/dumps/status"]) {
            NSDictionary *task = [[DHDumpManager sharedManager] taskStatus:DHQueryValue(target, @"id")];
            DHSendResponse(socketFD, task ? 200 : 404, @"application/json",
                           DHJSONData(task ?: @{ @"error": @"dump task not found" }));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/dumps/download"]) {
            NSDictionary *task = [[DHDumpManager sharedManager] taskStatus:DHQueryValue(target, @"id")];
            NSString *state = [task[@"state"] isKindOfClass:NSString.class] ? task[@"state"] : nil;
            NSString *outputPath = [task[@"outputPath"] isKindOfClass:NSString.class] ? task[@"outputPath"] : nil;
            if (!task) {
                DHSendResponse(socketFD, 404, @"application/json", DHJSONData(@{ @"error": @"dump task not found" }));
            } else if (![state isEqualToString:@"succeeded"] || !outputPath.length) {
                DHSendResponse(socketFD, 409, @"application/json", DHJSONData(@{ @"error": @"dump task is not complete", @"task": task }));
            } else {
                DHSendFileResponse(socketFD, outputPath);
            }
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/dumps/start"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSString *image = [request[@"image"] isKindOfClass:NSString.class] ? request[@"image"] : nil;
            NSString *format = [request[@"format"] isKindOfClass:NSString.class] ? request[@"format"] : @"macho";
            NSString *outputName = [request[@"outputName"] isKindOfClass:NSString.class] ? request[@"outputName"] : nil;
            NSError *error = nil;
            NSDictionary *task = [[DHDumpManager sharedManager] startDumpWithImage:image format:format
                                                                        outputName:outputName error:&error];
            DHSendResponse(socketFD, task ? 202 : 400, @"application/json",
                           DHJSONData(task ?: @{ @"error": error.localizedDescription ?: @"could not start dump" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/dumps/clear-history"]) {
            NSUInteger removed = [[DHDumpManager sharedManager] clearCompletedTasks];
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(@{ @"removed": @(removed) }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/dump"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSString *image = [request[@"image"] isKindOfClass:NSString.class] ? request[@"image"] : nil;
            NSString *outputName = [request[@"outputName"] isKindOfClass:NSString.class] ? request[@"outputName"] : nil;
            NSError *error = nil;
            NSString *outputPath = DHDumpImageToCache(image, outputName, &error);
            BOOL success = outputPath != nil;
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{
                @"success": @(success),
                @"image": image ?: @"main",
                @"outputPath": outputPath ?: @"",
                @"error": error.localizedDescription ?: @""
            }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/clear"]) {
            [[DHLogStore shared] clearAll];
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(@{ @"ok": @YES }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/noise/clear"]) {
            [[DHLogStore shared] clearNoise];
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(@{ @"ok": @YES }));
        } else if (([method isEqualToString:@"POST"] || [method isEqualToString:@"PUT"]) && [path isEqualToString:@"/api/config"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSError *error = nil;
            BOOL success = [request isKindOfClass:NSDictionary.class] && [[DHConfig shared] updateFromDictionary:request error:&error];
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"invalid configuration" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/capture"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSString *category = [request[@"category"] isKindOfClass:NSString.class] ? request[@"category"] : nil;
            NSError *error = nil;
            BOOL success = category.length && [request[@"enabled"] respondsToSelector:@selector(boolValue)] && [[DHConfig shared] setCaptureEnabled:[request[@"enabled"] boolValue] forCategory:category error:&error];
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"invalid capture category" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/pause"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSError *error = nil;
            BOOL success = [request[@"paused"] respondsToSelector:@selector(boolValue)] && [[DHConfig shared] setPaused:[request[@"paused"] boolValue] error:&error];
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"paused must be boolean" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/pause/category"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSString *category = [request[@"category"] isKindOfClass:NSString.class] ? request[@"category"] : nil;
            NSError *error = nil;
            BOOL success = category.length && [request[@"paused"] respondsToSelector:@selector(boolValue)] &&
                           [[DHConfig shared] setPaused:[request[@"paused"] boolValue] forCategory:category error:&error];
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"category and paused are required" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/spoof"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSError *error = nil;
            BOOL success = [request isKindOfClass:NSDictionary.class] && [[DHConfig shared] updateFromDictionary:request error:&error];
            DHSendResponse(socketFD, success ? 200 : 400, @"application/json", DHJSONData(@{ @"success": @(success), @"config": [[DHConfig shared] publicSnapshot], @"error": error.localizedDescription ?: @"invalid spoof configuration" }));
        } else if ([path isEqualToString:@"/api/mcp"] && ![method isEqualToString:@"POST"]) {
            DHSendResponse(socketFD, 405, @"application/json",
                           DHJSONData(@{ @"error": @"MCP endpoint accepts POST only" }));
        } else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/mcp"]) {
            NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:nil] : nil;
            NSDictionary *response = [request isKindOfClass:NSDictionary.class] ?
                                     DHHandleMCP(request) : DHError(nil, -32700, @"Parse error");
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(response));
        } else {
            DHSendResponse(socketFD, 404, @"application/json", DHJSONData(@{ @"error": @"not found" }));
        }
        close(socketFD);
    }
}

static int DHCreateListeningSocket(uint16_t port) {
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) return -1;
    int yes = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socketFD, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(socketFD, 16) != 0) {
        close(socketFD);
        return -1;
    }
    return socketFD;
}

void DHStartHTTPServer(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uint16_t configuredPort = [DHConfig shared].httpPort;
        uint16_t finalPort = configuredPort;
        uint16_t lastPort = (configuredPort >= 8088 && configuredPort <= 8108) ? 8108 : configuredPort;
        int socketFD = -1;
        for (uint32_t port = configuredPort; port <= lastPort; port++) {
            socketFD = DHCreateListeningSocket((uint16_t)port);
            if (socketFD >= 0) {
                finalPort = (uint16_t)port;
                break;
            }
        }
        if (socketFD < 0) return;
        gListenSocket = socketFD;
        gHTTPPort = finalPort;
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            while (gListenSocket >= 0) {
                int client = accept(gListenSocket, NULL, NULL);
                if (client < 0) continue;
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{ DHHandleClient(client); });
            }
        });
    });
}

uint16_t DHHTTPServerPort(void) {
    return gHTTPPort ?: [DHConfig shared].httpPort;
}
