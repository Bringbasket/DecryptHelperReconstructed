#import "DHHTTPServer.h"
#import "DHConfig.h"
#import "DHImageInventory.h"
#import "DHDump.h"
#import "DHLogStore.h"
#import <arpa/inet.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>

static int gListenSocket = -1;
static uint16_t gHTTPPort;
static NSString * const kDHEngineVersion = @"0.1.0";

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
        @"imageCount": @(DHLoadedImageSnapshot().count),
        @"config": [[DHConfig shared] publicSnapshot]
    };
}

static NSString * const kDHIndexHTML =
@"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Decrypt Helper Reconstructed</title><style>"
"body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:0;background:#0b1020;color:#e8ecf8}"
"header{position:sticky;top:0;background:#121a31;padding:14px 18px;display:flex;gap:12px;align-items:center}"
"h1{font-size:17px;margin:0;flex:1}button{border:0;border-radius:8px;padding:8px 12px;background:#536dfe;color:white}"
"main{padding:14px}.card{background:#121a31;border-radius:12px;padding:12px;margin-bottom:10px}"
".meta{font-size:12px;color:#95a1c6;word-break:break-all}.body{white-space:pre-wrap;word-break:break-all;font:12px ui-monospace,monospace;max-height:240px;overflow:auto}"
".empty{text-align:center;color:#95a1c6;padding:50px 0}</style></head><body>"
"<header><h1>Decrypt Helper Reconstructed <span id='count'></span></h1>"
"<button onclick='loadEvents()'>刷新</button><button onclick='clearEvents()'>清空</button></header>"
"<main id='list'><div class='empty'>正在读取事件…</div></main><script>"
"const esc=v=>String(v??'');async function loadEvents(){let r=await fetch('/api/events');let a=await r.json();"
"count.textContent='('+a.length+')';let root=document.querySelector('#list');root.textContent='';"
"if(!a.length){root.innerHTML=\"<div class='empty'>暂无事件</div>\";return;}"
"for(let e of a.slice().reverse()){let d=document.createElement('div');d.className='card';"
"let t=document.createElement('div');t.textContent=`#${e.seq} ${esc(e.category)} · ${esc(e.algorithm)} · ${esc(e.operation)}`;d.append(t);"
"let m=document.createElement('div');m.className='meta';m.textContent=new Date(e.timestampMs).toLocaleString()+'  '+esc(e.detail);d.append(m);"
"let b=document.createElement('div');b.className='body';b.textContent=e.input||e.output||'';d.append(b);root.append(d);}}"
"async function clearEvents(){await fetch('/api/clear',{method:'POST'});loadEvents()}loadEvents();setInterval(loadEvents,3000);"
"</script></body></html>";

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

static void DHSendResponse(int socketFD, NSInteger status, NSString *contentType, NSData *body) {
    NSString *reason = status == 200 ? @"OK" : status == 204 ? @"No Content" :
                       status == 400 ? @"Bad Request" : status == 404 ? @"Not Found" :
                       status == 405 ? @"Method Not Allowed" : @"Internal Server Error";
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

static NSArray *DHMCPTools(void) {
    return @[
        DHMCPTool(@"get_stats", @"Return event counts and current runtime configuration.", @{}),
        DHMCPTool(@"query_events", @"Return captured events, optionally filtered by category.", @{
            @"category": @{ @"type": @"string" },
            @"limit": @{ @"type": @"integer", @"minimum": @1, @"maximum": @500 }
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
        DHMCPTool(@"reload_config", @"Reload configuration from the host App sandbox.", @{}),
        DHMCPTool(@"clear_events", @"Clear retained events and the JSONL log.", @{})
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
    if ([name isEqualToString:@"reload_config"]) {
        [[DHConfig shared] reload];
        return DHMCPToolResult(requestID, [[DHConfig shared] publicSnapshot]);
    }
    if ([name isEqualToString:@"clear_events"]) {
        [[DHLogStore shared] clearAll];
        return DHMCPToolResult(requestID, @{ @"cleared": @YES });
    }
    if ([name isEqualToString:@"query_events"]) {
        NSString *category = [arguments[@"category"] isKindOfClass:NSString.class] ? arguments[@"category"] : nil;
        NSUInteger limit = [arguments[@"limit"] respondsToSelector:@selector(unsignedIntegerValue)] ?
                           [arguments[@"limit"] unsignedIntegerValue] : 100;
        limit = MAX(1, MIN(limit, 500));
        NSMutableArray *events = [NSMutableArray array];
        for (NSDictionary *event in [[DHLogStore shared] dictionarySnapshot]) {
            if (category.length && [event[@"category"] caseInsensitiveCompare:category] != NSOrderedSame) continue;
            [events addObject:event];
        }
        if (events.count > limit) {
            events = [[events subarrayWithRange:NSMakeRange(events.count - limit, limit)] mutableCopy];
        }
        return DHMCPToolResult(requestID, events);
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
        NSString *path = parts.count > 1 ? [parts[1] componentsSeparatedByString:@"?"].firstObject : @"/";
        NSUInteger bodyStart = NSMaxRange(headerEnd);
        NSData *body = requestData.length > bodyStart ?
                       [requestData subdataWithRange:NSMakeRange(bodyStart, requestData.length - bodyStart)] : NSData.data;

        if ([method isEqualToString:@"OPTIONS"]) {
            DHSendResponse(socketFD, 204, @"text/plain", nil);
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/"]) {
            DHSendResponse(socketFD, 200, @"text/html; charset=utf-8",
                           [kDHIndexHTML dataUsingEncoding:NSUTF8StringEncoding]);
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/health"]) {
            NSMutableDictionary *health = [DHRuntimeSnapshot() mutableCopy];
            health[@"ok"] = @YES;
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(health));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/events"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData([[DHLogStore shared] dictionarySnapshot]));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/stats"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHRuntimeSnapshot()));
        } else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/images"]) {
            DHSendResponse(socketFD, 200, @"application/json", DHJSONData(DHLoadedImageSnapshot()));
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
