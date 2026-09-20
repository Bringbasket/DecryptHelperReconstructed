'use strict';

const fs = require('fs');
const read = path => fs.readFileSync(path, 'utf8');
const need = (text, token, label) => {
  if (!text.includes(token)) throw new Error(`${label}: missing ${token}`);
};

const configH = read('Headers/DHConfig.h');
const config = read('Source/DHConfig.m');
const storeH = read('Headers/DHLogStore.h');
const store = read('Source/DHLogStore.m');
const http = read('Source/DHHTTPServer.m');
const spoofH = read('Headers/DHSpoof.h');
const spoof = read('Source/DHSpoof.m');
const dynamic = read('Source/DHDynamic.m');
const dump = read('Source/DHDump.m');
const web = read('Web/console.html');

for (const token of ['pausedByCategory', 'noiseRules', 'setPaused:(BOOL)paused forCategory:', 'noiseActionForEvent:']) need(configH, token, 'config header');
for (const token of ['paused_by_category', 'noise_rules', 'detailContains', 'stackContains', 'requestId', 'contextId']) need(config, token, 'config engine');
for (const token of ['environment_probe', 'updateSpoofRuleOperation:', 'hidden_paths', 'hidden_images', 'hidden_schemes']) need(config, token, 'environment config');
for (const token of ['noiseRule', 'queryWithFilters:', 'eventForSequence:', 'clearNoise', 'noiseLogFilePath']) need(storeH, token, 'store header');
for (const token of ['kDHLogRotationBytes', 'noiseEntries', '@"nextCursor"', '@"hasMore"', '@"source"', '@"afterSeq"', '@"beforeSeq"']) need(store, token, 'event store');

for (const endpoint of ['/api/events/get', '/api/events/export', '/api/noise', '/api/noise/clear', '/api/pause/category']) need(http, endpoint, 'http api');
for (const tool of ['query_events', 'get_event', 'export_events', 'query_noise', 'clear_noise', 'set_category_pause']) need(http, `@"${tool}"`, 'mcp tools');
for (const tool of ['get_diag', 'list_loaded_images', 'list_files', 'read_file', 'objc_resolve_imp', 'find_objc_methods']) need(http, `@"${tool}"`, 'compatibility tools');
for (const field of ['localOnly', 'httpOk', 'httpFailed', 'persistFailed', 'environmentProbeCount', 'hookFailureCount']) need(http, `@"${field}"`, 'diagnostic health');
for (const filter of ['algorithm', 'operation', 'threadId', 'sinceMs', 'untilMs', 'stack', 'contains', 'requestId', 'contextId', 'order']) need(http, `@"${filter}"`, 'mcp filters');

for (const symbol of ['DHEnvironmentProbeCount', 'DHSpoofMatchesImagePath']) need(spoofH, symbol, 'environment header');
for (const hook of ['DHHookedPtrace', 'DHHookedCSOps', 'DHHookedSysctl', 'DHHookedSysctlByName', 'DHHookedStat', 'DHHookedLstat', 'DHHookedAccess', 'DHHookedFaccessat', 'DHHookedFstatat', 'DHHookedGetenv', 'DHHookedUname', 'DHHookedDyldImageName', 'DHSpoofedCanOpenURL']) need(spoof, hook, 'environment hooks');
for (const token of ['matchedRule', 'DHSpoofMatchesImagePath(imagePath)']) need(dynamic, token, 'dladdr observation');
need(dump, 'if ([normalizedFormat isEqualToString:@"bin"]) normalizedFormat = @"zip";', 'bin ZIP alias');

const networkH = read('Headers/DHNetwork.h');
const networkExt = read('Source/DHNetworkExtensions.m');
const webkit = read('Source/DHWebKitProbe.m');
const websocket = read('Source/DHWebSocket.m');
const networkFramework = read('Source/DHNetworkFramework.m');
const configText = read('Source/DHConfig.m');
const commonCrypto = read('Source/DHCommonCrypto.m');
const asymmetric = read('Source/DHAsymmetric.m');
for (const token of ['DHInstallNetworkExtensions', 'DHNetworkCaptureCoverage', 'DHWebKitProbeSnapshot', 'DHInstallWebKitProbeHooks']) need(networkH, token, 'network extension header');
for (const token of ['socket', 'connect', 'accept', 'sendmsg', 'recvmsg', 'getaddrinfo', 'SSLWrite', 'SSLRead']) need(networkExt, token, 'BSD/SecureTransport hooks');
for (const token of ['dhProbe', 'fetch', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'crypto']) need(webkit, token, 'WebKit probe');
for (const token of ['webkit_probe', 'webkit_probe_redact', 'webkit_probe_max_bytes', 'webkit_probe_allow_domains', 'webkit_probe_deny_domains']) need(configText, token, 'WebKit configuration');
for (const token of ['sendMessage:completionHandler:', 'receiveMessageWithCompletionHandler:', 'WebSocket']) need(websocket, token, 'WebSocket hooks');
for (const token of ['nw_connection_send', 'nw_connection_receive', 'dispatch_data_apply']) need(networkFramework, token, 'Network.framework hooks');
for (const token of ['CCRandomGenerateBytes', 'SecRandomCopyBytes']) need(commonCrypto, token, 'RNG hooks');
for (const token of ['SecKeyEncrypt', 'SecKeyDecrypt', 'SecKeyRawSign', 'SecKeyRawVerify']) need(asymmetric, token, 'legacy Security hooks');
for (const tool of ['get_capture_coverage', 'get_webkit_probe', 'set_webkit_probe', 'get_capabilities']) need(http, `@"${tool}"`, 'coverage MCP tools');
for (const endpoint of ['/api/capture/coverage', '/api/webkit/probe']) need(http, endpoint, 'coverage HTTP endpoints');

for (const id of ['view-noise', 'noiseTable', 'noiseRules', 'categoryPauses', 'clearNoise', 'saveNoiseConfig', 'statNoise']) need(web, `id="${id}"`, 'web console');
for (const fn of ['loadNoise()', 'loadNoiseConfig()', 'saveNoiseConfig()']) need(web, fn, 'web console logic');

const workflows = ['.github/workflows/build.yml', '.github/workflows/build-roothide.yml'];
for (const path of workflows) need(read(path), 'node Tools/check_phase2.js', path);

console.log('phase2-contract-ok: noise routing, category pause, cursor filters, JSONL rotation, HTTP/MCP/Web');
