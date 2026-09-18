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
const web = read('Web/console.html');

for (const token of ['pausedByCategory', 'noiseRules', 'setPaused:(BOOL)paused forCategory:', 'noiseActionForEvent:']) need(configH, token, 'config header');
for (const token of ['paused_by_category', 'noise_rules', 'detailContains', 'stackContains', 'requestId', 'contextId']) need(config, token, 'config engine');
for (const token of ['noiseRule', 'queryWithFilters:', 'eventForSequence:', 'clearNoise', 'noiseLogFilePath']) need(storeH, token, 'store header');
for (const token of ['kDHLogRotationBytes', 'noiseEntries', '@"nextCursor"', '@"hasMore"', '@"source"', '@"afterSeq"', '@"beforeSeq"']) need(store, token, 'event store');

for (const endpoint of ['/api/events/get', '/api/events/export', '/api/noise', '/api/noise/clear', '/api/pause/category']) need(http, endpoint, 'http api');
for (const tool of ['query_events', 'get_event', 'export_events', 'query_noise', 'clear_noise', 'set_category_pause']) need(http, `@"${tool}"`, 'mcp tools');
for (const filter of ['algorithm', 'operation', 'threadId', 'sinceMs', 'untilMs', 'stack', 'contains', 'requestId', 'contextId', 'order']) need(http, `@"${filter}"`, 'mcp filters');

for (const id of ['view-noise', 'noiseTable', 'noiseRules', 'categoryPauses', 'clearNoise', 'saveNoiseConfig', 'statNoise']) need(web, `id="${id}"`, 'web console');
for (const fn of ['loadNoise()', 'loadNoiseConfig()', 'saveNoiseConfig()']) need(web, fn, 'web console logic');

const workflows = ['.github/workflows/build.yml', '.github/workflows/build-roothide.yml'];
for (const path of workflows) need(read(path), 'node Tools/check_phase2.js', path);

console.log('phase2-contract-ok: noise routing, category pause, cursor filters, JSONL rotation, HTTP/MCP/Web');
