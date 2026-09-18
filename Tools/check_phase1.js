const fs = require('fs');

function read(path) { return fs.readFileSync(path, 'utf8'); }
function requireText(text, pattern, label) {
  if (!pattern.test(text)) throw new Error(`phase1 contract missing: ${label}`);
}

const registry = read('Source/DHHookRegistry.m');
const dynamic = read('Source/DHDynamic.m');
const network = read('Source/DHNetwork.m');
const commonCrypto = read('Source/DHCommonCrypto.m');
const evp = read('Source/DHEVP.m');
const logStore = read('Source/DHLogStore.m');
const sources = fs.readdirSync('Source')
  .filter(name => name.endsWith('.m'))
  .map(name => read(`Source/${name}`));

requireText(registry, /int DHRebindSymbols\(/, 'central fishhook installer');
requireText(registry, /\*originalSlot = resolvedAddress;/, 'late original-slot initialization');
requireText(dynamic, /DHRouteResolvedSymbol\(symbol, resolvedAddress, &routed\)/,
  'dlsym wrapper routing');
requireText(dynamic, /return returnedAddress;/, 'dlsym returns routed wrapper');
requireText(network, /setHTTPBody:/, 'mutable request body hook');
requireText(network, /setHTTPBodyStream:/, 'mutable request body-stream hook');
requireText(network, /URLSession:dataTask:didReceiveData:/, 'delegate data capture');
requireText(network, /URLSession:dataTask:didReceiveResponse:completionHandler:/,
  'delegate response capture');
requireText(network, /URLSession:task:didCompleteWithError:/, 'delegate completion capture');
requireText(network, /@"requestId"/, 'network request correlation id');
requireText(logStore, /@"contextId"/, 'thread context correlation id');
requireText(commonCrypto, /kDHCaptureLimit = 4 \* 1024 \* 1024/,
  'CommonCrypto 4 MiB capture limit');
requireText(evp, /kDHEVPCaptureLimit = 4 \* 1024 \* 1024/,
  'EVP 4 MiB capture limit');

const directFishhookCalls = sources.reduce((count, source) =>
  count + (source.match(/\brebind_symbols\s*\(/g) || []).length, 0);
if (directFishhookCalls !== 1) {
  throw new Error(`expected one central rebind_symbols call, found ${directFishhookCalls}`);
}
const centralCalls = sources.reduce((count, source) =>
  count + (source.match(/\bDHRebindSymbols\s*\(/g) || []).length, 0);
if (centralCalls < 9) throw new Error(`expected all hook modules in central registry, found ${centralCalls}`);

console.log(`phase1-contract-ok: ${centralCalls - 1} hook modules, dlsym/body/delegate/correlation/4MiB`);
