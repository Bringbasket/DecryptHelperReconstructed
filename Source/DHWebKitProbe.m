#import "DHNetwork.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "DHHookRegistry.h"
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

static const void *kDHProbeBridgeKey = &kDHProbeBridgeKey;
static const void *kDHProbeInstalledKey = &kDHProbeInstalledKey;
typedef id (*DHWKInitFn)(id, SEL, CGRect, WKWebViewConfiguration *);
static DHWKInitFn gOriginalWKInit;

static BOOL DHProbeDomainMatches(NSString *host, NSString *domain) {
    NSString *h = host.lowercaseString ?: @"";
    NSString *d = domain.lowercaseString ?: @"";
    return d.length && ([h isEqualToString:d] || [h hasSuffix:[@"." stringByAppendingString:d]]);
}

static BOOL DHProbeAllowsURL(NSString *url) {
    NSString *host = [NSURL URLWithString:url ?: @""].host ?: @"";
    NSArray *allow = [DHConfig shared].webkitProbeAllowDomains;
    NSArray *deny = [DHConfig shared].webkitProbeDenyDomains;
    BOOL result = !allow.count;
    for (NSString *domain in allow) if (DHProbeDomainMatches(host, domain)) result = YES;
    for (NSString *domain in deny) if (DHProbeDomainMatches(host, domain)) result = NO;
    return result;
}

static NSDictionary *DHProbeRedactedBody(NSDictionary *body) {
    NSMutableDictionary *copy = [body mutableCopy];
    if (![DHConfig shared].webkitProbeRedact) return copy;
    NSMutableDictionary *headers = [copy[@"headers"] mutableCopy];
    for (NSString *key in headers.allKeys) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"authorization"] || [lower containsString:@"cookie"] || [lower containsString:@"token"]) {
            headers[key] = @"<redacted>";
        }
    }
    if (headers) copy[@"headers"] = headers;
    return copy;
}

@interface DHWebKitProbeBridge : NSObject <WKScriptMessageHandler>
@end

@implementation DHWebKitProbeBridge
- (void)userContentController:(WKUserContentController *)controller
      didReceiveScriptMessage:(WKScriptMessage *)message {
    NSDictionary *body = [message.body isKindOfClass:NSDictionary.class] ? message.body : nil;
    if (!body || ![DHConfig shared].webkitProbeEnabled) return;
    NSString *url = [body[@"url"] isKindOfClass:NSString.class] ? body[@"url"] : @"";
    if (!DHProbeAllowsURL(url)) return;
    NSDictionary *safeBody = DHProbeRedactedBody(body);
    NSData *json = [NSJSONSerialization dataWithJSONObject:safeBody options:0 error:nil];
    NSUInteger maximum = [DHConfig shared].webkitProbeMaxBytes;
    BOOL truncated = json.length > maximum;
    if (truncated) json = [json subdataWithRange:NSMakeRange(0, maximum)];
    DHLogEntry *entry = [DHLogEntry entryWithCategory:@"WEBKIT"
                                            algorithm:@"WEBKIT-PROBE"
                                            operation:safeBody[@"kind"] ?: @"observe"];
    entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : @"{}";
    if (truncated) entry.detail = [entry.detail stringByAppendingString:@"\n<truncated>"];
    NSString *bodyText = [safeBody[@"body"] isKindOfClass:NSString.class] ? safeBody[@"body"] : nil;
    if (bodyText.length) entry.input = [bodyText dataUsingEncoding:NSUTF8StringEncoding];
    entry.callStack = DHFilteredCallStack();
    [[DHLogStore shared] append:entry];
}
@end

static NSString *DHProbeJavaScript(void) {
    NSUInteger maximum = [DHConfig shared].webkitProbeMaxBytes;
    NSString *script =
    @"(function(){if(window.__dhProbe)return;window.__dhProbe=1;"
     "var M=__MAX__,C=function(v){try{v=String(v);return v.length>M?v.slice(0,M):v}catch(e){return ''}},"
     "H=function(h){var o={};try{if(h&&h.forEach)h.forEach(function(v,k){o[k]=C(v)})}catch(e){}return o},"
     "R=function(k,d){try{d=d||{};d.kind=k;d.ts=Date.now();d.url=d.url?new URL(d.url,location.href).href:location.href;window.webkit.messageHandlers.dhProbe.postMessage(d)}catch(e){}};"
     "var F=window.fetch;if(F)window.fetch=function(i,o){o=o||{};var u=typeof i==='string'?i:(i&&i.url)||'',m=o.method||(i&&i.method)||'GET';R('fetch.request',{url:u,method:m,headers:H(o.headers||(i&&i.headers)),body:C(o.body)});return F.apply(this,arguments).then(function(x){try{x.clone().text().then(function(t){R('fetch.response',{url:x.url||u,status:x.status,headers:H(x.headers),body:C(t)})})}catch(e){R('fetch.response',{url:x.url||u,status:x.status,headers:H(x.headers)})}return x})};"
     "var O=XMLHttpRequest.prototype.open,S=XMLHttpRequest.prototype.send,Q=XMLHttpRequest.prototype.setRequestHeader;XMLHttpRequest.prototype.open=function(m,u){this.__dh={method:m,url:u,headers:{}};return O.apply(this,arguments)};XMLHttpRequest.prototype.setRequestHeader=function(k,v){if(this.__dh)this.__dh.headers[k]=v;return Q.apply(this,arguments)};XMLHttpRequest.prototype.send=function(b){var x=this;R('xhr.request',{url:x.__dh&&x.__dh.url,method:x.__dh&&x.__dh.method,headers:x.__dh&&x.__dh.headers,body:C(b)});x.addEventListener('load',function(){var q='';try{q=(x.responseType===''||x.responseType==='text')?x.responseText:'[binary]'}catch(e){}R('xhr.response',{url:x.responseURL,status:x.status,body:C(q)})});return S.apply(this,arguments)};"
     "var W=window.WebSocket;if(W){var X=function(u,p){var w=p===undefined?new W(u):new W(u,p);R('websocket.open',{url:u});w.addEventListener('message',function(e){R('websocket.recv',{url:u,body:C(e.data)})});var s=w.send;w.send=function(d){R('websocket.send',{url:u,body:C(d)});return s.apply(w,arguments)};return w};X.prototype=W.prototype;window.WebSocket=X}"
     "if(navigator.sendBeacon){var B=navigator.sendBeacon;navigator.sendBeacon=function(u,d){R('beacon',{url:u,body:C(d)});return B.apply(this,arguments)}}"
     "if(window.EventSource){var E=window.EventSource;window.EventSource=function(u,c){R('eventsource.open',{url:u});return new E(u,c)}}"
     "if(window.Storage){var P=Storage.prototype,A=P.setItem,D=P.removeItem,L=P.clear;P.setItem=function(k,v){R((this===localStorage?'localStorage':'sessionStorage')+'.set',{key:C(k),body:C(v)});return A.apply(this,arguments)};P.removeItem=function(k){R((this===localStorage?'localStorage':'sessionStorage')+'.remove',{key:C(k)});return D.apply(this,arguments)};P.clear=function(){R((this===localStorage?'localStorage':'sessionStorage')+'.clear',{});return L.apply(this,arguments)}}"
     "if(window.console){['log','info','warn','error'].forEach(function(n){var z=console[n];if(z)console[n]=function(){try{R('console.'+n,{body:C([].slice.call(arguments).join(' '))})}catch(e){}return z.apply(console,arguments)}})}"
     "if(window.crypto&&crypto.subtle){var T=crypto.subtle;['digest','encrypt','decrypt','sign','verify','deriveBits','importKey','exportKey'].forEach(function(n){var z=T[n];if(z)T[n]=function(){var a=arguments,q=a[0];R('crypto.'+n,{algorithm:q&&(q.name||q)});return z.apply(this,arguments)}})}"
     "})();";
    return [script stringByReplacingOccurrencesOfString:@"__MAX__"
                                             withString:[NSString stringWithFormat:@"%lu", (unsigned long)maximum]];
}

static void DHInstallProbeOnView(WKWebView *view) {
    if (!view || ![DHConfig shared].webkitProbeEnabled || objc_getAssociatedObject(view, kDHProbeInstalledKey)) return;
    DHWebKitProbeBridge *bridge = [DHWebKitProbeBridge new];
    WKUserContentController *controller = view.configuration.userContentController;
    [controller addScriptMessageHandler:bridge name:@"dhProbe"];
    WKUserScript *script = [[WKUserScript alloc] initWithSource:DHProbeJavaScript()
                                                  injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                               forMainFrameOnly:NO];
    [controller addUserScript:script];
    objc_setAssociatedObject(view, kDHProbeBridgeKey, bridge, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(view, kDHProbeInstalledKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static id DHHookedWKInit(id self, SEL selector, CGRect frame, WKWebViewConfiguration *configuration) {
    id view = gOriginalWKInit ? gOriginalWKInit(self, selector, frame, configuration) : nil;
    DHInstallProbeOnView(view);
    return view;
}

static BOOL DHInstallWKMethod(void) {
    Method method = class_getInstanceMethod(WKWebView.class, @selector(initWithFrame:configuration:));
    if (!method) return NO;
    gOriginalWKInit = (DHWKInitFn)method_getImplementation(method);
    method_setImplementation(method, (IMP)DHHookedWKInit);
    return YES;
}

NSDictionary<NSString *, id> *DHWebKitProbeSnapshot(void) {
    return @{
        @"enabled": @([DHConfig shared].webkitProbeEnabled),
        @"redact": @([DHConfig shared].webkitProbeRedact),
        @"maxBytes": @([DHConfig shared].webkitProbeMaxBytes),
        @"allowDomains": [DHConfig shared].webkitProbeAllowDomains ?: @[],
        @"denyDomains": [DHConfig shared].webkitProbeDenyDomains ?: @[],
        @"hookInstalled": @(gOriginalWKInit != NULL),
        @"note": @"Configuration changes apply to newly created WKWebView instances."
    };
}

void DHInstallWebKitProbeHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        DHRegisterHook(@"WKWebView.initWithFrame:configuration:", @"objc", DHInstallWKMethod());
    });
}
