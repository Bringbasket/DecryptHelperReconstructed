#import "DHWebConsole.h"

#include "DHWebConsoleBase64.inc"

NSString *DHWebConsoleHTML(void) {
    static NSString *html;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSData *data = [[NSData alloc] initWithBase64EncodedString:kDHWebConsoleBase64 options:0];
        html = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        if (!html.length) html = @"<!doctype html><meta charset='utf-8'><title>Decrypt Helper</title><p>Web console unavailable.</p>";
    });
    return html;
}
