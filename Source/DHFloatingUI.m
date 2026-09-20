#import "DHFloatingUI.h"
#import "DHConfig.h"
#import "DHHTTPServer.h"
#import "DHLogStore.h"
#import <UIKit/UIKit.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

@interface DHPassthroughWindow : UIWindow
@end

@implementation DHPassthroughWindow

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    UIView *root = self.rootViewController.view;
    return hit == self || hit == root ? nil : hit;
}

@end

static NSString *DHDeviceIPv4Address(void) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0 || !interfaces) return @"127.0.0.1";
    NSString *fallback = nil;
    for (struct ifaddrs *cursor = interfaces; cursor; cursor = cursor->ifa_next) {
        if (!cursor->ifa_addr || cursor->ifa_addr->sa_family != AF_INET) continue;
        if (!(cursor->ifa_flags & IFF_UP) || (cursor->ifa_flags & IFF_LOOPBACK)) continue;
        char buffer[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in *address = (struct sockaddr_in *)cursor->ifa_addr;
        if (!inet_ntop(AF_INET, &address->sin_addr, buffer, sizeof(buffer))) continue;
        NSString *value = [NSString stringWithUTF8String:buffer];
        NSString *name = cursor->ifa_name ? [NSString stringWithUTF8String:cursor->ifa_name] : @"";
        if ([name isEqualToString:@"en0"]) {
            fallback = value;
            break;
        }
        if (!fallback.length) fallback = value;
    }
    freeifaddrs(interfaces);
    return fallback.length ? fallback : @"127.0.0.1";
}

static UIWindowScene *DHForegroundWindowScene(void) API_AVAILABLE(ios(13.0)) {
    UIWindowScene *fallback = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        if (scene.activationState == UISceneActivationStateForegroundActive) return windowScene;
        if (!fallback && scene.activationState == UISceneActivationStateForegroundInactive) fallback = windowScene;
    }
    return fallback;
}

@interface DHFloatingController : NSObject
@property (nonatomic, strong) DHPassthroughWindow *overlayWindow;
@property (nonatomic, weak) UIWindowScene *attachedScene;
@property (nonatomic, strong) UIButton *bubble;
@property (nonatomic, strong) UILabel *badgeLabel;
@property (nonatomic, strong) UIView *panel;
@property (nonatomic, strong) UILabel *statsLabel;
@property (nonatomic, strong) UILabel *urlLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *pauseButton;
@property (nonatomic, strong) NSTimer *refreshTimer;
@end

@implementation DHFloatingController

+ (instancetype)sharedController {
    static DHFloatingController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ controller = [DHFloatingController new]; });
    return controller;
}

- (void)start {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        [center addObserver:self selector:@selector(applicationBecameActive:)
                       name:UIApplicationDidBecomeActiveNotification object:nil];
        [center addObserver:self selector:@selector(applicationBecameActive:)
                       name:UIApplicationWillEnterForegroundNotification object:nil];
        [center addObserver:self selector:@selector(applicationBecameActive:)
                       name:UIWindowDidBecomeKeyNotification object:nil];
        if (@available(iOS 13.0, *)) {
            [center addObserver:self selector:@selector(applicationBecameActive:)
                           name:UISceneDidActivateNotification object:nil];
            [center addObserver:self selector:@selector(applicationBecameActive:)
                           name:UISceneWillEnterForegroundNotification object:nil];
        }
        [self installIfPossible];
        [self scheduleInstallRetries];
        self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self
                                                           selector:@selector(refreshStatus)
                                                           userInfo:nil repeats:YES];
    });
}

- (void)applicationBecameActive:(NSNotification *)notification {
    (void)notification;
    [self installIfPossible];
    [self scheduleInstallRetries];
}

- (void)scheduleInstallRetries {
    NSArray<NSNumber *> *delays = @[@0.05, @0.20, @0.50, @1.0, @2.0];
    for (NSNumber *delay in delays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self installIfPossible];
        });
    }
}

- (void)installIfPossible {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self installIfPossible]; });
        return;
    }
    UIApplication *application = UIApplication.sharedApplication;
    if (!application) return;
    UIWindowScene *scene = nil;
    if (@available(iOS 13.0, *)) scene = DHForegroundWindowScene();
    if (self.overlayWindow && (!scene || self.attachedScene == scene)) {
        [self refreshStatus];
        return;
    }
    [self.overlayWindow resignKeyWindow];
    self.overlayWindow.hidden = YES;
    self.overlayWindow = nil;
    self.attachedScene = scene;

    CGRect bounds = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
    DHPassthroughWindow *window;
    if (@available(iOS 13.0, *)) {
        window = scene ? [[DHPassthroughWindow alloc] initWithWindowScene:scene]
                       : [[DHPassthroughWindow alloc] initWithFrame:bounds];
    } else {
        window = [[DHPassthroughWindow alloc] initWithFrame:bounds];
    }
    window.frame = bounds;
    window.backgroundColor = UIColor.clearColor;
    window.windowLevel = UIWindowLevelAlert + 96.0;
    UIViewController *rootController = [UIViewController new];
    rootController.view.backgroundColor = UIColor.clearColor;
    window.rootViewController = rootController;
    self.overlayWindow = window;
    [self buildInterfaceInView:rootController.view];
    [rootController.view setNeedsLayout];
    [rootController.view layoutIfNeeded];
    window.hidden = ![DHConfig shared].floatingUIEnabled;
    [self refreshStatus];
}

- (UIButton *)actionButtonWithTitle:(NSString *)title selector:(SEL)selector {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    button.backgroundColor = [UIColor colorWithRed:0.16 green:0.19 blue:0.27 alpha:1.0];
    button.layer.cornerRadius = 9.0;
    [button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)buildInterfaceInView:(UIView *)rootView {
    CGFloat size = 54.0;
    CGRect bounds = rootView.bounds;
    UIButton *bubble = [UIButton buttonWithType:UIButtonTypeCustom];
    bubble.frame = CGRectMake(MAX(12.0, CGRectGetWidth(bounds) - size - 18.0),
                              MAX(100.0, CGRectGetHeight(bounds) * 0.28), size, size);
    bubble.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleBottomMargin;
    bubble.backgroundColor = [UIColor colorWithRed:0.38 green:0.30 blue:0.95 alpha:0.96];
    bubble.layer.cornerRadius = size / 2.0;
    bubble.layer.borderWidth = 1.0;
    bubble.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.25].CGColor;
    bubble.layer.shadowColor = UIColor.blackColor.CGColor;
    bubble.layer.shadowOpacity = 0.30;
    bubble.layer.shadowRadius = 8.0;
    bubble.layer.shadowOffset = CGSizeMake(0, 3);
    [bubble setTitle:@"DH" forState:UIControlStateNormal];
    [bubble setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    bubble.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    bubble.accessibilityLabel = @"Decrypt Helper 浮动控制台";
    [bubble addTarget:self action:@selector(togglePanel) forControlEvents:UIControlEventTouchUpInside];
    [bubble addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(dragBubble:)]];
    [rootView addSubview:bubble];
    self.bubble = bubble;

    UILabel *badge = [[UILabel alloc] initWithFrame:CGRectMake(size - 17.0, -3.0, 21.0, 21.0)];
    badge.backgroundColor = [UIColor colorWithRed:0.96 green:0.30 blue:0.38 alpha:1.0];
    badge.textColor = UIColor.whiteColor;
    badge.font = [UIFont monospacedDigitSystemFontOfSize:9 weight:UIFontWeightBold];
    badge.textAlignment = NSTextAlignmentCenter;
    badge.layer.cornerRadius = 10.5;
    badge.layer.masksToBounds = YES;
    badge.userInteractionEnabled = NO;
    [bubble addSubview:badge];
    self.badgeLabel = badge;

    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 306.0, 224.0)];
    panel.backgroundColor = [UIColor colorWithRed:0.055 green:0.067 blue:0.105 alpha:0.97];
    panel.layer.cornerRadius = 17.0;
    panel.layer.borderWidth = 1.0;
    panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;
    panel.layer.shadowColor = UIColor.blackColor.CGColor;
    panel.layer.shadowOpacity = 0.34;
    panel.layer.shadowRadius = 14.0;
    panel.layer.shadowOffset = CGSizeMake(0, 5);
    panel.hidden = YES;
    [rootView addSubview:panel];
    self.panel = panel;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(16, 12, 238, 25)];
    title.text = @"Decrypt Helper";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBold];
    [panel addSubview:title];

    UIButton *close = [self actionButtonWithTitle:@"×" selector:@selector(togglePanel)];
    close.frame = CGRectMake(262, 9, 32, 30);
    close.titleLabel.font = [UIFont systemFontOfSize:21 weight:UIFontWeightRegular];
    close.backgroundColor = UIColor.clearColor;
    [panel addSubview:close];

    UILabel *stats = [[UILabel alloc] initWithFrame:CGRectMake(16, 43, 274, 21)];
    stats.textColor = [UIColor colorWithRed:0.72 green:0.76 blue:0.86 alpha:1.0];
    stats.font = [UIFont monospacedDigitSystemFontOfSize:11 weight:UIFontWeightRegular];
    [panel addSubview:stats];
    self.statsLabel = stats;

    UILabel *url = [[UILabel alloc] initWithFrame:CGRectMake(16, 66, 274, 34)];
    url.textColor = [UIColor colorWithRed:0.50 green:0.72 blue:1.0 alpha:1.0];
    url.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    url.numberOfLines = 2;
    url.lineBreakMode = NSLineBreakByCharWrapping;
    [panel addSubview:url];
    self.urlLabel = url;

    UIButton *open = [self actionButtonWithTitle:@"打开 Web" selector:@selector(openWebConsole)];
    UIButton *copy = [self actionButtonWithTitle:@"复制 URL" selector:@selector(copyWebURL)];
    UIButton *pause = [self actionButtonWithTitle:@"暂停采集" selector:@selector(togglePause)];
    UIButton *clear = [self actionButtonWithTitle:@"清空事件" selector:@selector(clearEvents)];
    clear.backgroundColor = [UIColor colorWithRed:0.42 green:0.15 blue:0.19 alpha:1.0];
    pause.frame = CGRectZero;
    self.pauseButton = pause;

    UIStackView *rowOne = [[UIStackView alloc] initWithArrangedSubviews:@[open, copy]];
    rowOne.axis = UILayoutConstraintAxisHorizontal;
    rowOne.distribution = UIStackViewDistributionFillEqually;
    rowOne.spacing = 8.0;
    UIStackView *rowTwo = [[UIStackView alloc] initWithArrangedSubviews:@[pause, clear]];
    rowTwo.axis = UILayoutConstraintAxisHorizontal;
    rowTwo.distribution = UIStackViewDistributionFillEqually;
    rowTwo.spacing = 8.0;
    UIStackView *actions = [[UIStackView alloc] initWithArrangedSubviews:@[rowOne, rowTwo]];
    actions.frame = CGRectMake(16, 105, 274, 78);
    actions.axis = UILayoutConstraintAxisVertical;
    actions.distribution = UIStackViewDistributionFillEqually;
    actions.spacing = 8.0;
    [panel addSubview:actions];

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 190, 274, 20)];
    status.textColor = [UIColor colorWithWhite:0.66 alpha:1.0];
    status.font = [UIFont systemFontOfSize:11];
    status.textAlignment = NSTextAlignmentCenter;
    [panel addSubview:status];
    self.statusLabel = status;
    [self placePanel];
}

- (NSString *)webURLString {
    return [NSString stringWithFormat:@"http://%@:%u/", DHDeviceIPv4Address(), DHHTTPServerPort()];
}

- (void)refreshStatus {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self refreshStatus]; });
        return;
    }
    BOOL enabled = [DHConfig shared].floatingUIEnabled;
    self.overlayWindow.hidden = !enabled;
    if (!enabled || !self.overlayWindow) return;
    NSUInteger count = [DHLogStore shared].totalCount;
    self.badgeLabel.text = count > 99 ? @"99+" : [NSString stringWithFormat:@"%lu", (unsigned long)count];
    self.badgeLabel.hidden = count == 0;
    self.statsLabel.text = [NSString stringWithFormat:@"PID %d  ·  %lu events  ·  port %u",
                            NSProcessInfo.processInfo.processIdentifier, (unsigned long)count, DHHTTPServerPort()];
    self.urlLabel.text = [self webURLString];
    BOOL paused = [DHConfig shared].paused;
    [self.pauseButton setTitle:paused ? @"继续采集" : @"暂停采集" forState:UIControlStateNormal];
    self.pauseButton.backgroundColor = paused
        ? [UIColor colorWithRed:0.52 green:0.34 blue:0.10 alpha:1.0]
        : [UIColor colorWithRed:0.16 green:0.19 blue:0.27 alpha:1.0];
    self.bubble.accessibilityValue = [NSString stringWithFormat:@"%lu 个事件，%@",
                                      (unsigned long)count, paused ? @"已暂停" : @"采集中"];
}

- (void)togglePanel {
    self.panel.hidden = !self.panel.hidden;
    self.statusLabel.text = @"";
    [self placePanel];
    [self refreshStatus];
}

- (void)dragBubble:(UIPanGestureRecognizer *)recognizer {
    UIView *root = self.overlayWindow.rootViewController.view;
    CGPoint translation = [recognizer translationInView:root];
    self.bubble.center = CGPointMake(self.bubble.center.x + translation.x, self.bubble.center.y + translation.y);
    [recognizer setTranslation:CGPointZero inView:root];
    if (recognizer.state == UIGestureRecognizerStateEnded || recognizer.state == UIGestureRecognizerStateCancelled) {
        UIEdgeInsets insets = root.safeAreaInsets;
        CGFloat half = CGRectGetWidth(self.bubble.bounds) / 2.0;
        CGFloat minX = insets.left + half + 8.0;
        CGFloat maxX = CGRectGetWidth(root.bounds) - insets.right - half - 8.0;
        CGFloat minY = insets.top + half + 8.0;
        CGFloat maxY = CGRectGetHeight(root.bounds) - insets.bottom - half - 8.0;
        CGPoint center = self.bubble.center;
        center.x = MIN(MAX(center.x, minX), maxX);
        center.y = MIN(MAX(center.y, minY), maxY);
        center.x = center.x < CGRectGetMidX(root.bounds) ? minX : maxX;
        [UIView animateWithDuration:0.18 animations:^{ self.bubble.center = center; [self placePanel]; }];
    } else {
        [self placePanel];
    }
}

- (void)placePanel {
    if (!self.panel || !self.bubble) return;
    UIView *root = self.overlayWindow.rootViewController.view;
    CGRect bounds = root.bounds;
    CGFloat width = MIN(306.0, CGRectGetWidth(bounds) - 24.0);
    CGRect frame = self.panel.frame;
    frame.size.width = width;
    CGFloat x = CGRectGetMidX(self.bubble.frame) < CGRectGetMidX(bounds)
        ? CGRectGetMaxX(self.bubble.frame) + 8.0
        : CGRectGetMinX(self.bubble.frame) - width - 8.0;
    if (x < 12.0 || x + width > CGRectGetWidth(bounds) - 12.0) {
        x = MIN(MAX(12.0, CGRectGetMidX(self.bubble.frame) - width / 2.0), CGRectGetWidth(bounds) - width - 12.0);
    }
    CGFloat y = CGRectGetMidY(self.bubble.frame) - frame.size.height / 2.0;
    UIEdgeInsets insets = root.safeAreaInsets;
    y = MIN(MAX(y, insets.top + 8.0), CGRectGetHeight(bounds) - insets.bottom - frame.size.height - 8.0);
    frame.origin = CGPointMake(x, y);
    self.panel.frame = frame;
}

- (void)showStatus:(NSString *)text {
    self.statusLabel.text = text;
}

- (void)copyWebURL {
    UIPasteboard.generalPasteboard.string = [self webURLString];
    [self showStatus:@"Web 地址已复制"];
}

- (void)openWebConsole {
    NSURL *url = [NSURL URLWithString:[self webURLString]];
    if (!url) return;
    [UIApplication.sharedApplication openURL:url options:@{} completionHandler:^(BOOL success) {
        [self showStatus:success ? @"已打开浏览器" : @"无法打开浏览器"];
    }];
}

- (void)togglePause {
    NSError *error = nil;
    BOOL paused = ![DHConfig shared].paused;
    BOOL success = [[DHConfig shared] setPaused:paused error:&error];
    [self showStatus:success ? (paused ? @"采集已暂停" : @"采集已继续")
                             : (error.localizedDescription ?: @"更新失败")];
    [self refreshStatus];
}

- (void)clearEvents {
    [[DHLogStore shared] clearAll];
    [self showStatus:@"事件已清空"];
    [self refreshStatus];
}

@end

void DHInstallFloatingUI(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ [[DHFloatingController sharedController] start]; });
}
