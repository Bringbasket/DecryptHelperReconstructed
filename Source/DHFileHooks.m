#import "DHFileHooks.h"
#import "DHConfig.h"
#import "DHLogStore.h"
#import "fishhook.h"
#import <fcntl.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdlib.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/types.h>
#import <unistd.h>

#define DH_MAX_TRACKED_FD 4096

static __thread int gFileGuard;
static pthread_mutex_t gFDLock = PTHREAD_MUTEX_INITIALIZER;
static char *gFDPaths[DH_MAX_TRACKED_FD];

static BOOL DHIgnoreFilePath(const char *path) {
    if (!path) return YES;
    return strstr(path, "/Library/Caches/IOSDecryptHub/") != NULL ||
           strstr(path, "/usr/lib/IOSDecryptHub/") != NULL;
}

static void DHRememberFD(int fd, const char *path) {
    if (fd < 0 || fd >= DH_MAX_TRACKED_FD || DHIgnoreFilePath(path)) return;
    pthread_mutex_lock(&gFDLock);
    free(gFDPaths[fd]);
    gFDPaths[fd] = strdup(path);
    pthread_mutex_unlock(&gFDLock);
}

static char *DHCopyFDPath(int fd) {
    if (fd < 0 || fd >= DH_MAX_TRACKED_FD) return NULL;
    pthread_mutex_lock(&gFDLock);
    char *copy = gFDPaths[fd] ? strdup(gFDPaths[fd]) : NULL;
    pthread_mutex_unlock(&gFDLock);
    return copy;
}

static void DHForgetFD(int fd) {
    if (fd < 0 || fd >= DH_MAX_TRACKED_FD) return;
    pthread_mutex_lock(&gFDLock);
    free(gFDPaths[fd]);
    gFDPaths[fd] = NULL;
    pthread_mutex_unlock(&gFDLock);
}

static NSString *DHStringFromPath(const char *path) {
    if (!path) return @"";
    NSString *value = [NSString stringWithUTF8String:path];
    if (value) return value;
    return [[NSData dataWithBytes:path length:strlen(path)] base64EncodedStringWithOptions:0];
}

static void DHLogFile(NSString *category,
                      NSString *operation,
                      const char *path,
                      int fd,
                      const void *input,
                      size_t inputLength,
                      const void *output,
                      size_t outputLength,
                      NSDictionary *extra) {
    if (gFileGuard || ![DHConfig shared].fileEnabled || DHIgnoreFilePath(path)) return;
    gFileGuard++;
    @autoreleasepool {
        NSMutableDictionary *metadata = [@{
            @"path": DHStringFromPath(path),
            @"fd": @(fd)
        } mutableCopy];
        if (extra) [metadata addEntriesFromDictionary:extra];
        NSData *json = [NSJSONSerialization dataWithJSONObject:metadata options:0 error:nil];
        DHLogEntry *entry = [DHLogEntry entryWithCategory:category
                                                algorithm:@"POSIX"
                                                operation:operation];
        entry.detail = json ? [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] : nil;
        if (input && inputLength) entry.input = [NSData dataWithBytes:input length:inputLength];
        if (output && outputLength) entry.output = [NSData dataWithBytes:output length:outputLength];
        entry.callStack = DHFilteredCallStack();
        [[DHLogStore shared] append:entry];
    }
    gFileGuard--;
}

typedef int (*DHOpenFn)(const char *, int, ...);
typedef ssize_t (*DHReadFn)(int, void *, size_t);
typedef ssize_t (*DHPreadFn)(int, void *, size_t, off_t);
typedef ssize_t (*DHWriteFn)(int, const void *, size_t);
typedef void *(*DHMmapFn)(void *, size_t, int, int, int, off_t);
typedef int (*DHCloseFn)(int);
typedef int (*DHUnlinkFn)(const char *);
typedef int (*DHRenameFn)(const char *, const char *);

static DHOpenFn gOriginalOpen;
static DHReadFn gOriginalRead;
static DHPreadFn gOriginalPread;
static DHWriteFn gOriginalWrite;
static DHMmapFn gOriginalMmap;
static DHCloseFn gOriginalClose;
static DHUnlinkFn gOriginalUnlink;
static DHRenameFn gOriginalRename;

static int DHHookedOpen(const char *path, int flags, ...) {
    mode_t mode = 0;
    BOOL hasMode = (flags & O_CREAT) != 0;
    if (hasMode) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int fd = gOriginalOpen ?
        (hasMode ? gOriginalOpen(path, flags, mode) : gOriginalOpen(path, flags)) : -1;
    if ([DHConfig shared].fileEnabled && fd >= 0) DHRememberFD(fd, path);
    DHLogFile(@"FILE_OPEN", @"open", path, fd, NULL, 0, NULL, 0,
              @{ @"flags": @(flags), @"mode": @(mode), @"success": @(fd >= 0) });
    return fd;
}

static ssize_t DHHookedRead(int fd, void *buffer, size_t count) {
    ssize_t result = gOriginalRead ? gOriginalRead(fd, buffer, count) : -1;
    if ([DHConfig shared].fileEnabled && result > 0) {
        char *path = DHCopyFDPath(fd);
        if (path) {
            DHLogFile(@"FILE_READ", @"read", path, fd, NULL, 0, buffer, (size_t)result,
                      @{ @"requested": @(count), @"read": @(result) });
            free(path);
        }
    }
    return result;
}

static ssize_t DHHookedPread(int fd, void *buffer, size_t count, off_t offset) {
    ssize_t result = gOriginalPread ? gOriginalPread(fd, buffer, count, offset) : -1;
    if ([DHConfig shared].fileEnabled && result > 0) {
        char *path = DHCopyFDPath(fd);
        if (path) {
            DHLogFile(@"FILE_READ", @"pread", path, fd, NULL, 0, buffer, (size_t)result,
                      @{ @"requested": @(count), @"read": @(result), @"offset": @(offset) });
            free(path);
        }
    }
    return result;
}

static ssize_t DHHookedWrite(int fd, const void *buffer, size_t count) {
    ssize_t result = gOriginalWrite ? gOriginalWrite(fd, buffer, count) : -1;
    if ([DHConfig shared].fileEnabled && result > 0) {
        char *path = DHCopyFDPath(fd);
        if (path) {
            DHLogFile(@"FILE_WRITE", @"write", path, fd, buffer, (size_t)result, NULL, 0,
                      @{ @"requested": @(count), @"written": @(result) });
            free(path);
        }
    }
    return result;
}

static void *DHHookedMmap(void *address, size_t length, int protection,
                          int flags, int fd, off_t offset) {
    void *result = gOriginalMmap ?
        gOriginalMmap(address, length, protection, flags, fd, offset) : MAP_FAILED;
    if ([DHConfig shared].fileEnabled && result != MAP_FAILED) {
        char *path = DHCopyFDPath(fd);
        if (path) {
            DHLogFile(@"FILE_MMAP", @"mmap", path, fd, NULL, 0, NULL, 0,
                      @{
                          @"length": @(length), @"offset": @(offset),
                          @"protection": @(protection), @"flags": @(flags),
                          @"address": [NSString stringWithFormat:@"%p", result]
                      });
            free(path);
        }
    }
    return result;
}

static int DHHookedClose(int fd) {
    int result = gOriginalClose ? gOriginalClose(fd) : -1;
    if (result == 0) DHForgetFD(fd);
    return result;
}

static int DHHookedUnlink(const char *path) {
    int result = gOriginalUnlink ? gOriginalUnlink(path) : -1;
    DHLogFile(@"FILE_UNLINK", @"unlink", path, -1, NULL, 0, NULL, 0,
              @{ @"status": @(result) });
    return result;
}

static int DHHookedRename(const char *oldPath, const char *newPath) {
    int result = gOriginalRename ? gOriginalRename(oldPath, newPath) : -1;
    DHLogFile(@"FILE_RENAME", @"rename", oldPath, -1, NULL, 0, NULL, 0,
              @{ @"destination": DHStringFromPath(newPath), @"status": @(result) });
    return result;
}

void DHInstallFileHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {"open", (void *)DHHookedOpen, (void **)&gOriginalOpen},
            {"read", (void *)DHHookedRead, (void **)&gOriginalRead},
            {"pread", (void *)DHHookedPread, (void **)&gOriginalPread},
            {"write", (void *)DHHookedWrite, (void **)&gOriginalWrite},
            {"mmap", (void *)DHHookedMmap, (void **)&gOriginalMmap},
            {"close", (void *)DHHookedClose, (void **)&gOriginalClose},
            {"unlink", (void *)DHHookedUnlink, (void **)&gOriginalUnlink},
            {"rename", (void *)DHHookedRename, (void **)&gOriginalRename}
        };
        rebind_symbols(bindings, sizeof(bindings) / sizeof(bindings[0]));
    });
}
