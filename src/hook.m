// AppSealing Bypass Dylib — Runtime Hooking
// Uses fishhook to intercept AppSealing detection functions at dyld level
// Compile: xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=14.0 \
//   -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//   -dynamiclib -o AppSealingBypass.dylib hook.m fishhook.c \
//   -framework Foundation -I. -fobjc-arc

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/syslog.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/ldsyms.h>
#include "fishhook.h"

// ============================================================
// The NAME of this dylib as seen by _dyld_get_image_name()
// We filter ourselves out of the image list.
// ============================================================
// NOTE: The actual filename on disk. Sideloadly injects it as:
// "AppSealingBypass.dylib" — change this if you rename the file!
#define DYLIB_NAME "AppSealingBypass.dylib"
#define DYLIB_NAME_ALT "libswiftCore.dylib"  // Spoof name (optional)

// ============================================================
// Logging — hidden, no fs writes, just syslog
// ============================================================
#define LOG_TAG "[Bypass] "
static void bypass_log(const char *msg) {
    syslog(LOG_NOTICE, "%s%s", LOG_TAG, msg);
}

static void bypass_logf(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    bypass_log(buf);
}

// ============================================================
// Original function pointers
// ============================================================
static int (*orig_stat)(const char *path, struct stat *buf);
static int (*orig_lstat)(const char *path, struct stat *buf);
static int (*orig_fstat)(int fd, struct stat *buf);
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int (*orig_fstatfs)(int fd, struct statfs *buf);
static int (*orig_open)(const char *path, int flags, ...);
static FILE* (*orig_fopen)(const char *path, const char *mode);
static void* (*orig_dlopen)(const char *path, int mode);
static void* (*orig_dlsym)(void *handle, const char *symbol);
static int (*orig_sysctl)(int *mib, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_access)(const char *path, int mode);
static char** (*orig_objc_copyClassNamesForImage)(const char *image, unsigned int *outCount);
static uint32_t (*orig_dyld_image_count)(void);
static const char* (*orig_dyld_get_image_name)(uint32_t index);
static const struct mach_header* (*orig_dyld_get_image_header)(uint32_t index);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t index);
static int (*orig_dladdr)(const void *addr, Dl_info *info);

// ============================================================
// Binary paths
// ============================================================
static char *g_binary_path = NULL;
static char *g_lic_path = NULL;

static void discover_paths(void) {
    if (g_binary_path) return;
    @autoreleasepool {
        NSBundle *bundle = [NSBundle mainBundle];
        NSString *execPath = [bundle executablePath];
        if (execPath) {
            g_binary_path = strdup([execPath UTF8String]);
        }
        NSString *bundlePath = [bundle bundlePath];
        if (bundlePath) {
            NSString *licPath = [bundlePath stringByAppendingPathComponent:@"appsealing.lic"];
            g_lic_path = strdup([licPath UTF8String]);
        }
        bypass_logf("Binary: %s", g_binary_path ?: "?");
        bypass_logf("License: %s", g_lic_path ?: "?");
    }
}

// ============================================================
// DYLD IMAGE HOOKS — 🎯 CRITICAL: Hide our dylib from AppSealing!
// ============================================================
// We use a FILTER approach: iterate through real images, skip ours,
// and present a clean list without our dylib.
// This is safer than just offsetting by 1.

static bool is_our_dylib(const char *name) {
    if (!name) return false;
    return (strstr(name, DYLIB_NAME) != NULL) ||
           (strstr(name, "Substrate") != NULL) ||
           (strstr(name, "substrate") != NULL) ||
           (strstr(name, "cynject") != NULL);
}

uint32_t hooked_dyld_image_count(void) {
    uint32_t real_count = orig_dyld_image_count();
    uint32_t filtered = 0;
    for (uint32_t i = 0; i < real_count; i++) {
        if (!is_our_dylib(orig_dyld_get_image_name(i))) {
            filtered++;
        }
    }
    return filtered;
}

// Get the Nth non-our image index
static uint32_t real_index_for_fake(uint32_t fake_idx) {
    uint32_t real_count = orig_dyld_image_count();
    uint32_t seen = 0;
    for (uint32_t i = 0; i < real_count; i++) {
        if (!is_our_dylib(orig_dyld_get_image_name(i))) {
            if (seen == fake_idx) return i;
            seen++;
        }
    }
    return fake_idx; // Fallback
}

const char* hooked_dyld_get_image_name(uint32_t index) {
    uint32_t real_idx = real_index_for_fake(index);
    return orig_dyld_get_image_name(real_idx);
}

const struct mach_header* hooked_dyld_get_image_header(uint32_t index) {
    uint32_t real_idx = real_index_for_fake(index);
    return orig_dyld_get_image_header(real_idx);
}

intptr_t hooked_dyld_get_image_vmaddr_slide(uint32_t index) {
    uint32_t real_idx = real_index_for_fake(index);
    return orig_dyld_get_image_vmaddr_slide(real_idx);
}

// ============================================================
// Hook: dladdr — hide our dylib's address range
// ============================================================
int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret != 0 && info->dli_fname) {
        if (strstr(info->dli_fname, DYLIB_NAME) ||
            strstr(info->dli_fname, DYLIB_NAME_ALT)) {
            // Pretend this address isn't in any known image
            return 0;
        }
    }
    return ret;
}

// ============================================================
// Hook: fopen — block integrity reads + jailbreak files
// ============================================================
FILE* hooked_fopen(const char *path, const char *mode) {
    if (!path) return orig_fopen(path, mode);

    // Block AppSealing from reading the license file
    if (g_lic_path && strstr(path, "appsealing.lic")) {
        bypass_log("Blocked: appsealing.lic read");
        errno = ENOENT;
        return NULL;
    }

    // Block AppSealing from reading the binary for hash check
    if (g_binary_path && strcmp(path, g_binary_path) == 0) {
        bypass_log("Blocked: binary read via fopen");
        errno = EACCES;
        return NULL;
    }

    // Block jailbreak-related paths
    static const char *jb_paths[] = {
        "/private/var/lib/apt/",
        "/private/var/mobile/Library/SBSettings",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/bin/bash", "/bin/sh",
        "/etc/apt", "/usr/libexec/cydia/",
        "/usr/sbin/sshd", "/usr/bin/sshd",
        "/var/lib/cydia", "/var/cache/apt",
        NULL
    };
    for (int i = 0; jb_paths[i]; i++) {
        if (strncmp(path, jb_paths[i], strlen(jb_paths[i])) == 0) {
            errno = ENOENT;
            return NULL;
        }
    }

    return orig_fopen(path, mode);
}

// ============================================================
// Hook: open — same as fopen (low-level)
// ============================================================
int hooked_open(const char *path, int flags, ...) {
    if (!path) return orig_open(path, flags);

    if (g_lic_path && strstr(path, "appsealing.lic")) {
        errno = ENOENT;
        return -1;
    }
    if (g_binary_path && strcmp(path, g_binary_path) == 0) {
        errno = EACCES;
        return -1;
    }

    return orig_open(path, flags);
}

// ============================================================
// Hook: stat/lstat — hide jailbreak files
// ============================================================
int hooked_stat(const char *path, struct stat *buf) {
    if (!path) return orig_stat(path, buf);

    static const char *hidden[] = {
        "/private/var/lib/apt/",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/bin/bash", "/bin/sh",
        "/etc/apt", NULL
    };
    for (int i = 0; hidden[i]; i++) {
        if (strncmp(path, hidden[i], strlen(hidden[i])) == 0) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_stat(path, buf);
}

int hooked_lstat(const char *path, struct stat *buf) {
    return hooked_stat(path, buf);
}

// ============================================================
// Hook: access
// ============================================================
int hooked_access(const char *path, int mode) {
    if (!path) return orig_access(path, mode);

    static const char *blocked[] = {
        "/private/var/lib/apt/",
        "/Applications/Cydia.app",
        "/bin/bash", "/bin/sh",
        "/etc/apt", NULL
    };
    for (int i = 0; blocked[i]; i++) {
        if (strncmp(path, blocked[i], strlen(blocked[i])) == 0) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_access(path, mode);
}

// ============================================================
// Hook: dlopen/dlsym — block substrate/tweak loading
// ============================================================
void* hooked_dlopen(const char *path, int mode) {
    if (!path) return orig_dlopen(path, mode);

    if (strstr(path, "Substrate") || strstr(path, "substrate") ||
        strstr(path, "cyc") || strstr(path, "CydiaSubstrate")) {
        bypass_logf("Blocked dlopen: %s", path);
        return NULL;
    }
    return orig_dlopen(path, mode);
}

void* hooked_dlsym(void *handle, const char *symbol) {
    if (!symbol) return orig_dlsym(handle, symbol);

    if (strstr(symbol, "MSHook") || strstr(symbol, "Substrate")) {
        return NULL;
    }
    return orig_dlsym(handle, symbol);
}

// ============================================================
// Hook: sysctl — hide debugger + suspicious processes
// ============================================================
int hooked_sysctl(int *mib, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // Block KERN_PROC (process listing — AppSealing scans for debuggers)
    if (namelen >= 2 && mib[0] == CTL_KERN && mib[1] == KERN_PROC) {
        if (oldp && oldlenp) {
            *oldlenp = 0;  // Empty process list
        }
        return 0;
    }
    // Block KERN_PROCARGS (process args — shows injected dylib paths)
    if (namelen >= 3 && mib[0] == CTL_KERN && mib[1] == KERN_PROCARGS2) {
        errno = EACCES;
        return -1;
    }
    return orig_sysctl(mib, namelen, oldp, oldlenp, newp, newlen);
}

int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name) return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);

    if (strstr(name, "debug") || strstr(name, "proc_info") ||
        strstr(name, "kern.proc")) {
        if (oldp && oldlenp) *oldlenp = 0;
        return 0;
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// Hook: objc_copyClassNamesForImage — hide injected classes
// ============================================================
char** hooked_objc_copyClassNamesForImage(const char *image, unsigned int *outCount) {
    if (!image) return orig_objc_copyClassNamesForImage(image, outCount);

    // Block queries for our own dylib
    if (strstr(image, DYLIB_NAME) || strstr(image, "Substrate")) {
        if (outCount) *outCount = 0;
        return NULL;
    }

    return orig_objc_copyClassNamesForImage(image, outCount);
}

// ============================================================
// Constructor — runs BEFORE AppSealing's init
// Priority 1 = as early as possible
// ============================================================
__attribute__((constructor(1)))
static void bypass_init(void) {
    @autoreleasepool {
        discover_paths();

        // Store original dyld count (for reference only)
        uint32_t dyld_count = _dyld_image_count();

        // Register ALL hooks via fishhook
        struct rebinding bindings[] = {
            // Dyld image hiding (CRITICAL FOR APPSEALING)
            {"_dyld_image_count", hooked_dyld_image_count, (void**)&orig_dyld_image_count},
            {"_dyld_get_image_name", hooked_dyld_get_image_name, (void**)&orig_dyld_get_image_name},
            {"_dyld_get_image_header", hooked_dyld_get_image_header, (void**)&orig_dyld_get_image_header},
            {"_dyld_get_image_vmaddr_slide", hooked_dyld_get_image_vmaddr_slide, (void**)&orig_dyld_get_image_vmaddr_slide},
            {"dladdr", hooked_dladdr, (void**)&orig_dladdr},

            // File I/O blocking (prevent integrity hash check)
            {"fopen", hooked_fopen, (void**)&orig_fopen},
            {"open", hooked_open, (void**)&orig_open},

            // File hiding (jailbreak + license)
            {"stat", hooked_stat, (void**)&orig_stat},
            {"lstat", hooked_lstat, (void**)&orig_lstat},
            {"access", hooked_access, (void**)&orig_access},

            // Library loading
            {"dlopen", hooked_dlopen, (void**)&orig_dlopen},
            {"dlsym", hooked_dlsym, (void**)&orig_dlsym},

            // System introspection
            {"sysctl", hooked_sysctl, (void**)&orig_sysctl},
            {"sysctlbyname", hooked_sysctlbyname, (void**)&orig_sysctlbyname},

            // ObjC runtime
            {"objc_copyClassNamesForImage", hooked_objc_copyClassNamesForImage, (void**)&orig_objc_copyClassNamesForImage},
        };

        int n = sizeof(bindings) / sizeof(bindings[0]);
        int ret = rebind_symbols(bindings, n);

        if (ret == 0) {
            bypass_logf("SUCCESS: %d hooks installed. Original dyld count: %u", n, dyld_count);
        } else {
            bypass_logf("FAILED: rebind_symbols returned %d", ret);
        }
    }
}
