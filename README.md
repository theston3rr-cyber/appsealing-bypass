# AppSealing Bypass Dylib for iOS

Runtime hooking dylib to bypass AppSealing v1.13.x integrity checks on non-jailbroken iOS devices.

## How it works

This dylib uses [fishhook](https://github.com/facebook/fishhook) to intercept AppSealing's detection functions at runtime:

| Hooked Function | Purpose |
|----------------|---------|
| `fopen` / `open` | Block AppSealing from reading binary & appsealing.lic for hash checking |
| `stat` / `lstat` / `access` | Hide jailbreak file signatures |
| `dlopen` / `dlsym` | Block AppSealing framework loading |
| `sysctl` / `sysctlbyname` | Hide debugger detection |
| `objc_copyClassNamesForImage` | Hide injected classes |

Since no binary code is modified, the integrity hash check PASSES.

## How to Build

### Option 1: GitHub Actions (Recommended)

1. Create a new **private** GitHub repository
2. Upload these files to the repo:
   ```
   .
   ├── .github/workflows/build.yml
   ├── src/
   │   ├── hook.m
   │   ├── fishhook.h
   │   └── fishhook.c
   └── README.md
   ```
3. Push to GitHub → Actions tab → workflow runs automatically
4. Download `AppSealingBypass.dylib` from Artifacts

### Option 2: Build Locally (macOS only)

```bash
# Requires Xcode + command line tools
cd src/
xcrun -sdk iphoneos clang \
  -arch arm64 \
  -miphoneos-version-min=14.0 \
  -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
  -dynamiclib -O2 \
  -o AppSealingBypass.dylib \
  hook.m fishhook.c \
  -framework Foundation \
  -fobjc-arc
```

## How to Inject

1. **Sign with Sideloadly:** Load the unmodified decrypted IPA
2. **CHECK** "Inject dylibs/frameworks"
3. Select `AppSealingBypass.dylib`
4. Sign and install as usual
5. The dylib loads automatically when the app starts

## How to Verify

After injecting, check the console log for:
```
[AppSealingBypass] AppSealingBypass initialized. 10 hooks registered.
```

## Files

| File | Description |
|------|-------------|
| `src/hook.m` | Main hooking code (Objective-C + C) |
| `src/fishhook.h` | Facebook fishhook library header |
| `src/fishhook.c` | Facebook fishhook library implementation |
| `.github/workflows/build.yml` | GitHub Actions workflow for compilation |
