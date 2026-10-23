# Build and install

## Prerequisites

- The upstream GhostLock source at commit `bf836bc` (this fork).
- Android NDK (the reference build used the ONDK/LLVM toolchain with API 35).
- Android SDK build-tools (`zipalign`, `apksigner`) and a JDK.
- The upstream release APK (for the in-place repack) or a Gradle build.
- The matching firmware (`boot.img`, `vendor_boot.img`) if you need to re-extract offsets.
- A test keystore. The published APK uses a test key:
  `CN=GhostLock Test, O=Test`, SHA-256 `57484e77dc0dbf74c94516d07ac2c2724e5bde0778991a7454f71babb079db2e`.
- BakaSU for the root manager. Shizuku is optional (shell flow only).

## Build the native core

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
make -C src ghostlock
# -> build/native/ghostlock (arm64 PIE)
```

The build uses `aarch64-linux-android35-clang++`, C++23, LTO, and `-static-libstdc++`. Strip before packaging:

```bash
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip \
  --strip-all build/native/ghostlock
```

The W3 zero-store code is in:

- `src/core/session/backend/cve_2026_43499_backend.cpp` — `w3()`: park, two zero stores,
  resume, read-back, probe.
- `src/core/session/victim_process.cpp` — the `S` protocol step (`raise(SIGSTOP)`, then
  report `Seccomp:`), `stop_child()`, `continue_and_report_seccomp()`.
- `src/core/memory/payload_builder.h` — the documented value space (zero or a kernel
  pointer; there is no mask arm).

## Build the release APK

Gradle builds and signs the APK in one step. A keystore is optional: without one the
release variant falls back to the debug key, which is fine for a local test device but
cannot replace an APK signed by another key.

```bash
# local.properties (gitignored)
sdk.dir=/path/to/android-sdk
ndk.dir=/path/to/android-sdk/ndk/<version>
KEYSTORE_PATH=/path/to/ghostlock-release.jks
KEYSTORE_PASS=...
KEY_ALIAS=ghostlock
KEY_PASSWORD=...

ANDROID_NDK_HOME=/path/to/android-sdk/ndk/<version> ./gradlew :app:assembleRelease
```

Output: `build/app/outputs/apk/release/GhostLock-v<versionName>(<versionCode>)-arm64-v8a-release.apk`.
The task first builds `build/native/ghostlock`, copies it to `app/src/main/jniLibs/`
stripped, and also builds the Rust extractor for `aarch64-linux-android`. `versionCode` is
`max(git rev-list --count HEAD, 578)` and `versionName` is set in `app/build.gradle.kts`.

Verify before publishing:

```bash
apksigner verify --print-certs build/app/outputs/apk/release/*.apk
unzip -p build/app/outputs/apk/release/*.apk \
  assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf | head -6
sha256sum build/app/outputs/apk/release/*.apk
```

If the APK replaces one signed with a different key, Android rejects it
(`INSTALL_FAILED_UPDATE_INCOMPATIBLE`); uninstall first, which also deletes app data.

## Repack the APK (historical, upstream-asset flow)

Use the upstream release APK as the base and replace only the native library and profile assets. A full rezip violates Android's `resources.arsc` stored/aligned rule.

```bash
cp GhostLock-release.apk GhostLock-patched.apk
mkdir -p apkwork/lib/arm64-v8a apkwork/assets/kernel_profiles
cp build/native/ghostlock apkwork/lib/arm64-v8a/libghostlock.so
cp app/src/main/assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf \
   apkwork/assets/kernel_profiles/
cp app/src/main/assets/kernel_profiles/index.conf apkwork/assets/kernel_profiles/

cd apkwork
zip -0 ../GhostLock-patched.apk lib/arm64-v8a/libghostlock.so
zip    ../GhostLock-patched.apk \
  assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf \
  assets/kernel_profiles/index.conf
cd ..

zipalign -f -p 4 GhostLock-patched.apk GhostLock-patched-aligned.apk
apksigner sign --ks test.keystore \
  --ks-pass pass:ghostlock --key-pass pass:ghostlock \
  --out GhostLock-patched3.apk GhostLock-patched-aligned.apk
apksigner verify GhostLock-patched3.apk
```

The published APK:

- package `com.ghostlock.app`
- versionCode `577`, versionName `1.2`
- minSdk `31`, targetSdk `37`
- SHA-256 `14dff5737cde0126a649e9424fc9a09320782e05d8768eb7743cbc85708771cd`

Verify the marker is present:

```bash
unzip -p GhostLock-patched3.apk lib/arm64-v8a/libghostlock.so \
  | strings | grep -m1 'TIF_SECCOMP mask'
```

## Install

```bash
adb install -r GhostLock-patched3.apk
```

Install BakaSU (`com.resukisu.resukisu`) first. GhostLock extracts `libksud.so` from the BakaSU APK during the handoff, in-process. Install Shizuku (`moe.shizuku.privileged.api`) only if you want the shell flow.

## Optional: Shizuku and wireless ADB

1. Enable **Developer options → Wireless debugging** on the phone.
2. Pair and connect as usual:
   ```bash
   adb pair <phone-ip>:<pair-port> <code>
   adb connect <phone-ip>:<connect-port>
   ```
   The connect port changes after reboots and after Shizuku starts. `tools/scan_adb.py` scans the current port:
   ```bash
   python3 tools/scan_adb.py <phone-ip>
   ```
3. Start Shizuku from its app (it launches its server as shell UID 2000 over the ADB connection).
4. Grant GhostLock the Shizuku permission.

## Load the profile and run

1. Open GhostLock → **Advanced options** → **Parameter configuration**.
2. Confirm **Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k**.
3. If a user profile is active, **Load configuration** → the profile → **Unload**.
4. Ensure **Run via Shizuku** is on.
5. Tap **Run**.
6. Verify:
   ```bash
   adb shell su -c id
   adb shell cat /proc/modules | grep kernelsu
   ```
7. After reboot the LKM is gone; tap **Run** again (add Shizuku only for the shell flow). Root is temporary.

## Release

Release `x6840-v1` contains:

- `GhostLock-patched3.apk`
- `X6840-6.6.118-final.conf`
- `ghostlock-x6840-final.patch`
- `sha256sums.txt`

The APK is test-signed; verify the checksum or build from source.

## Troubleshooting

**`INSTALL_FAILED_INVALID_APK` / `resources.arsc` must be stored uncompressed** — a full rezip was used. Rebuild by copying the original APK and updating only the lib/assets with `zip -0`.

**`INSTALL_FAILED_UPDATE_INCOMPATIBLE`** — the installed app has a different signing key. Uninstall first (this wipes app data) or sign with the same key.

**App shows `User profile: msf_88`** — unload the test overlay; the built-in final is the safe profile.

**`KernelSU module not loaded` with `Seccomp: 2`** — the in-process W3 path was used. Turn Shizuku on and run again; the shell path skips W3.

**Boot reason says `kernel_panic`** — check uptime. The mask/value build completes all steps; the reason is usually stale from an earlier zero-store run.

**ADB device offline after a run** — if it was a panic, wait for the reboot, re-enable wireless debugging, and reconnect. The connect port changes.
