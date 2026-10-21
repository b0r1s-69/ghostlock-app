# GhostLock X6840 — x6840-v1

First public port release for the Infinix Smart 20 (X6840), kernel `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`.

## Assets

| Asset | SHA-256 |
|---|---|
| `GhostLock-patched3.apk` | `14dff5737cde0126a649e9424fc9a09320782e05d8768eb7743cbc85708771cd` |
| `X6840-6.6.118-final.conf` | `f18aeadb77cc34b44807e924c67555ef7b52e6b4c59f203dd3b1b5d4435c667f` |
| `ghostlock-x6840-final.patch` | `15e6fc6429a5e075292e070247b52558edc7dcc2b913a56c01351379f9ddb87d` |
| `sha256sums.txt` | — |

## Status

- **Shizuku path:** verified. W3 is skipped; `ksud late-load` loads KernelSU; `su -c id` returns root.
- **In-process W3:** the mask/value build fixes the panic but cannot clear seccomp. The child stays `Seccomp: 2`; `finit_module` is blocked; the module does not load. The final profile sets `w3_attempts=0`.
- **Root:** temporary; lost on reboot; bootloader stays locked.
- **Device:** exact kernel match required.

## APK

- package `com.ghostlock.app`
- versionCode `577`, versionName `1.2`
- minSdk `31`, targetSdk `37`
- signer `CN=GhostLock Test, O=Test`
- signer SHA-256 `57484e77dc0dbf74c94516d07ac2c2724e5bde0778991a7454f71babb079db2e`

The APK is test-signed. Verify the checksum or build from source.

## Install

1. Install BakaSU (`com.resukisu.resukisu`) and Shizuku (`moe.shizuku.privileged.api`).
2. `adb install -r GhostLock-patched3.apk`
3. Open GhostLock → **Advanced options → Parameter configuration**; confirm **Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k**. Unload any user profile.
4. Enable **Run via Shizuku**; start Shizuku; tap **Run**.
5. Verify:
   ```bash
   adb shell su -c id
   adb shell cat /proc/modules | grep kernelsu
   ```

After reboot, start Shizuku and Run again.

## What changed

- Added the X6840 kernel profile, index entry, and supported-device row.
- Added `WriteMode::SeccompFlags` / `SeccompMode` (masked flags + `mode=0, filter_count=1`) to remove the W3 zero-store panic.
- Documented why the in-process W3 write is a no-op on this kernel and why Shizuku is required.
- Added the full port/W3/profile/build/verification/security docs and sanitized evidence.

## Warning

Kernel exploit. Use only on a device you own and are authorized to modify. It can panic, reboot, corrupt memory, or lose data. The bootloader remains locked. No warranty.

Source and details: https://github.com/b0r1s-69/ghostlock-app
Upstream: https://github.com/YuKongA/ghostlock-app
