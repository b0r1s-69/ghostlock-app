# GhostLock X6840 — x6840-v3

In-process release for the Infinix Smart 20 (X6840), kernel
`6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`.

**W3 now works in-process**: the rooted child is parked, `thread_info.flags` and
`seccomp.mode` are zeroed with the write primitive's zero-valued leaf arm, and a forked
probe proves the descendants inherit `Seccomp: 0`. No ADB, no Shizuku, the bootloader stays
locked, root stays temporary.

## Asset

| Asset | SHA-256 |
|---|---|
| `GhostLock-v1.3-584-arm64-v8a-x6840-v3.apk` | `859fa63910a57765d833e9d9c097cd6426bd3eeb50a03dcee718b438d5acb895` |
| `X6840-6.6.118-final.conf` | `7a2dba8ae21b8062f9db499c10ebc82905e0e8685957389eee3adbcfc666b82d` |
| `ghostlock-x6840-final.patch` | listed in [`release/sha256sums.txt`](../release/sha256sums.txt) |

APK facts:

- package `com.ghostlock.app`, versionCode `584`, versionName `1.3`
- minSdk `31`, targetSdk `37`, ABI `arm64-v8a` only
- built from the `x6840-v3` tag (branch `very-not-stable-dev`), on top of `x6840-v2`
- toolchain: JDK 21, NDK `27.3.13750724`, Gradle wrapper from this repository
- `lib/arm64-v8a/libghostlock.so` is the stripped native core built from this tree
  (inside the APK: `sha256 d9930ac4009cf4e794f10524b1d06b357d72a342c11156b51fa9fda9eb07adcf`)
- signed with a **new test key**: `CN=GhostLock Test, O=Test`, certificate SHA-256
  `f9cf7022f483871b05aa93d95ee82f253aae164bd4825fab3988845f07d86e2b`, APK Signature Scheme
  v3 (accepted from API 28; this app requires API 31)

> [!WARNING]
> The v1/v2 asset (`GhostLock-patched3.apk`) used a different signing key that is not in this
> repository. Android refuses to replace an app signed by another key, so installing this
> build over the old one fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. **Uninstall the old
> APK first** - that deletes the app's data, including any imported user profile. To keep
> upgrade-in-place, rebuild from source with the original key (`KEYSTORE_PATH` in
> `local.properties`).

## Status

- **In-process W3:** fixed (zero store). No ADB and no Shizuku are needed; the built-in
  profile ships `recommend_shizuku = 0`, `w3_attempts = 2`, `w3_chain_rounds = 2`,
  `w3_settle_us = 50000`.
- **Shizuku path:** still supported. A shell flow has no app filter (`Seccomp: 0`), so W3
  returns immediately with `no app seccomp filter (shell flow); skipping W3`.
- **Root:** temporary; the LKM is lost on reboot; the bootloader stays locked.
- **Device:** exact kernel match required.
- **Device gate:** **not run for this build.** The APK was built, signed and inspected
  (payload, profile asset, signature, class retention) but not executed on hardware here.
  The gate record is
  [`docs/analysis/device-gates/W3-ZERO-STORE.md`](../docs/analysis/device-gates/W3-ZERO-STORE.md);
  run it before publishing broadly.

## Install

1. Install the root manager (BakaSU, `com.resukisu.resukisu`). Shizuku
   (`moe.shizuku.privileged.api`) is optional.
2. Uninstall any previous GhostLock build signed by a different key.
3. `adb install -r "GhostLock-v1.3-584-arm64-v8a-x6840-v3.apk"`
4. Open GhostLock → **Advanced options → Parameter configuration**; confirm
   **Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k**, and unload any user
   profile.
5. Leave **Run via Shizuku** off and tap **Run**.
6. Verify:
   ```bash
   su -c id
   # uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
   cat /proc/modules | grep kernelsu
   # kernelsu 192512 1 - Live 0x0000000000000000 (O)
   ```

After a reboot the LKM is gone; tap **Run** again.

## What changed since x6840-v2

- W3 performs the seccomp clear instead of refusing it: park the rooted child
  (`victim_process` `S` step), zero `thread_info.flags`, zero the `{mode, filter_count}`
  word, re-zero the flags, resume, read back `Seccomp: 0`, then prove inheritance with a
  forked probe.
- `WriteMode::SeccompFlags` / `SeccompMode` are gone: the primitive stores only zero or a
  mapped kernel pointer, so a mask can never land.
- Adopted from v2's disarm review and now enforced by the working path:
  `run_state::fail()` / `RunStateCodec.Failed` (`completed` only after verification), the
  `-ESRCH` correction that demotes the `finit_module` errno probe to informational, and the
  note that `~(1<<bit)` was never a flag-preserving mask.
- New verdict: a forked child reporting `Seccomp: 0` proves `copy_seccomp()` stopped
  re-arming `TIF_SECCOMP`, which is the property `sh -> ksud` needs.
- Fixed `ProfileMerger.resolveMerged` aliasing the shared `execution-tuning.conf` preset:
  one profile's stage override leaked into every profile resolved later in the same process
  (this made the exporter disagree with the app, and could mix tuning between app loads).
- W3 hint strings now say "retry, Shizuku optional" instead of "W3 always fails".
- Tests: `X6840ProfileDefaultsTest` locks the in-process defaults; `ProfileMergerTest` locks
  the preset-aliasing fix; `backend_dataflow_test` asserts the W3 store plan and ordering for
  the app flow and asserts nothing is written in the shell flow;
  `ProfileMigrationEquivalenceTest` pins the nine bundled profiles the remote-main fixture
  predates.

## What changed in x6840-v2 (kept)

- `fix(w3): disarm unsupported seccomp writes and report failure honestly` - the disarm is
  superseded by this release, but its status/`fail()` contract and probe corrections are
  retained (see [`docs/analysis/W3-DISARM-RECORD.md`](../docs/analysis/W3-DISARM-RECORD.md),
  which now carries a "superseded" banner).
- `fix(build): clear bionic PAGE_SIZE macro`, so the native core builds on NDK r27+.
- `fix(build): floor versionCode` at 578+, so a fresh clone never installs as a downgrade.

## Verification performed for this asset

| Check | Result |
|---|---|
| `:app:testDebugUnitTest` | 82 tests, 0 failures |
| `:profile-core:test` | 19 tests, 0 failures |
| Native host suite (25 binaries + dataflow harness) | pass |
| `make -C src ghostlock` (NDK 27.3, API 35) | 0 warnings, arm64 PIE |
| `clang-tidy --warnings-as-errors` on changed TUs | 0 findings |
| APK payload | profile asset `recommend_shizuku=0`, `w3_attempts=2`; `libghostlock.so` matches the stripped build output |
| APK signature | `apksigner verify` OK (v3), certificate as listed above |
| Device gate | **not run** |
