# GhostLock X6840 — Infinix Smart 20 port

**A detailed, reproducible port of [GhostLock](https://github.com/YuKongA/ghostlock-app) to the Infinix Smart 20 (X6840), including a verified kernel profile, a complete W3/seccomp failure analysis, and a working Shizuku + BakaSU root path.**

> [!WARNING]
> GhostLock is a kernel exploit (CVE‑2026‑43499). This port was developed against one owned test device. Use it only on hardware you own and are authorized to modify. A wrong kernel profile can panic, corrupt kernel memory, reboot, or lose data. The bootloader stays locked and root is **temporary**.

---

## At a glance

| Item | Value |
|---|---|
| Device | Infinix Smart 20 (X6840) |
| SoC | MediaTek MT6769 / mt6768 |
| Android | 16 / SDK 36 / arm64-v8a |
| Build | `X6840-16.3.0.140SP09(OPPJ004PF001PJ)` |
| Kernel | `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k` |
| Bootloader | locked, verified boot **green**, SELinux **Enforcing** before the run |
| Root manager | BakaSU / ReSukiSU `v4.2.0-rc3` (`com.resukisu.resukisu`) |
| Root type | temporary LKM, loaded in-process; lost on reboot |
| Profile | built-in, `recommend_shizuku=0`, `w3_attempts=2` |
| App | GhostLock `1.2` (versionCode 577), built from upstream `bf836bc` + this port |
| Status | in-process W3 seccomp bypass **fixed** (zero-store); Shizuku optional |

### What works

- Installing GhostLock and loading the built-in X6840 profile.
- W1 (SELinux permissive) and W2 (credential overwrite) — the child reaches `uid=0`.
- **W3 without ADB or Shizuku**: the rooted child is parked, `thread_info.flags` and
  `seccomp.mode` are zeroed, and the child then reports `Seccomp: 0`.
- `ksud late-load` from that child, KernelSU loading, and `su -c id` returning root.
- BakaSU recognizing the LKM (`Working · LKM`).

### What does not

- Persistent root across reboot (bootloader locked).
- Any kernel other than the exact release above.
- Module loading from a *non-rooted* process: the app process still carries the zygote
  filter, so only the rooted child's chain can call `finit_module`.

---

## Quick start (release build)

The prebuilt APK is attached to the [x6840‑v1 release](https://github.com/b0r1s-69/ghostlock-app/releases/tag/x6840-v1). It is signed with a **test key**, not the upstream release key. Verify the checksum from `release/sha256sums.txt` before installing.

1. **Install the root manager** — [BakaSU](https://github.com/Baka-SU/BakaSU) (`com.resukisu.resukisu`). GhostLock extracts its `libksud.so` during the handoff.
2. **Install GhostLock** (the APK is also in the release; any installer works — ADB is only
   needed for this one step, not for the exploit):
   ```bash
   adb install -r GhostLock-patched3.apk
   ```
3. **Confirm the profile** — open GhostLock → **Advanced options** → **Parameter configuration**. It must read:
   ```
   Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k
   ```
   If a user profile is loaded (for example `msf_88`), open **Load configuration** → the profile → **Unload**. The built-in profile has `w3_attempts=2` and `recommend_shizuku=0`.
4. **Run in-process** — leave **Run via Shizuku** off and tap **Run**. No Shizuku server,
   no ADB, no PC.
5. **Verify** (any terminal app with root, or the manager):
   ```bash
   su -c id
   # uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
   cat /proc/modules | grep kernelsu
   # kernelsu 192512 1 - Live 0x0000000000000000 (O)
   ```
6. **After every reboot**: the LKM unloads. Tap **Run** again. Root is not persistent.

> Keep `w3_attempts > 0`. It is the in-process seccomp clear; this build performs it with
> zero stores while the rooted child is parked, which is the only value the write
> primitive can land. See [docs/W3-SECCOMP-ANALYSIS.md](docs/W3-SECCOMP-ANALYSIS.md).

---

## Why Shizuku is no longer needed

Shizuku was a workaround: its shell process (UID 2000) has **no app seccomp filter**, so
W3 could be skipped and `ksud late-load` could call `finit_module`. That path still works
and is still supported — the exploit skips W3 when `/proc/self/status` reports
`Seccomp: 0`.

The in-process path now works too. The app process carries the zygote filter, W3 removes
it, and the rooted child's whole descendant chain (`sh -> ksud -> ...`) runs filter-free,
so KernelSU loads without any external helper.

---

## The W3 fix in one minute

The write primitive stamps exactly two kinds of word: **zero** (the leaf arm) or a
**dereferenceable kernel pointer** (the value arm). A bit mask or a `0x1_00000000` word is
not a mapped address, so the relink walk never reaches the store — that is why the old
`SeccompFlags`/`SeccompMode` code reported success and changed nothing.

The seccomp state machine on this kernel allows a much simpler clear (arm64 6.6):

- the syscall gate is `TIF_SECCOMP`, bit 11 of `thread_info.flags` at `task+0x00`;
- `__secure_computing()` `BUG()`s on `SECCOMP_MODE_DISABLED`, so `mode` may only be
  zeroed *after* the flag is gone — that, not `filter_count`, was the old panic;
- `copy_seccomp()` re-arms the flag in every child while `mode != DISABLED`, so clearing
  only the flag leaves `sh -> ksud` filtered;
- `release_task()` releases `seccomp.filter` regardless of `mode`, so `DISABLED` with a
  live filter pointer is consistent.

W3 therefore issues two zero stores — `task+0x00`, then `task+0x8e8`
(`{mode, filter_count}`) — while the rooted child is parked in a group stop, resumes it,
reads back `Seccomp: 0`, and confirms with the forked `finit_module` probe. Everything
stays inside the primitive's value space; nothing is masked.

```
W3: TIF_SECCOMP clear attempt 1/2
=== W3: TIF_SECCOMP clear === target=0xffffff801c11ddc0 mode=1 leaf=1
W3: seccomp mode clear attempt 1/2
=== W3: seccomp mode clear === target=0xffffff801c11e6a8 mode=1 leaf=1
W3: child reports Seccomp: 0
seccomp finit_module probe = 0x9
child seccomp disabled (mode=0); descendants run filter-free
```

Full analysis, ordering argument, and failure signatures:
**[docs/W3-SECCOMP-ANALYSIS.md](docs/W3-SECCOMP-ANALYSIS.md)**. Design record:
**[docs/analysis/w3-seccomp-zero-store-plan.md](docs/analysis/w3-seccomp-zero-store-plan.md)**.

---

## Repository layout

```
app/                       upstream Android app + built-in X6840 profile
src/                       native exploit (C/C++) + the no-panic W3 code
docs/                      this port's deep dives + upstream documentation
docs/evidence/             captured logs from the test device (sanitized)
profiles/                  standalone X6840 HOCON profile
patches/                   code + build + profile + test delta against the pre-port base
tools/scan_adb.py          wireless-debugging port scanner
release/sha256sums.txt     checksums for the GitHub release assets
LICENSE                    Apache-2.0 (upstream)
```

Deep dives:

- **[docs/X6840-PORT.md](docs/X6840-PORT.md)** — device, firmware, extractor, offsets, built-in profile.
- **[docs/W3-SECCOMP-ANALYSIS.md](docs/W3-SECCOMP-ANALYSIS.md)** — the complete W3 story, logs, and primitive limitation.
- **[docs/PROFILE.md](docs/PROFILE.md)** — every profile field and why it is set.
- **[docs/BUILD-AND-INSTALL.md](docs/BUILD-AND-INSTALL.md)** — NDK build, APK repack, signing, install, Shizuku setup.
- **[docs/VERIFICATION.md](docs/VERIFICATION.md)** — exact checks, expected outputs, failure signatures, recovery.
- **[docs/SECURITY.md](docs/SECURITY.md)** — risk, ethics, test key, privacy, license.
- **[docs/evidence/README.md](docs/evidence/README.md)** — how to read the captured evidence.
- **[docs/UPSTREAM-README.md](docs/UPSTREAM-README.md)** — upstream project README (preserved).
- **[docs/UPSTREAM-README_ZH.md](docs/UPSTREAM-README_ZH.md)** — upstream Chinese README (preserved).

---

## The profile

The standalone profile is [`profiles/X6840-6.6.118-final.conf`](profiles/X6840-6.6.118-final.conf); the same file is built into the APK at `app/src/main/assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf`.

Key values:

```hocon
recommend_shizuku = 0
kernel_phys_load   = 1074266112   # 0x40080000
kernel_phys_offset = 1073741824   # 0x40000000
route { select_stack { waiter_shift = -2 } }
fallback { to = "none" }
execution { selected_cpus { main = 6 consumer = 7 } }
w3_attempts = 2          # in-process seccomp clear (zero-store)
w3_chain_rounds = 2
w3_settle_us = 50000
```

The profile also carries the full `task_struct`, `cred`, and kernel-offset geometry (see [docs/PROFILE.md](docs/PROFILE.md)). `kernel_phys_offset` was corrected manually from `0` to `0x40000000`: the extractor read the **host's** `/proc/iomem` and overwrote the vendor_boot-proven DRAM base.

The profile is matched by **exact `uname -r`**. It will not be used on another kernel.

---

## Build and install

The native core is built with the Android NDK:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
make -C src ghostlock
# build/native/ghostlock
```

Then the APK is repacked in place over the upstream release APK (replacing `lib/arm64-v8a/libghostlock.so` and the profile assets), zipaligned, and signed. A full rezip violates Android's `resources.arsc` stored/aligned rule; the in-place method is important.

Exact commands, signing, and the Shizuku/wireless-ADB setup: **[docs/BUILD-AND-INSTALL.md](docs/BUILD-AND-INSTALL.md)**.

The release APK is signed with the test key:

```
CN=GhostLock Test, O=Test
SHA-256 57484e77dc0dbf74c94516d07ac2c2724e5bde0778991a7454f71babb079db2e
```

Build from source if you do not trust the binary.

---

## Verification

The full checklist is in [docs/VERIFICATION.md](docs/VERIFICATION.md). The essentials:

```bash
# device and kernel
adb shell getprop ro.product.model
adb shell uname -r

# profile: must show Built-in profile, not a user overlay
# GhostLock -> Advanced options -> Parameter configuration

# Shizuku path
adb shell su -c id
adb shell cat /proc/modules | grep kernelsu
```

Known failure signature on the in-process path:

```
seccomp=Seccomp: 2 Seccomp_filters: 1
seccomp finit_module probe = 0xfffffffd
KernelSU module not loaded
```

This is not a panic. The mask/value build completes all steps; it simply cannot change the seccomp state. The earlier zero-store panic is the source of a **stale** `ro.boot.bootreason=kernel_panic` on a boot that predates the latest run.

---

## Security, ethics, and risk

- Use only on a device you own and are authorized to modify.
- Kernel exploits can corrupt memory, panic, reboot, or lose data.
- The bootloader remains locked; root is temporary; OTA updates can replace the kernel and invalidate the profile.
- The release APK is **test-signed**; verify its checksum and/or build from source.
- No telemetry. The logs in this repository are from the test device and contain no LAN IP, ADB pairing code, or personal account data.
- The upstream project and this port are **Apache-2.0**. See [LICENSE](LICENSE).

Read **[docs/SECURITY.md](docs/SECURITY.md)** before running anything.

---

## FAQ

**Why does the boot reason still say `kernel_panic`?**
It is from an earlier boot, caused by the very first W3 variant (an 8-byte zero store issued
before the flag was cleared, which is a `BUG()` in `__secure_computing()`). The current W3
parks the child, clears the flag first, and never issues a mode store behind a live flag.
The boot reason is sticky for that boot.

**Can I run it without ADB and without Shizuku?**
Yes. That is the default now: `recommend_shizuku = 0` and `w3_attempts = 2`. The app runs
the exploit itself and the rooted child loads KernelSU; nothing external is needed. ADB is
only used to install the APK once.

**Why not use Shizuku anyway?**
You can. It is still supported: shell UID 2000 has no app seccomp filter, so W3 skips
itself and `ksud` loads the module. It is just no longer required.

**Is root permanent?**
No. The bootloader is locked. The KernelSU LKM is lost on reboot; tap Run again.

**Will this work on another X6840 build?**
Only the exact kernel `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`. A different build needs a new profile extracted from its own `boot.img`/`vendor_boot.img`.

**Why is the firmware not in the repo?**
It is large and vendor-distributed. The profile is the important artifact; the firmware is only needed to re-extract offsets.

**Why the test key?**
The APK is a convenience build from this source. The certificate is `CN=GhostLock Test`; verify the SHA-256 or rebuild.

**What about the `msf_88` profile?**
That was a test overlay. The safe state is the built-in final with no active user profile.

**Does this unlock the bootloader?**
No. Verified boot stays green; the bootloader stays locked.

---

## Credits

- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) — upstream GhostLock, app, native core, extractor, and kernel-profile framework.
- [Baka-SU/BakaSU](https://github.com/Baka-SU/BakaSU) / ReSukiSU — root manager and `ksud`.
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — KernelSU.
- [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku) — Shizuku.
- The GhostLock contributors and the kernel-profile documentation in `docs/kernel_profiles/`.
- Port, profile, and W3 analysis: `b0r1s-69`.

## License

Apache License 2.0. See [LICENSE](LICENSE). The upstream copyright and license notices are retained. This port is provided **as is**, without warranty.
