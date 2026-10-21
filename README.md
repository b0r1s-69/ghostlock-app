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
| Root type | temporary LKM via Shizuku; lost on reboot |
| Profile | built-in, `recommend_shizuku=1`, `w3_attempts=0` |
| App | GhostLock `1.2` (versionCode 577), built from upstream `bf836bc` + this port |
| Status | **Shizuku path verified**; in-process W3 seccomp bypass **blocked** by the write primitive |

### What works

- Installing GhostLock and loading the built-in X6840 profile.
- W1 (SELinux permissive) and W2 (credential overwrite) — the child reaches `uid=0`.
- The **Shizuku path**: W3 is skipped, `ksud late-load` succeeds, KernelSU loads, and `su -c id` returns root.
- BakaSU recognizing the LKM (`Working · LKM`).

### What does not

- **In-process W3 seccomp bypass.** The writes complete but do not change the target (details below). The child remains `Seccomp: 2 Seccomp_filters: 1`; `finit_module` is blocked; `ksud` exits 0 without loading the module.
- Persistent root across reboot (bootloader locked).
- Any kernel other than the exact release above.

---

## Quick start (release build)

The prebuilt APK is attached to the [x6840‑v1 release](https://github.com/b0r1s-69/ghostlock-app/releases/tag/x6840-v1). It is signed with a **test key**, not the upstream release key. Verify the checksum from `release/sha256sums.txt` before installing.

1. **Install the root manager** — [BakaSU](https://github.com/Baka-SU/BakaSU) (`com.resukisu.resukisu`). GhostLock extracts its `libksud.so` during the handoff.
2. **Install Shizuku** — [Shizuku](https://github.com/RikkaApps/Shizuku) / Shizuku‑Next (`moe.shizuku.privileged.api`). Start its server from the app (wireless ADB is enough; `tools/scan_adb.py` finds the current port).
3. **Install GhostLock**:
   ```bash
   adb install -r GhostLock-patched3.apk
   ```
4. **Confirm the profile** — open GhostLock → **Advanced options** → **Parameter configuration**. It must read:
   ```
   Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k
   ```
   If a user profile is loaded (for example `msf_88`), open **Load configuration** → the profile → **Unload**. The built-in profile has `w3_attempts=0` and `recommend_shizuku=1`.
5. **Run via Shizuku** — enable **Run via Shizuku** (the built-in profile recommends it), start Shizuku, return to GhostLock, and tap **Run**.
6. **Verify**:
   ```bash
   adb shell su -c id
   # uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
   adb shell cat /proc/modules | grep kernelsu
   # kernelsu 192512 1 - Live 0x0000000000000000 (O)
   ```
7. **After every reboot**: Shizuku's server stops and the LKM unloads. Start Shizuku again and tap **Run**. Root is not persistent.

> Do **not** set `w3_attempts > 0`. That path is the guard against the old panic, and on this kernel it cannot clear seccomp anyway.

---

## Why Shizuku?

Shizuku runs the exploit through `adb` as **shell UID 2000**. The shell process has **no app seccomp filter**, so GhostLock's W3 stage is unnecessary and is skipped. `ksud late-load` is then allowed to call `finit_module`, and KernelSU loads.

The in-process path is different: the app process carries a seccomp filter. W3 is supposed to disable it. It does not, on this kernel — see below.

---

## The W3 finding in one minute

The exploit's write primitive stamps only two kinds of values:

- `0` (`WriteMode::Zero`), or
- a **valid kernel pointer** (`WriteMode::Credential`, e.g. `init_cred_alias`).

The W3 code needs to write:

- a **masked flags word** (`~ (1 << 11)`) to clear only `TIF_SECCOMP`, and
- `mode=0, filter_count=1` (`0x0000000100000000`) to disable seccomp without corrupting the filter reference count.

Neither value is a valid kernel pointer. The route reports success, but the target is unchanged:

```
W3: TIF_SECCOMP mask + mode attempt 1/1
=== W3: TIF_SECCOMP === target=0xffffff801c11ddc0 mode=3 leaf=0
=== W3: seccomp mode === target=0xffffff801c11e6a8 mode=4 leaf=0
seccomp finit_module probe = 0xfffffffd
W3 seccomp clear failed; ksud late-load will likely stay blocked
```

The root script then reports:

```
root script start uid=0 euid=0
seccomp=Seccomp: 2 Seccomp_filters: 1
late-load kmi=android15-6.6
late-load exit=0
temp su uid=0; watching kernelsu.ko
KernelSU module not loaded
```

The old code used an 8-byte **zero** store. That *did* write — and cleared every `TIF_*` flag and `filter_count`, which panicked the kernel. The mask/value form removes the panic but is a no-op. The final profile therefore uses Shizuku and `w3_attempts=0`.

Full analysis, target arithmetic, and captured logs: **[docs/W3-SECCOMP-ANALYSIS.md](docs/W3-SECCOMP-ANALYSIS.md)**.

---

## Repository layout

```
app/                       upstream Android app + built-in X6840 profile
src/                       native exploit (C/C++) + the no-panic W3 code
docs/                      this port's deep dives + upstream documentation
docs/evidence/             captured logs from the test device (sanitized)
profiles/                  standalone X6840 HOCON profile
patches/                   exact patch against upstream bf836bc
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
recommend_shizuku = 1
kernel_phys_load   = 1074266112   # 0x40080000
kernel_phys_offset = 1073741824   # 0x40000000
route { select_stack { waiter_shift = -2 } }
fallback { to = "none" }
execution { selected_cpus { main = 6 consumer = 7 } }
w3_attempts = 0
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
It is from an earlier boot, caused by the old 8-byte zero W3 store. The mask/value build's run-state is `w1a…w3c all completed` and the app exits normally; the boot reason is sticky for that boot.

**Can I make the in-process path work by enabling W3?**
Not with the current primitive. The mask/value writes are no-ops; the zero store panics. `w3_attempts=0` is intentional. A real fix needs a 4-byte/bit-granular or arbitrary-value write, or a different kernel bug.

**Why not use Shizuku?**
It is the working path. Shell UID 2000 has no app seccomp filter, so W3 is skipped and `ksud` can load the module.

**Is root permanent?**
No. The bootloader is locked. The KernelSU LKM and Shizuku server are lost on reboot; start Shizuku and Run again.

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
