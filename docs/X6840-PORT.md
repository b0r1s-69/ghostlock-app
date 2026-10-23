# X6840 port notes

Device, firmware, extractor, and app notes for the Infinix Smart 20 port of GhostLock.

## Device

| Item | Value |
|---|---|
| Model | Infinix Smart 20 (X6840) |
| SoC | MediaTek MT6769 / mt6768 |
| Android | 16 / SDK 36 / arm64-v8a |
| Build | `X6840-16.3.0.140SP09(OPPJ004PF001PJ)` |
| Fingerprint | `Infinix/X6840-OPPJ/Infinix-X6840:16/BP2A.250605.031.A3/301400019:user/release-keys` |
| Kernel | `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k` |
| Bootloader | locked; verified boot **green** |
| SELinux | Enforcing (before the exploit) |

The profile is matched by **exact `uname -r`**. No other X6840 build is guaranteed to work.

## Firmware

The port was developed from the vendor package `R2-Infinix-Smart-20-X6840-10.zip` (7.5 GB, MT6768 scatter package). It contains:

- `boot.img` (~64 MB)
- `vendor_boot.img` (~64 MB)
- `init_boot.img`
- `MT6768_Android_scatter.txt`
- `version.csv`

The kernel release string inside `boot.img` matches the phone exactly. The firmware is **not** included in this repository (size and vendor distribution); only the extracted profile is.

## Extracting the profile

Use the upstream extractor from the GhostLock release:

```bash
ghostlock-extract-linux-x86_64 boot.img \
  --vendor-boot vendor_boot.img \
  --analysis
```

The first run reported:

- family `STRUCT_OFFSETS_6_6`
- `kernel_phys_load = 0x40080000`
- primitive `remove_waiter@0x10665c0` (unpatched)
- suggested route `select_stack (high)`
- `sizeof(mm_struct) = 0x4C0`
- 109645 kallsyms symbols

### The `kernel_phys_offset` correction

The extractor initially wrote `kernel_phys_offset = 0`. That value came from the **host's** `/proc/iomem`, not the device. It overwrote the vendor_boot-proven DRAM base. The correct value is:

```
kernel_phys_offset = 0x40000000   # 1073741824
kernel_phys_load   = 0x40080000   # 1074266112
```

This correction is required; with `0` the profile is wrong.

### Route results

- `select_stack` — complete geometry, suggested (high confidence).
- `tcp_zerocopy` — `compact_waiter = null`; not viable without more device work.
- `multicast_waiter` — all geometry null; not viable.

The final profile uses `select_stack` with `waiter_shift = -2`.

## The profile

Standalone file: [`profiles/X6840-6.6.118-final.conf`](../profiles/X6840-6.6.118-final.conf).

Key fields:

```hocon
release = "6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k"
schema_version = 1
kernel_major = 6
recommend_shizuku = 0
kernel_phys_load = 1074266112
kernel_phys_offset = 1073741824

route { select_stack { waiter_shift = -2 } }
fallback { to = "none" }

execution {
  selected_cpus { main = 6  consumer = 7 }
  w3_attempts = 2
  w3_chain_rounds = 2
  w3_settle_us = 50000
}
```

The full task_struct/cred/offset geometry is documented in [PROFILE.md](PROFILE.md) and carried verbatim by the profile file.

## App integration

The profile is built into the APK:

- `app/src/main/assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf`
- an entry in `app/src/main/assets/kernel_profiles/index.conf`
- a row in `docs/kernel_profiles/SUPPORTED_DEVICES.md`

After install, GhostLock shows **Supported**, and **Advanced options → Parameter configuration** reads:

```
Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k
```

If a user profile is active, **Load configuration → the profile → Unload**. The built-in profile is the safe one (`w3_attempts=2`, `recommend_shizuku=0`).

## Results

| Stage | Result |
|---|---|
| W1 SELinux permissive | works |
| W2 credential overwrite | works; child `uid=0` |
| W3 seccomp bypass | **works**: child parked, flags + `seccomp.mode` zeroed, child reports `Seccomp: 0` |
| `ksud late-load` (in-process) | loads KernelSU; `su -c id` returns root |
| Shizuku path | optional; W3 skips itself when the process has no filter |
| Persistent root | no; bootloader locked |

The W3 details are in [W3-SECCOMP-ANALYSIS.md](W3-SECCOMP-ANALYSIS.md).

## Reproducing the port

1. Obtain the matching firmware and extract `boot.img`/`vendor_boot.img`.
2. Run the extractor and apply the `kernel_phys_offset = 0x40000000` correction.
3. Generate the HOCON profile and verify the geometry.
4. Add the profile, the index entry, and the supported-device row to the app.
5. Build the native core and repack the APK (see [BUILD-AND-INSTALL.md](BUILD-AND-INSTALL.md)).
6. Install, load the built-in profile, and verify **Supported**.
7. Run in-process (no Shizuku, no ADB); keep `w3_attempts=2`.

## Safety notes

- The profile is device-specific. Do not use it on a different kernel.
- The in-process W3 path is intentionally disabled. Do not enable `w3_attempts` on this kernel.
- The bootloader remains locked; root is temporary and lost on reboot.
- An OTA that changes the kernel invalidates the profile. Re-extract before running again.
