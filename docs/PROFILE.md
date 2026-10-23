# Profile

The X6840 profile is built into the APK and also provided standalone at [`profiles/X6840-6.6.118-final.conf`](../profiles/X6840-6.6.118-final.conf).

## Key fields

```hocon
release = "6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k"
schema_version = 1
kernel_major = 6
recommend_shizuku = 0
kernel_phys_load = 1074266112   # 0x40080000
kernel_phys_offset = 1073741824 # 0x40000000

route { select_stack { waiter_shift = -2 } }
fallback { to = "none" }

execution {
  selected_cpus { main = 6  consumer = 7 }
  w3_attempts = 2
  w3_chain_rounds = 2
  w3_settle_us = 50000
}
```

`w3_attempts = 2` drives the in-process seccomp clear: two zero stores
(`thread_info.flags`, then the `{mode, filter_count}` word) while the rooted child is
parked, then a `Seccomp: 0` read-back and the forked `finit_module` probe. Zero is the only
value the write primitive can land, so a masked write is not an option; see
[W3-SECCOMP-ANALYSIS.md](W3-SECCOMP-ANALYSIS.md).

## Geometry

### task_struct

| Field | Offset |
|---|---:|
| `prio` | 132 |
| `normal_prio` | 140 |
| `sched_task_group` | 840 |
| `tasks` | 1360 |
| `atomic_flags` | 1496 |
| `pid` | 1560 |
| `tgid` | 1564 |
| `real_cred` | 2072 |
| `cred` | 2080 |
| `comm` | 2096 |
| `pi_lock` | 2316 |
| `pi_waiters` | 2336 |
| `pi_top_task` | 2352 |
| `pi_blocked_on` | 2360 |
| `seccomp` | 2280 |

### cred

| Field | Value |
|---|---:|
| `copy_size` | 136 |
| `usage_value` | 1 |
| `caps_offset` | 48 |
| `caps_count` | 5 |
| `caps_value` | -1 |

### Kernel offsets

| Symbol | Offset |
|---|---:|
| `init_task` | 34726528 |
| `init_cred` | 34801480 |
| `empty_zero_page` | 36757504 |
| `root_task_group` | 36791680 |
| `selinux_enforcing` | 37060320 |
| `selinux_blob_sizes` | 23568240 |
| `security_hook_heads` | 23566392 |
| `slide_nfulnl_logger` | 34677344 |
| `slide_loggers_0_1` | 34677168 |
| `slide_boot_id` | 37195480 |

These values come from the extractor over the matching `boot.img`/`vendor_boot.img`. The addresses in the captured logs are per-boot and vary with KASLR; the offsets do not.

## Physical addresses

- `kernel_phys_load = 0x40080000` (1074266112)
- `kernel_phys_offset = 0x40000000` (1073741824)

The extractor first produced `kernel_phys_offset = 0` because it read the **host's** `/proc/iomem`. The vendor_boot image proves the DRAM base is `0x40000000`. The profile uses the corrected value.

## Route and execution

- Route: `select_stack`, `waiter_shift = -2`.
- CPU pair: main 6, consumer 7.
- Fallback: none.
- W3: `w3_attempts = 2`, `w3_chain_rounds = 2`, `w3_settle_us = 50000`.
- Shizuku: not required (the flag stays available for shell flows).

`select_stack` was the high-confidence route from the extractor. `tcp_zerocopy` had `compact_waiter = null`; `multicast_waiter` had no derivable geometry. The tcp variant was tested and also panicked in W3 before the mask/value change, so it is not a fallback.

## Built-in integration

The profile is stored at:

```
app/src/main/assets/kernel_profiles/6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf
```

and indexed in `app/src/main/assets/kernel_profiles/index.conf`:

```
{ release = "6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k",
  file = "6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k.conf" }
```

`docs/kernel_profiles/SUPPORTED_DEVICES.md` lists the device. The app shows it under **Built-in profiles** as the device kernel and under **Kernel profiles**.

## Loading

1. GhostLock → **Advanced options** → **Parameter configuration**.
2. The source line must read **Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k**.
3. If a user profile is active, open **Load configuration** → the profile → **Unload**.
4. Leave **Run via Shizuku** off (the built-in profile no longer recommends it).
5. Tap **Run**; no Shizuku server or ADB is involved.

The app also supports importing the standalone HOCON via **Load configuration → Import offsets.conf (v2)**. Importing is optional; the built-in copy is preferred because it cannot drift from the APK.

## Validation

A correctly loaded profile gives:

- **Supported** on the home screen.
- The exact kernel string.
- **Built-in profile** in Parameter configuration.
- `w3_attempts = 2` and `recommend_shizuku = 0` in the profile.
- In-process path: `child reports Seccomp: 0`, the probe returns a normal errno, then
  `su -c id` returns root and `/proc/modules` shows `kernelsu`.

If the app shows a user profile such as `msf_88`, unload it. That overlay was used for W3 testing and is not the safe configuration.

## Safety

- Use only with the exact kernel above. The profile will not match a different build.
- Do not set `w3_attempts = 0` and then expect the module to load in-process: that skips
  the seccomp clear, which is only correct for shell/Shizuku runs (`Seccomp: 0`).
- The bootloader remains locked; root is temporary.
- An OTA that changes the kernel requires a new extraction and profile.
