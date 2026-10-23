# Verification

Use these checks after installing and before trusting the result.

## Device

```bash
adb shell getprop ro.product.model          # Infinix X6840
adb shell getprop ro.build.version.release  # 16
adb shell uname -r                          # 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k
adb shell getprop ro.boot.verifiedbootstate # green
adb shell getprop ro.boot.flash.locked      # 1
adb shell getenforce                        # Enforcing (before the exploit)
```

The profile only matches the exact `uname -r` above.

## App and profile

Open GhostLock:

- Home: **Supported**.
- **Advanced options → Parameter configuration**: **Built-in profile: 6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k**.
- **Run via Shizuku** is off (Shizuku is optional).
- No active user overlay (for example `msf_88`). If one is present, **Load configuration** → profile → **Unload**.

The built-in profile has `recommend_shizuku = 0` and `w3_attempts = 2`.

## In-process path (default)

1. Confirm the built-in profile is loaded (previous section).
2. Leave **Run via Shizuku** off, start Shizuku only if you want the shell flow.
3. Tap **Run**.
4. The log must show the zero-store W3 clear:
   ```text
   W3: TIF_SECCOMP clear attempt 1/2
   W3: seccomp mode clear attempt 1/2
   W3: child reports Seccomp: 0
   seccomp finit_module probe = 0x9
   child seccomp disabled (mode=0); descendants run filter-free
   ```
5. Verify:
   ```bash
   adb shell su -c id
   # uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

   adb shell cat /proc/modules | grep kernelsu
   # kernelsu 192512 1 - Live 0x0000000000000000 (O)
   ```
6. BakaSU should show **Working · LKM**.

A shell flow (Shizuku or `adb shell`) has no app filter, so W3 returns immediately with
`no app seccomp filter (shell flow); skipping W3` and `ksud` can load the module.

## Pre-fix signature (historical)

Older builds logged this and could not load the module in-process:

```text
Seccomp: 2 Seccomp_filters: 1
seccomp finit_module probe = 0xfffffffd
W3 seccomp clear failed; ksud late-load will likely stay blocked
late-load exit=0
KernelSU module not loaded
```

`probe = 0xfffffffd` means the probe child was killed by `SIGSYS`, i.e. the filter was
still armed. If you see it on the fixed build, W3 did not land: check
`W3: child reports Seccomp:` in the same log. Do not re-enable the old mask/value path.

## Failure signatures

| Signature | Meaning |
|---|---|
| `ro.boot.bootreason=kernel_panic` | usually stale from an earlier zero-store W3 run; check uptime |
| ADB device offline, new wireless-debugging port | phone rebooted; reconnect and re-enable wireless debugging |
| `Seccomp: 2` in the root script | W3 did not take; use Shizuku |
| `KernelSU module not loaded` after `late-load exit=0` | `finit_module` was filtered |
| App shows a user profile | unload it; use the built-in final |
| No `kernelsu` in `/proc/modules` | LKM not loaded; run again via Shizuku |

## Recovery after a panic

1. Wait for the phone to reboot.
2. Re-enable **Wireless debugging** if needed.
3. Find the new connect port:
   ```bash
   python3 tools/scan_adb.py <phone-ip>
   adb connect <phone-ip>:<port>
   ```
4. Open GhostLock; confirm the built-in profile and `w3_attempts=2`.
5. Tap **Run** again (add Shizuku only if you use the shell flow).
6. Verify `su -c id` and `/proc/modules`.

Root is temporary; the LKM is lost on every reboot.

## Evidence

The captured logs are in [`docs/evidence`](evidence/README.md):

- `ghostlock_native_final.log` — W3 targets, probe, and handoff.
- `ghostlock_ksu_final.log` — root script and `Seccomp: 2`.
- `ghostlock_root.sh` — exact handoff script.
- `runstate_poll.log` — live step states, all W1–W3 completed.

See [W3-SECCOMP-ANALYSIS.md](W3-SECCOMP-ANALYSIS.md) for the full interpretation.
