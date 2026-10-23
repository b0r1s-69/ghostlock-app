# Device gate — W3-ZERO-STORE

Status: **PENDING** (no post-fix device run yet).

Design record: [`docs/analysis/w3-seccomp-zero-store-plan.md`](../w3-seccomp-zero-store-plan.md)
Root cause: [`docs/W3-SECCOMP-ANALYSIS.md`](../../W3-SECCOMP-ANALYSIS.md)

## What this gate proves

The in-process W3 clear works on the target kernel with **no ADB shell and no Shizuku**:
`thread_info.flags` and `seccomp.mode` are zeroed, the rooted child (and its descendants)
run filter-free, and `ksud late-load` loads KernelSU.

## Preconditions

| Item | Required value |
|---|---|
| Device | Infinix Smart 20 (X6840) |
| Kernel | `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k` |
| Boot | cold boot, bootloader locked, verified boot green |
| KernelSU | **not** loaded (`/proc/modules` has no `kernelsu`) |
| SELinux | enforcing before the run |
| Profile | built-in, `recommend_shizuku = 0`, `w3_attempts = 2`, `w3_chain_rounds = 2`, `w3_settle_us = 50000` |
| Route / CPUs | `select_stack`, main 6 / consumer 7 |
| Shizuku | **off** (this gate is the no-Shizuku path) |
| ADB | used only to install the APK and to collect the log afterwards |

## Procedure

1. Cold boot; confirm `uname -r` and that `kernelsu` is absent from `/proc/modules`.
2. Install the fixed APK, open GhostLock, confirm the built-in profile line.
3. Leave **Run via Shizuku** off. Tap **Run**.
4. Collect `Download/ghostlock-debug-log/<stamp>/*.log.txt` plus `profile.conf` /
   `profile.bin` from the same directory.
5. Record the checks below.

## Required log evidence

```text
W3-0: leaf dir attempt 1/4
leaf dir probe comm_len=0 comm[0]=00
W3: child <pid> stopped for the seccomp clear
W3: TIF_SECCOMP clear attempt 1/2
=== W3: TIF_SECCOMP clear === target=... mode=1 leaf=1
W3: seccomp mode clear attempt 1/2
=== W3: seccomp mode clear === target=... mode=1 leaf=1
W3: TIF_SECCOMP re-clear attempt 1/2
W3: child reports Seccomp: 0
seccomp finit_module probe = <normal errno, 2..40>
child seccomp filter bypassed (finit_module errno=...)
child seccomp disabled (mode=0); descendants run filter-free
```

and in the root script log:

```text
root script start uid=0 euid=0
seccomp=Seccomp: 0 Seccomp_filters: <n>
late-load kmi=android15-6.6
late-load exit=0
[+] KernelSU module loaded
```

## Pass criteria

| Check | Expected |
|---|---|
| `W3: child reports Seccomp:` | `0` |
| `finit_module` probe | any normal errno (e.g. `0x9` EBADF) - never `0xfffffffd` (SIGSYS) |
| root script `seccomp=` line | `Seccomp: 0` |
| `/proc/modules` | contains `kernelsu` |
| `su -c id` | `uid=0(root) ... context=u:r:ksu:s0` |
| Manager | BakaSU shows **Working · LKM** |
| Kernel | no panic, no reboot; `ro.boot.bootreason` unchanged for this boot |
| Second run without reboot | W3 returns `no app seccomp filter (shell flow); skipping W3` once the child is already filter-free, and the manager keeps root |

## Fail criteria (any of these fails the gate)

- `W3: child reports Seccomp: 2` on every attempt (mode store never landed).
- `W3: mode is disabled but the forked probe is filtered` (flag store missed).
- Any kernel panic, `BUG:`, or `refcount_t` warning in `dmesg`/pstore.
- Any `free_task` WARN after the rooted child exits.

## Result

| Field | Value |
|---|---|
| Date | _pending_ |
| Build | _pending_ (commit + `sha256sum` of `libghostlock.so`) |
| Log directory | _pending_ |
| Verdict | _pending_ |
| Notes | _pending_ |

Fill this table when the gate runs; a passing record may then flip
`docs/kernel_profiles/SUPPORTED_DEVICES.md` back to a plain supported row and let
`docs/release-notes.md` drop the "pending" wording.
