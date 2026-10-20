# Evidence

These are the captured logs from the test device (Infinix Smart 20, kernel `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`). They are sanitized: no LAN IP, ADB pairing code, account name, or serial number.

## Files

| File | What it shows |
|---|---|
| [`ghostlock_native_final.log`](ghostlock_native_final.log) | full native log: W3 targets, leaf probe, `finit_module` probe, handoff |
| [`ghostlock_ksu_final.log`](ghostlock_ksu_final.log) | root script log: `Seccomp: 2`, `late-load exit=0`, module missing |
| [`ghostlock_root.sh`](ghostlock_root.sh) | exact root handoff script (`KSUD`, `late-load`, module watch) |
| [`runstate_poll.log`](runstate_poll.log) | live `run-state` samples: all W1–W3 steps completed |

## Timeline

1. Earlier W3 builds: an 8-byte zero store at `thread_info.flags` / `seccomp.mode` panicked the kernel (`kernel_panic,bug`).
2. Flags write removed: still panicked.
3. Mask/value build: all steps complete, **no panic**, but seccomp is unchanged.

The `ro.boot.bootreason=kernel_panic` on the phone is sticky for the boot in which the earlier panic happened. The mask/value run at 19:20 completed and did not reboot the phone; its run-state is all `completed`.

## Final run

Key native lines:

```
W3-0: leaf dir target=0xffffff801c11e5f0 mode=1 leaf=1
W3: TIF_SECCOMP mask + mode attempt 1/1
=== W3: TIF_SECCOMP === target=0xffffff801c11ddc0 mode=3 leaf=0
=== W3: seccomp mode === target=0xffffff801c11e6a8 mode=4 leaf=0
seccomp finit_module probe = 0xfffffffd
W3 seccomp clear failed; ksud late-load will likely stay blocked
```

Root script:

```
root script start uid=0 euid=0
seccomp=Seccomp: 2 Seccomp_filters: 1
late-load kmi=android15-6.6
late-load exit=0
temp su uid=0; watching kernelsu.ko
KernelSU module not loaded
```

Run-state: `w1a w1b w2a w2b w3a w3b w3c` all `completed`.

## Addresses

| Target | Address | Offset |
|---|---|---|
| child task | `0xffffff801c11ddc0` | — |
| cred (W2) | `0xffffff801c11e5e0` | `+0x820` |
| comm (leaf) | `0xffffff801c11e5f0` | `+0x830` |
| flags | `0xffffff801c11ddc0` | `+0` |
| seccomp | `0xffffff801c11e6a8` | `+0x8e8` |

W2 succeeds at `+0x820` (child `uid=0`), so the target math is correct; the W3 values are the problem. See [W3-SECCOMP-ANALYSIS.md](../W3-SECCOMP-ANALYSIS.md).

## Reproducing the evidence

The in-process run is only a diagnostic:

1. Profile: `w3_attempts=1`, `recommend_shizuku=0`.
2. Shizuku off.
3. Run GhostLock.
4. Capture `files/.ghostlock_native.log`, `files/ghostlock-ksu-*.log`, and `.ghostlock_run_state.json` (the debug build is debuggable, so `run-as` works).

Do not use this path for normal root. The final profile uses `w3_attempts=0` and Shizuku.
