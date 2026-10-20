# W3 seccomp analysis

This is the detailed account of GhostLock's W3 stage on the Infinix Smart 20 (X6840), kernel `6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`. It covers the original panic, the two attempted fixes, the exact evidence, and why the in-process path still cannot load KernelSU.

## The stage

GhostLock's temporary-root chain has three write stages:

| Stage | Target | Purpose | Result on X6840 |
|---|---|---|---|
| W1 | `selinux_enforcing` | set SELinux permissive | works |
| W2 | `task_struct.cred` | replace the child credentials with root | works; child `uid=0` |
| W3 | `task_struct.seccomp` / `thread_info.flags` | disable seccomp before `ksud` | **no-op**; child stays `Seccomp: 2` |

W3 matters because the rooted child then runs `ksud late-load`, which calls `finit_module`. If seccomp is still active, that syscall is filtered and the module never loads.

## First failure: the zero-store panic

The original W3 code issued two 8-byte zero stores:

1. `thread_info.flags = 0`
2. `seccomp.mode = 0`

Both are wrong on this kernel:

- `thread_info.flags` is a 64-bit word. Zeroing it clears **every** `TIF_*` bit, not just `TIF_SECCOMP` (bit 11). That corrupts scheduling and signal state.
- `struct seccomp` is `{ int mode; int filter_count; struct seccomp_filter *filter; }`. An 8-byte zero at `mode` also clears `filter_count`, leaving the filter pointer inconsistent.

The result was a kernel panic:

```
ro.boot.bootreason = kernel_panic
sys.boot.reason     = kernel_panic,bug
```

## Second attempt: remove the flags write

The flags store was removed so only `seccomp.mode = 0` remained. That still panicked: the `filter_count` corruption alone is enough, and the W3 leaf/route also remained unstable.

## Third attempt: masked flags + mode/filter_count

The current code (in `src/core/session/backend/cve_2026_43499_backend.cpp` and `src/core/memory/payload_builder.*`) adds two write modes:

- `WriteMode::SeccompFlags` — write `~ (1 << 11)` (`0xFFFFFFFFFFFFF7FF`) to clear only `TIF_SECCOMP`.
- `WriteMode::SeccompMode` — write `0x0000000100000000` at `seccomp.mode`, i.e. `mode=0`, `filter_count=1`.

The intent is correct: preserve every other flag and keep the filter reference count valid. The build completes all W3 steps and **does not panic**. But the write does not take effect.

### Evidence

Run-state, captured live via `run-as`:

```
w1a completed  w1b completed
w2a completed  w2b completed
w3a completed  w3b completed  w3c completed
```

Native log:

```
W3-0: leaf dir attempt 1/4
W3-0: leaf dir target=0xffffff801c11e5f0 mode=1 leaf=1
W3: TIF_SECCOMP mask + mode attempt 1/1
=== W3: TIF_SECCOMP === target=0xffffff801c11ddc0 mode=3 leaf=0
=== W3: seccomp mode === target=0xffffff801c11e6a8 mode=4 leaf=0
seccomp finit_module probe = 0xfffffffd
W3 seccomp clear failed; ksud late-load will likely stay blocked
W3 seccomp bypass failed after 1 chain rounds; ksud late-load will likely stay blocked
...
KernelSU module load failed
```

`ksud` log:

```
[*] root script start uid=0 euid=0
[*] seccomp=Seccomp: 2 Seccomp_filters: 1
[*] late-load kmi=android15-6.6
[*] late-load exit=0
[*] temp su uid=0; watching kernelsu.ko
[!] KernelSU module not loaded
```

The crucial line is `Seccomp: 2 Seccomp_filters: 1`: the root child is still in seccomp mode 2 with one filter. The W3 writes were accepted by the route but did not change the target.

## Address arithmetic

From the captured run:

| Target | Address | Offset from child task |
|---|---|---|
| child task base | `0xffffff801c11ddc0` | — |
| `cred` (W2) | `0xffffff801c11e5e0` | `+0x820` (2080) |
| `comm` (leaf probe) | `0xffffff801c11e5f0` | `+0x830` (2096) |
| `thread_info.flags` | `0xffffff801c11ddc0` | `+0` |
| `seccomp` | `0xffffff801c11e6a8` | `+0x8e8` (2280) |

The targets are correct:

- W2 writes the credential at `+0x820` and the child reports `uid=0`. So the child base and the `cred` offset are right.
- The W3 `seccomp` target is the same child base plus the profile's `task_struct.seccomp = 2280`.
- The leaf probe writes at `comm` (`+0x830`) with `leaf=1`; the captured run resolved `leaf_to_target8 = 0`.

Because W2 succeeds at the same child base, the problem is not the address or the profile offset. It is the **value** being written.

## Why the values are no-ops

The primitive used by `select_stack` stamps the fake waiter's `right` field. The supported value space is:

- `0` (`WriteMode::Zero`), or
- a **valid kernel pointer** (`WriteMode::Credential`, e.g. `init_cred_alias`).

The route's `right` field is consumed as a pointer by the kernel's PI/rb-tree path. Zero and a mapped kernel pointer are valid inputs; they are written to the target. The W3 values are neither:

- `0xFFFFFFFFFFFFF7FF` — a bitmask, not a mapped pointer.
- `0x0000000100000000` — a user-space-looking address, not a mapped kernel pointer.

The route still returns success, and the run-state records the step as completed, but the store does not land. That is why the logs show `mode=3` / `mode=4` writes completing and the child still at `Seccomp: 2`.

This is also why the earlier zero store behaved differently: zero **is** in the supported value space, so it did write — and corrupted `filter_count` / all `TIF_*` bits, causing the panic.

A true fix therefore cannot be a different offset or a different pair of magic values. It needs one of:

- a 4-byte or bit-granular write, so `mode` can be cleared without touching `filter_count`;
- an arbitrary-value write, so the mask / `mode=0, filter_count=1` word can be stamped;
- a different kernel object/bug that disables the filter for the root child.

None of these is available in the current `select_stack` / `tcp_zerocopy` write paths.

## The Shizuku path

Shizuku runs the native exploit through `adb` as **shell UID 2000**. The shell process has no app seccomp filter, so:

- W3 is skipped (`w3_attempts=0` and the shell flow).
- `ksud late-load` can call `finit_module`.
- KernelSU loads.

The previously verified Shizuku run produced:

```
child uid = 2000
...
[*] late-load exit=0
/proc/modules: kernelsu 192512 1 - Live 0x0000000000000000 (O)
su -c id: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

This is the supported path in the release profile (`recommend_shizuku=1`, `w3_attempts=0`).

## Reproduction (test only)

The in-process W3 attempt is preserved as a diagnostic. To reproduce it:

1. Use a test profile with `w3_attempts=1` and `recommend_shizuku=0`.
2. Turn the Shizuku toggle off.
3. Run GhostLock.
4. Expect: all W3 steps complete, no panic, `Seccomp: 2`, `finit_module probe = 0xfffffffd`, `KernelSU module not loaded`.

Unloading the Shizuku path is not recommended for normal use. The in-process path cannot succeed with the current primitive.

## Evidence

- [`docs/evidence/ghostlock_native_final.log`](evidence/ghostlock_native_final.log) — full native log, W3 target lines and probe.
- [`docs/evidence/ghostlock_ksu_final.log`](evidence/ghostlock_ksu_final.log) — root script log with `Seccomp: 2` and `late-load`.
- [`docs/evidence/ghostlock_root.sh`](evidence/ghostlock_root.sh) — exact handoff script.
- [`docs/evidence/runstate_poll.log`](evidence/runstate_poll.log) — live step states, all W1–W3 completed.
- [`docs/evidence/README.md`](evidence/README.md) — how to read the evidence and the timeline.

## Conclusion

- The W3 **panic** is fixed by the masked/mode form: no kernel crash, all steps complete.
- The W3 **seccomp bypass** is not fixed. The write primitive cannot store the required values. The child remains `Seccomp: 2`; `finit_module` is blocked; the module does not load.
- The final configuration uses Shizuku and `w3_attempts=0`. Do not enable the in-process W3 path on this kernel.
