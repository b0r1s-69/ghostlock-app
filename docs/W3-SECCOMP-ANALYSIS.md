# W3 seccomp analysis and fix

This is the account of GhostLock's W3 stage on the Infinix Smart 20 (X6840), kernel
`6.6.118-android15-8-g0b9c3bf6db7f-ab14877662-4k`: the original panic, why the
"no-panic" masked variant could never work, the root cause, and the fix that lets W3 run
in-process without ADB and without Shizuku.

## The stage

GhostLock's temporary-root chain has three write stages:

| Stage | Target | Purpose | Result on X6840 |
|---|---|---|---|
| W1 | `selinux_state.enforcing` | SELinux permissive | works |
| W2 | `task_struct.cred` | child credentials become `init_cred` | works; child `uid=0` |
| W3 | `thread_info.flags` + `task_struct.seccomp` | disable seccomp for the child and its descendants | **works with this fix** |

W3 matters because the rooted child then runs `ksud late-load`, which calls
`finit_module`. The app process inherits the zygote seccomp filter, and that filter
answers `finit_module` with `SIGSYS`/`EPERM`. Until seccomp is off, no module loads, so
there is no KernelSU and no `su`.

## What the write primitive can actually store

The select/tcp erase relink (`src/core/support/util.cpp`,
`src/core/memory/payload_builder.cpp`) stamps one waiter word into `[target]`. The
stamped word is either

- **zero** - the leaf arm (`WriteMode::Zero`, `leaf=1`): waiter =
  `{pc = target - 8, rb_right = 0, rb_left = target}` and the relink stores `0` at
  `[target]`; or
- **a dereferenceable kernel pointer** - the value arm (`leaf=0`): waiter =
  `{pc = value, rb_right = 0, rb_left = target}`.

The walk consumes `value` as an rb-parent pointer before it relinks. A bit mask
(`0xFFFFFFFFFFFFF7FF`) or a user-looking word (`0x0000000100000000`) is not a mapped
kernel address, so the walk never reaches the store. That is the whole explanation for
this log line from the previous build:

```
=== W3: TIF_SECCOMP === target=0xffffff801c11ddc0 mode=3 leaf=0
=== W3: seccomp mode === target=0xffffff801c11e6a8 mode=4 leaf=0
seccomp finit_module probe = 0xfffffffd
```

The route reported success, nothing was written, and the child stayed
`Seccomp: 2 Seccomp_filters: 1`. The fix therefore cannot be a better mask; it has to be
a word whose whole 64-bit slot may legitimately be zero.

## Root cause: the 6.6 seccomp state machine

Read from the v6.6 sources this analysis relies on (`arch/arm64/include/asm/thread_info.h`,
`include/linux/thread_info.h`, `arch/arm64/kernel/entry-common.c`, `kernel/seccomp.c`,
`kernel/fork.c`, `kernel/exit.c`):

1. **The gate is `TIF_SECCOMP`, bit 11 of `thread_info.flags` at `task+0x00`.**
   arm64 6.6 has no `syscall_work` word, so `set_task_syscall_work(task, SECCOMP)`
   resolves to `set_ti_thread_flag(ti, TIF_SECCOMP)`. Every syscall checks that flag.
2. **`SECCOMP_MODE_DISABLED` is a `BUG()` in `__secure_computing()`.** The switch has
   `STRICT`, `FILTER`, `DEAD`, and `default: BUG();`. So zeroing `seccomp.mode` while
   the flag is still set panics on the *next* syscall. This - not the filter reference
   count - is why the "mode-only" attempt panicked.
3. **A child re-arms the flag.** `kernel/fork.c copy_seccomp()` ends with
   `if (p->seccomp.mode != SECCOMP_MODE_DISABLED) set_task_syscall_work(p, SECCOMP)`.
   Clearing only the flag therefore leaves the `sh -> ksud` chain filtered, which is
   exactly where the module load happens.
4. **`DISABLED` with the filter pointer still set is consistent.**
   `kernel/exit.c release_task()` calls `seccomp_filter_release()` regardless of `mode`,
   which zeroes `seccomp.filter` and drops the reference, so `free_task()`'s
   `WARN_ON_ONCE(tsk->seccomp.filter)` does not fire.

Put together, the only two stores W3 needs are both **zero**:

| Write | Target | Effect |
|---|---|---|
| 1 | `task + 0x00` | `thread_info.flags = 0`, i.e. `TIF_SECCOMP` gone (the other bits a live task carries are resched/signal/task-work) |
| 2 | `task + 0x8e8` | `seccomp.mode = 0`, `filter_count = 0` - a real `SECCOMP_MODE_DISABLED` |

Because `mode` is `DISABLED`, `copy_seccomp()` stops re-arming the flag, and every
descendant inherits the cleared flags word via `dup_task_struct()`. The rooted child,
the shell it execs, `ksud`, and `ksud`'s own children all run filter-free, which is the
property the late-load needs.

## Ordering and the parked-child window

Order matters at exactly one point: write 2 must never land before write 1 while the
child can execute a syscall (that is the `BUG()`). Two mechanisms make it safe:

- **The child is parked.** W3 sends the `S` command; the child calls `raise(SIGSTOP)`
  and the parent confirms the group stop with `waitpid(..., WUNTRACED)`. No userspace
  syscall of the child can observe an intermediate state, whatever order the kernel
  writes land in.
- **A partial state is still safe.** If write 1 lands and write 2 does not, the child is
  merely filter-free for itself; if write 1 does not land, write 2 is skipped entirely
  (`zero_word(flags) && zero_word(mode)` short-circuits). The only unsafe combination is
  "mode cleared, flag still set", and the sequence never issues it.

After the writes the child is resumed with `SIGCONT` and reports its own
`/proc/self/status` `Seccomp:` value. W3 then forks a child that reports *its own* mode:
`copy_seccomp()` copies `mode` and re-arms `TIF_SECCOMP` only while the mode is not
`DISABLED`, so a forked child that also reports `Seccomp: 0` proves the clear reached the
descendant chain - which is exactly what `sh -> ksud` needs. That fork probe is the
verdict. The `finit_module` errno probe is logged for the record only (see the correction
below: it cannot separate a filtered syscall from an unfiltered one).

`docs/analysis/w3-seccomp-zero-store-plan.md` records the design, the reviewed
lifecycle, and the verification plan.

## Address arithmetic (unchanged)

From the captured run:

| Target | Address | Offset from child task |
|---|---|---|
| child task base | `0xffffff801c11ddc0` | - |
| `cred` (W2) | `0xffffff801c11e5e0` | `+0x820` (2080) |
| `comm` (leaf probe) | `0xffffff801c11e5f0` | `+0x830` (2096) |
| `thread_info.flags` | `0xffffff801c11ddc0` | `+0` |
| `seccomp` | `0xffffff801c11e6a8` | `+0x8e8` (2280) |

W2 writing the credential at `+0x820` and the child reporting `uid=0` proves the child
base and the credential offset. The seccomp target is the same base plus the profile's
`task_struct.seccomp = 2280`, and the W3 leaf-direction probe (zero the comm word, then
read `/proc/self/comm`) proves both that a zero store lands on `[target]` and which side
of a target it hits.

## Expected log for the fixed run

```
W3-0: leaf dir attempt 1/4
leaf dir probe comm_len=0 comm[0]=00
W3: child stopped for the seccomp clear
W3: TIF_SECCOMP clear attempt 1/2
=== W3: TIF_SECCOMP clear === target=0xffffff801c11ddc0 mode=1 leaf=1
W3: seccomp mode clear attempt 1/2
=== W3: seccomp mode clear === target=0xffffff801c11e6a8 mode=1 leaf=1
W3: TIF_SECCOMP re-clear attempt 1/2
W3: child reports Seccomp: 0
forked child reports Seccomp: 0
forked child inherits mode=0 (copy_seccomp stops re-arming)
finit_module probe errno field = 0x9 (informational)
child seccomp disabled (mode=0); descendants run filter-free
```

The two `Seccomp: 0` lines are the gate; the `finit_module` line is informational only.
The root script then logs a filter-free `late-load` and `/proc/modules` gains `kernelsu`.

## Failure signatures

| Log | Meaning |
|---|---|
| `W3 could not park the rooted child` | the child died or stopped reading the command pipe; the chain parks/respawns |
| `W3: child reports Seccomp: 2` | write 2 did not land; the child is still safe (flag write only) and the chain retries |
| `W3: mode is disabled but a forked child is re-armed` | mode landed but the flag write did not; the child runs, but descendants are re-armed |
| `forked child reports Seccomp: 2` | the same condition, seen by the fork probe (the verdict) |
| `finit_module probe errno field = 0xfffffffd` | `-ESRCH`; ambiguous by construction - it is neither a pass nor a fail, which is why it is informational |

## Reproduction

1. Use the built-in profile (`recommend_shizuku = 0`, `w3_attempts = 2`,
   `w3_chain_rounds = 2`).
2. Leave **Run via Shizuku** off.
3. Tap **Run**.
4. Expect `child reports Seccomp: 0`, a probe errno in the 2..40 range, and `kernelsu`
   in `/proc/modules` once the root script finishes.

The Shizuku path still works: a shell flow has no app filter (`Seccomp: 0`) and W3
returns immediately with `no app seccomp filter (shell flow); skipping W3`.

## Corrections adopted from the disarm review

An earlier revision of this document was superseded by a "disarm" change that removed the
W3 writes entirely and recorded the step as `failed`. Its review produced three corrections
that survive here and are now enforced in code:

1. **`~(1ULL << TIF_SECCOMP_BIT)` was never a flag-preserving mask.** It sets every *other*
   bit to 1. The fix does not resurrect a mask: it zeroes whole words, which is the only
   value the primitive can store and the only value that is correct here.
2. **The `finit_module` errno cannot prove anything.** `0xfffffffd` is `-ESRCH`, not a
   `SIGSYS` marker; a `SECCOMP_RET_KILL` action terminates the thread instead of returning,
   and an *unfiltered* `finit_module` also returns `-ESRCH` for a bogus fd. The probe is now
   logged only; the fork probe (above) carries the verdict.
3. **A step may only be recorded `completed` after verification.** `run_state::fail()` and
   the app's `RunStateCodec.Failed` are now used for refused/failed W3 steps, so a rejected
   write can never look like a working bypass again.

The disarm's *conclusion* ("W3 cannot work with this primitive") was wrong: it held only
for non-zero values. Zero is inside the value space, and `thread_info.flags` /
`seccomp.mode` are both words whose correct new value is zero.

## Evidence

- [`docs/evidence/ghostlock_native_final.log`](evidence/ghostlock_native_final.log) - the
  pre-fix run: mask targets, `probe = 0xfffffffd`.
- [`docs/evidence/ghostlock_ksu_final.log`](evidence/ghostlock_ksu_final.log) - pre-fix
  root script with `Seccomp: 2`.
- [`docs/evidence/ghostlock_root.sh`](evidence/ghostlock_root.sh) - the handoff script.
- [`docs/evidence/runstate_poll.log`](evidence/runstate_poll.log) - pre-fix step states.

Those files are the *old* evidence and are kept as the failure record. A device gate log
for the fixed build belongs in `docs/analysis/device-gates/W3-ZERO-STORE.md` (gate
template in `docs/development/documentation-standards.md`).
