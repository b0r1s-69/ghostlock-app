# W3 zero-store plan (L: attack path)

Status: implemented on top of `x6840-v2` (which carries the disarm, the NDK `PAGE_SIZE`
guard and the versionCode floor), host- and unit-test-verified; **device gate pending**.

## Motivation

W3 cannot clear seccomp on the X6840 kernel with the current value space. The masked
`TIF_SECCOMP` and `mode=0, filter_count=1` stores are outside the primitive's supported
value space (0 or a mapped kernel pointer), so they never land; the previous mitigation
was to require Shizuku, which needs a PC plus wireless ADB to start its server. The
objective is a root chain that runs entirely in-process: dump -> W1 -> W2 -> W3 ->
`ksud late-load` -> KernelSU, with no ADB and no Shizuku, and no bootloader unlock.

## Root cause (summary)

See [`docs/W3-SECCOMP-ANALYSIS.md`](../W3-SECCOMP-ANALYSIS.md) for the kernel-source
citations. In short:

- the syscall seccomp gate is `TIF_SECCOMP` (bit 11 of `thread_info.flags`, `task+0x00`);
- `__secure_computing()` `BUG()`s on `SECCOMP_MODE_DISABLED`, so `mode` may only be
  cleared after the flag is gone;
- `copy_seccomp()` re-arms the flag in every child while `mode != DISABLED`, so only a
  real `DISABLED` state carries to `sh -> ksud`;
- `release_task()` releases `seccomp.filter` regardless of `mode`, so `DISABLED` with a
  live filter pointer is consistent.

The safe clear is two whole-word zero stores: `task+0x00`, then
`task + task_struct.seccomp` (`{mode, filter_count}`).

## Impacted files

| File | Change |
|---|---|
| `src/core/memory/payload_builder.h` | drop `SeccompFlags` / `SeccompMode`; document the real value space |
| `src/core/memory/payload_builder.cpp` | remove the mask / mode-word arms |
| `src/core/session/victim_process.hpp` | declare `stop_child()` / `continue_and_report_seccomp()` |
| `src/core/session/victim_process.cpp` | `S` protocol step (self `SIGSTOP`, report `Seccomp:`), parent stop/resume helpers |
| `src/core/session/backend/cve_2026_43499_backend.cpp` | `w3()` rewritten: park, flags clear, mode clear, resume, verify |
| `src/core/tests/host/host_attack_script.hpp` | scripted stop verdict, reported mode, ordered timeline of writes |
| `src/core/tests/host/victim_stub.cpp` | stub the two new helpers |
| `src/core/tests/host/route_stub.cpp` | record the write plan (target/mode/leaf) |
| `src/core/tests/host/backend_dataflow_test.cpp` | W3 plan + ordering + no-park regressions |
| `profiles/X6840-6.6.118-final.conf` | `recommend_shizuku = 0`, `w3_attempts = 2`, `w3_settle_us = 50000`, `w3_chain_rounds = 2` |
| `app/src/main/assets/kernel_profiles/6.6.118-...conf` | same values (built-in copy) |
| `docs/W3-SECCOMP-ANALYSIS.md`, `docs/PROFILE.md`, `docs/VERIFICATION.md`, `docs/BUILD-AND-INSTALL.md`, `docs/release-notes.md`, `README.md`, `README_ZH.md` | document the fix and the in-process run |

No change to: `kernelsnitch/`, profile binary format (v2), route catalog, Kotlin wire
contract, or the `w3a`/`w3b`/`w3c` run-state step ids.

## Behavioural difference

| | before | after |
|---|---|---|
| W3 value space | mask / `0x1_00000000` (never lands) | `0` through the leaf arm (proven by W1 and the comm probe) |
| child state during W3 | running, can fork | parked in a group stop for the whole window |
| end state | `Seccomp: 2` | `Seccomp: 0`, descendants filter-free |
| Shizuku | required | optional (shell flow still short-circuits W3) |
| partial failure | `mode=0` with the flag set = kernel `BUG()` | write 2 is skipped when write 1 fails; the parked child is always resumed |

Attack-path ordering that must not change: `prepare_good_kernel_page` -> route ->
`attack_write` per store; W1 -> W2 -> W3 -> handoff; the PI waiter lifetime within one
route is untouched.

## Ownership / lifecycle review

| Object | Owner | Created | Terminated |
|---|---|---|---|
| rooted child task | `VictimContext` (`pipes.child()`), transferred to `session.parked_victim` by `release_child()` | `spawn_victim()` | `retire_child()`, or parked forever by the child itself |
| child command pipe write end | parent (`cmd_write`), moved to `parked_victim_cmd` | `spawn_child()` | reset at handoff/park; child holds the read end |
| child report pipe read end | parent (`uid_read`) | `spawn_child()` | `reset()` after the last report |
| parked-stop state | kernel (`TASK_STOPPED` for the child's own group) | `stop_child()` | `continue_and_report_seccomp()` |
| kernel payload page per store | `prepare_good_kernel_page()` | each `attack_write()` | `support::discard_prebuilt_page()` on route failure |

Every path out of the parked window resumes the child: `w3()` calls
`continue_and_report_seccomp()` unconditionally after the stores, and the only return
before that point (`stop_child()` failure) happens when no stop was taken. A stopped
child can therefore never be handed to `park_retry_child()` (which writes to the command
pipe) or to the handoff.

## Verification plan

1. `make -C src host-attack-dataflow-test` - asserts the W3 plan (zero/leaf only, flags
   before mode, both inside the parked window) and the no-park failure path.
2. `make -C src native-host-tests` - the full host suite (the `tcp_zerocopy_route_test`
   host build fails on x86 because of arm64 inline asm; that is pre-existing and
   unrelated).
3. NDK build of all 24 native TUs, zero warnings; `clang-tidy` on the changed TUs with
   `--warnings-as-errors`.
4. `tools/cmp_disasm.py` against the previous release binary for the 8 attack functions;
   the W3 stage is expected to differ (it is the fix) - the other functions must be
   identical or annotated.
5. Android unit tests: `:app:testDebugUnitTest` (82 tests) and `:profile-core:test`
   (19 tests) are green, including the new `X6840ProfileDefaultsTest` and the
   `ProfileMerger` preset-aliasing regression.
6. **Device gate (pending)**: cold boot, CPU pair 6/7, `select_stack` route, KernelSU not
   loaded, Shizuku off; expect `child reports Seccomp: 0`, a probe errno in 2..40,
   `kernelsu` in `/proc/modules`, then `su -c id`. Archive the log per
   `docs/analysis/device-gates/`.
