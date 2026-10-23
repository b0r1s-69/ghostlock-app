# W3 disarm — change record

**Level:** L (attack-critical path + cross-layer Native↔Kotlin contract)
**Branch:** `very-not-stable-dev`
**Status:** implemented; host checks pass; **NDK build, `cmp_disasm` and the device
gate were NOT run in this environment** (see *Verification* below).

## Motivation

`docs/W3-SECCOMP-ANALYSIS.md` concluded that the write primitive cannot express
the two values W3 needs. The code nevertheless treated a route's "success" as a
completed step, so the status file recorded `w1a…w3c all completed` while the
child stayed `Seccomp: 2`. That false success is what made the no-op path look
like a working bypass and invited repeated re-enabling of the panic-prone zero
store.

Additionally, a live-device run on the X6840 confirmed the supported path
explicitly: `no app seccomp filter (adb/shell flow); skipping W3`, with `adb
shell` reporting `Seccomp: 0`. W3 has never contributed to a successful root.

## Behaviour before / after

| Aspect | Before | After |
| --- | --- | --- |
| `SeccompFlags` / `SeccompMode` layout | built with impossible values; route accepted | rejected in `payload_write_layout()`; request never armed |
| Status recorded for a no-op W3 | `completed` | `failed` (new terminal state) |
| Completion condition | route returned success | `verify_seccomp_probe_stage()` confirmed the change |
| `w3_attempts > 0` on this build | armed, stalled to heap-prepare timeout, then no-op | refused immediately, nothing written |
| Panic risk via W3 | reachable if `w3_attempts` misconfigured | unreachable — no kernel write is attempted |

## Files changed

- `src/core/memory/payload_builder.h` — `SeccompFlags`/`SeccompMode` documented as
  unsupported; recorded that `~(1<<bit)` was never a valid mask.
- `src/core/memory/payload_builder.cpp` — early rejection of both modes;
  defensive rejection in `payload_write_layout_matches_request()`.
- `src/core/support/run_state.{hpp,cpp}` — added `fail()` (status `failed`).
- `src/core/session/backend/cve_2026_43499_backend.cpp` — fast refusal when
  `w3_attempts > 0`; `fail()` on route failure, lost child and failed probe;
  `complete()` only after probe verification. Used `pr_warning`, not `pr_error`,
  because `pr_error` is fatal by design (`exit(-1)`) and would have turned a
  clean refusal into a process death.
- `src/core/session/victim_process.cpp` — corrected the probe interpretation
  (`0xfffffffd` is `-ESRCH`, not SIGSYS; the probe cannot prove the filter is
  armed).
- `app/src/main/kotlin/com/ghostlock/app/data/RunStateCodec.kt` — added the
  `Failed` constant so the cross-layer contract is explicit. `parseStuckStep()`
  still keys only on `in_progress`, so a `failed` step is not reported as a panic.
- `src/core/tests/host/backend_dataflow_test.cpp` — `run_once()` now models both
  environments; the happy path uses the supported shell flow; new
  `test_w3_disarmed_in_app_flow` asserts no seccomp write is attempted.
- `docs/W3-SECCOMP-ANALYSIS.md` — corrections section.

## Preserved (deliberately unchanged)

- `kernelsnitch/` ported code.
- Route implementations, the PI-futex race, waiter lifetime and cleanup ordering.
- The primitive itself: **no change to the value space**. This record does not and
  cannot make W3 work.

## Verification

Run and passing in this environment:

- `payload_builder_test` — pass (`payload builder request/layout vectors passed`)
- `run_state_test` — pass
- `make -C src host-attack-dataflow-test` — pass (`backend_dataflow_test: ok`)
- `-fsyntax-only -Wall -Wextra -Wconversion -Wsign-conversion` on all four touched
  native files — clean (only pre-existing `kernelsnitch/utils.h` warnings remain)

**NOT run — and required before merge** (principle 7: report uncertainty):

- **`make -C src ghostlock` (NDK build).** No NDK, `clang++` or `cmake` on this
  host. The arm64 binary was not produced.
- **`tools/cmp_disasm.py` against the 8 attack functions.** Requires the built
  arm64 binary from the step above, so it is blocked by the same gap.
- **`make -C src lint-tidy`.** `clang-tidy` is not installed.
- **Device gate** (cold boot, fixed CPU pair, KernelSU unloaded) and its archived
  record. Not attempted.

Consequently this change is **unverified on device**. The host harness exercises
the real backend through stub routes; it proves the control flow and the
status semantics, not kernel behaviour.

## Risk

The change only removes writes. It cannot introduce a new kernel write: the two
rejected modes now produce no armed request at all. The residual risk is
behavioural — a device that previously relied on W3's zero store would now get an
explicit refusal instead. No such device exists in this fork's supported set (the
built-in X6840 profile ships `w3_attempts = 0`).

## Rollback

Revert this commit. Nothing outside the listed files is affected, and no profile
or wire format changed.
