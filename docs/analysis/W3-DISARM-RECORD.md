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

Run and passing:

- `payload_builder_test` — pass (`payload builder request/layout vectors passed`)
- `run_state_test` — pass
- `make -C src host-attack-dataflow-test` — pass (`backend_dataflow_test: ok`)
- `-fsyntax-only -Wall -Wextra -Wconversion -Wsign-conversion` on all four touched
  native files — clean (only pre-existing `kernelsnitch/utils.h` warnings remain)
- **`make -C src ghostlock` with NDK r27.3.13750724 (API 35)** — pass, arm64 PIE,
  721104 bytes
- **`tools/cmp_disasm.py`** baseline (`main` + the `PAGE_SIZE` build fix) vs this
  branch — the 6 resolvable attack functions are `IDENTICAL` in instruction count
  and shape; `LAYOUT-SHIFT` annotations only, i.e. addresses moved because the
  change alters code size. `multicast_owner_worker` / `multicast_waiter_worker`
  are `MISSING` in **both** binaries; the same failure reproduces with
  baseline-vs-baseline, so it is a pre-existing property of this build
  configuration (multicast route not linked), not a regression.

**Still NOT run:**

- **`make -C src lint-tidy`** — `clang-tidy` is not installed on this host.
- **Device gate** (cold boot, fixed CPU pair, KernelSU unloaded) and its archived
  record. Not attempted.

The change is therefore **host- and binary-verified, but not device-gated**. The
host harness exercises the real backend through stub routes; `cmp_disasm` proves
the attack window's machine code is unchanged in shape. Neither proves kernel
behaviour on a device.

## Build-compatibility fix included

`src/core/kernel/constants.hpp` — NDK r27+ defines `PAGE_SIZE` as a macro in
`<bits/page_size.h>` (16 KB page support), which collided with the repo's own
`constexpr PAGE_SIZE` and made **both** `main` and this branch fail to compile:

```
core/kernel/constants.hpp:10:36: error: expected unqualified-id
```

The declaration is now preceded by `#ifdef PAGE_SIZE / #undef PAGE_SIZE`,
mirroring the guard the ported `kernelsnitch` headers already use. Both spellings
are `4096`, so no value changes. This is a build fix, not a behaviour change, and
it is required before any commit on this repo can be built with a current NDK.


## Risk

The change only removes writes. It cannot introduce a new kernel write: the two
rejected modes now produce no armed request at all. The residual risk is
behavioural — a device that previously relied on W3's zero store would now get an
explicit refusal instead. No such device exists in this fork's supported set (the
built-in X6840 profile ships `w3_attempts = 0`).

## Rollback

Revert this commit. Nothing outside the listed files is affected, and no profile
or wire format changed.

## Device install (informational, not a functional gate)

A full `:app:assembleDebug` build was produced with NDK r27.3.13750724 and
`platforms;android-37.2`, then installed on the reference X6840
(`6.6.118-android15-8-g0b9c3bf6db7f`, Android 16):

- `adb install -r` → Success, `versionCode=578`, `lastUpdateTime` advanced,
  app data preserved.
- `am start com.ghostlock.app/.ui.MainActivity` → process up, `logcat -b crash`
  empty.
- Packaged `lib/arm64-v8a/libghostlock.so` contains the `W3 disarmed` string, and
  the X6840 profile asset is present.
- Existing root was unaffected: `su -c id` → `uid=0 … u:r:ksu:s0`, `kernelsu`
  still Live (installing the APK does not touch the LKM).

This verifies **packaging and launch**, not the exploit chain. The exploit was
not re-run: root was already active, and a re-run would risk a panic on a running
device for no benefit. The cold-boot device gate in `AGENTS.md` therefore remains
outstanding.

## Build metadata fix included

`app/build.gradle.kts` — `versionCode` came from `git rev-list --count HEAD`,
which on a shallow clone or fresh fork reports a value far below the previously
published build (88 vs 577). Android refuses a "downgrade", so every later build
would have forced an uninstall and destroyed app data. The value is now
`maxOf(gitVersionCode, 578)`; the commit counter still takes over once it passes
the floor.
