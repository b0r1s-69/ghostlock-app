/*
 * Host data-flow test: drive the real cve_2026_43499 backend and root_child
 * frontend through Pipeline::run with the attack primitives stubbed. The
 * stage sequence, retries, chain rounds and handoff all execute unchanged; the
 * script decides the verify/probe outcomes.
 */

#include "host_attack_script.hpp"

#include "route/pipeline.hpp"
#include "session/backend/cve_2026_43499_backend.hpp"
#include "session/exploit_session.hpp"
#include "session/root_child_frontend.hpp"

#include <cstdio>
#include <cstdint>

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
     *   true  -> zygote app process WITH a seccomp filter (W3 would be needed)
     *   false -> adb/shell flow reporting Seccomp: 0 (W3 is skipped)
     * The shell flow is the supported path. W3 in the app flow is disarmed in
     * this build, so `app_flow = true` with w3_attempts > 0 must fail. */
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

    /* The disarmed W3 must never attempt the seccomp write. The pipeline
     * deliberately continues to the frontend handoff after W3 is refused (the
     * chain rounds exist for retryable failures), so the guarantee under test
     * is "no seccomp probe/write was attempted", not "the run aborts". On a
     * real device the handoff then fails because ksud cannot load the module.
     * This is the regression guard for the old behaviour, where the stub route
     * accepted a value the primitive cannot express and the run claimed a
     * successful bypass. */
    bool test_w3_disarmed_in_app_flow() {
        reset_script();
        const auto result = run_once(/*app_flow=*/true, /*w3_attempts=*/3);
        bool ok = true;
        ok &= expect(count_calls("verify_seccomp") == 0,
                     "w3-disarmed: no seccomp write is attempted");
        ok &= expect(result.stage == ghostlock::runtime::RunStage::Frontend,
                     "w3-disarmed: run reaches the frontend handoff without crashing");
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
} // namespace

int main() {
    bool ok = true;
    ok &= test_happy_path();
    ok &= test_w3_disarmed_in_app_flow();
    ok &= test_w2_retry_until_success();
    ok &= test_w2_exhausts_attempts();
    ok &= test_selinux_retry_then_w2();
    if (ok) {
        std::puts("backend_dataflow_test: ok");
        return 0;
    }
    return 1;
}
