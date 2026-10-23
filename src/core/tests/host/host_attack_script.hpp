#ifndef GHOSTLOCK_HOST_ATTACK_SCRIPT_HPP
#define GHOSTLOCK_HOST_ATTACK_SCRIPT_HPP

/*
 * Host-only script driving the attack data flow with no real kernel work.
 *
 * The link-time host stub TUs read their return values from this script, so a
 * test can decide each verify/probe outcome and record
 * the call order. It lives only in the host test binary; the Android build
 * never links it, so no production mutable global is added.
 */

#include <cstdint>
#include <cstdio>
#include <deque>
#include <string>
#include <vector>

#include <sys/types.h>

#include "support/status.hpp"

namespace ghostlock::host {
    struct HostAttackScript {
        /* verify_* outcomes: the front of the queue is consumed per call; an
         * empty queue returns the matching *_default. */
        std::deque<int32_t> verify_selinux{};
        std::deque<int32_t> verify_w2{};
        std::deque<int32_t> verify_seccomp{};
        std::deque<int32_t> verify_leaf{};
        int32_t verify_selinux_default = 1;
        int32_t verify_w2_default = 1;
        int32_t verify_seccomp_default = 1;
        int32_t verify_leaf_default = 1;

        /* Probe verdicts. */
        int32_t selinux_off_initial = 0;
        int32_t enforce_readable_value = 0;
        int32_t process_has_seccomp_value = 1;

        /* One middleware route result per call; empty queue returns *_default. */
        std::deque<ghostlock::Status> route_results{};
        ghostlock::Status route_default = true;

        /* One victim spawn per call; empty queue returns spawn_default. */
        struct Spawn {
            pid_t pid = -1;
            uintptr_t task = 0;
        };
        std::deque<Spawn> spawns{};
        Spawn spawn_default{-1, 0};

        /* Fake kernel page base handed to the heap spray. */
        uintptr_t page_base = 0xffff888000000000ULL;

        /* W3 sanitize window: the parked child verdict and the seccomp mode it
         * reports once resumed. */
        int32_t stop_child_result = 1;
        int32_t reported_seccomp_mode = 0;

        /* Every middleware request the backend issued, in order, so a test can
         * assert the write plan (target / mode / leaf). */
        struct WritePlan {
            uintptr_t target = 0;
            int32_t mode = 0;
            int32_t leaf = 0;
        };
        std::vector<WritePlan> writes{};

        /* One merged, ordered log of protocol steps and route writes, so a test
         * can assert the "park, write, resume" ordering invariant. A write is
         * logged as `write:<target>:<mode>:<leaf>`, target in %zx form. */
        std::vector<std::string> timeline{};

        static std::string write_tag(uintptr_t target, int32_t mode, int32_t leaf) {
            char tag[64] = {};
            std::snprintf(tag, sizeof(tag), "write:%zx:%d:%d",
                          static_cast<size_t>(target), mode, leaf);
            return std::string(tag);
        }

        void record_write(uintptr_t target, int32_t mode, int32_t leaf) {
            writes.push_back(WritePlan{target, mode, leaf});
            timeline.push_back(write_tag(target, mode, leaf));
        }

        /* Handoff probe result. */
        bool handoff_ready = true;

        /* Recorded call order for assertions. */
        std::vector<std::string> calls{};

        void record(const char *name) {
            calls.emplace_back(name);
            timeline.emplace_back(name);
        }

        int32_t next_selinux() { return pop(verify_selinux, verify_selinux_default); }
        int32_t next_w2() { return pop(verify_w2, verify_w2_default); }
        int32_t next_seccomp() { return pop(verify_seccomp, verify_seccomp_default); }
        int32_t next_leaf() { return pop(verify_leaf, verify_leaf_default); }

        ghostlock::Status next_route() {
            if (route_results.empty()) return route_default;
            const ghostlock::Status value = route_results.front();
            route_results.pop_front();
            return value;
        }

        Spawn next_spawn() {
            if (spawns.empty()) return spawn_default;
            const Spawn value = spawns.front();
            spawns.pop_front();
            return value;
        }

    private:
        static int32_t pop(std::deque<int32_t> &queue, int32_t fallback) {
            if (queue.empty()) return fallback;
            const int32_t value = queue.front();
            queue.pop_front();
            return value;
        }
    };

    /* Process-wide script for the host attack data flow. */
    HostAttackScript &script() noexcept;
} // namespace ghostlock::host

#endif
