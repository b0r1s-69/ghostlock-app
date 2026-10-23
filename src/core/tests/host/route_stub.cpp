#include "host_attack_script.hpp"
#include "route/route_api.hpp"
#include "route/route_middleware.hpp"

#include "session/exploit_session.hpp"

/* Host stubs for the middleware route. The real PI race never runs; the
 * scripted Status stands in for "verified write". */
namespace ghostlock::route::middleware {
    Status run_middleware_route(session::ExploitSession &session,
                                const memory::WriteRequest &request) {
        (void) session;
        host::script().record("route");
        host::script().record_write(
            static_cast<uintptr_t>(request.target),
            static_cast<int32_t>(request.mode),
            request.preserve_child ? 0 : 1);
        return host::script().next_route();
    }
} // namespace ghostlock::route::middleware

namespace ghostlock::route {
    void reserve_standard_io(void) {}

    RouteStatus do_pselect_fake_lock_route(const ghostlock::memory::WriteRequest *request) {
        (void) request;
        return RouteStatus{};
    }

    RouteStatus do_tcp_fake_lock_route(const ghostlock::memory::WriteRequest *request) {
        (void) request;
        return RouteStatus{};
    }

    RouteStatus do_kernel5_fake_lock_route(const ghostlock::memory::WriteRequest *request) {
        (void) request;
        return RouteStatus{};
    }
} // namespace ghostlock::route
