//! tests/netstack: one test binary for every netstack suite
//! (`zig build test-netstack`; `-Dtest-filter=<substring>` narrows it).
test {
    _ = @import("conformance.zig");
    _ = @import("hostile.zig");
    _ = @import("fuzz.zig");
    _ = @import("e2e.zig");
    _ = @import("vlink.zig");
    _ = @import("priority.zig");
    _ = @import("concurrency.zig");
    _ = @import("sack.zig");
    _ = @import("ipv6.zig");
    _ = @import("recovery.zig");
}