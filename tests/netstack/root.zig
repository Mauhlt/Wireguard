//! tests/netstack: one test binary for every netstack suite
//! (`zig build test-netstack`; `-Dtest-filter=<substring>` narrows it).
test {
    _ = @import("conformance.zig");
    _ = @import("hostile.zig");
}