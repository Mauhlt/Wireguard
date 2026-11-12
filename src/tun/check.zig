//! Root of the analysis-only cross builds (`zig build tun-check`).
const std = @import("std");
const tun = @import("root.zig");

// This std's default panic handler pulls in std.Io.Threaded, which does not
// compile for iOS (Threaded.zig: null_file has no `fd` on .ios). The check
// does not need panics; an iOS host build must likewise pick a panic handler
// (e.g. std.debug.simple_panic) until std is fixed.
pub const panic = std.debug.no_panic;

export fn zwg_tun_check() void {
    tun.analyzeBackend();
}
