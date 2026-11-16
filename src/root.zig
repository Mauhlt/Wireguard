//! WireGuard in pure Zig. Module boundaries and contracts: DESIGN.md.
pub const crypto = @import("crypto.zig");
/// IP addresses and prefixes, shared by device and tun.
pub const ip = @import("ip.zig");
pub const noise = @import("noise/root.zig");
pub const session = @import("session/root.zig");
pub const device = @import("device/root.zig");
pub const tun = @import("tun/root.zig");
pub const service = @import("service/root.zig");
pub const netstack = @import("netstack/root.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("fuzz.zig");
    _ = @import("thread_stack.zig");
}
