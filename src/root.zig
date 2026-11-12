//! WireGuard in pure Zig. Module boundaries and contracts: DESIGN.md.
pub const crypto = @import("crypto.zig");
pub const noise = @import("noise/root.zig");
pub const session = @import("session/root.zig");
pub const device = @import("device/root.zig");
pub const tun = @import("tun/root.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
