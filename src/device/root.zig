//! device module: peers, cryptokey routing, .conf, UDP, the event loop and
//! the `zwg` CLI support. Contract: DESIGN.md.
pub const keys = @import("keys.zig");
pub const ip = @import("ip.zig");
pub const config = @import("config.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
