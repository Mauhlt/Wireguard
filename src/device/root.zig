//! device module: peers, cryptokey routing, .conf, UDP, the event loop and
//! the `zwg` CLI support. Contract: DESIGN.md.
pub const keys = @import("keys.zig");
pub const ip = @import("ip.zig");
pub const config = @import("config.zig");
pub const allowed_ips = @import("allowed_ips.zig");
pub const AllowedIps = allowed_ips.AllowedIps;
pub const os = @import("os.zig");
pub const index_table = @import("index_table.zig");
pub const ratelimit = @import("ratelimit.zig");
pub const show = @import("show.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("wg_compat_test.zig");
}
