//! The Windows tunnel service (`zwg installtunnel`), modelled on WireGuard
//! for Windows: a per-tunnel LocalSystem service runs the data plane, the
//! unelevated user talks to it over a protected named pipe with the `wg`
//! UAPI text protocol. Design: tests/interop/README.md, "Elevation design".
//!
//! The pure parts (names, SDDL strings, UAPI, the service state machine)
//! build and test on every OS; the rest is Windows-only.
const builtin = @import("builtin");

pub const names = @import("names.zig");
pub const sddl = @import("sddl.zig");
pub const uapi = @import("uapi.zig");
pub const state = @import("state.zig");

const is_windows = builtin.os.tag == .windows;
pub const win32 = if (is_windows) @import("win32.zig") else struct {};
pub const store = if (is_windows) @import("store.zig") else struct {};
pub const log = if (is_windows) @import("log.zig") else struct {};
pub const scm = if (is_windows) @import("scm.zig") else struct {};
pub const pipe = if (is_windows) @import("pipe.zig") else struct {};
pub const tunnel = if (is_windows) @import("tunnel.zig") else struct {};
pub const cli = if (is_windows) @import("cli.zig") else struct {};

test {
    @import("std").testing.refAllDecls(@This());
}
