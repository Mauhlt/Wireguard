//! session module: keypairs, transport data messages (type 4), replay
//! window and per-peer timers. Contract: DESIGN.md.
//!
//! Layers (each usable on its own):
//! * `transport`    stateless wire format: `Header.parse/write`, `seal`,
//!                  `open`, `paddedLen`, `messageLen`.
//! * `ReplayWindow` RFC 6479 bitmap, 8128-counter window.
//! * `Keypair` / `Keypairs`  counters, expiry, current/previous/next
//!                  rotation (rules documented in keypair.zig).
//! * `Timers`       pure event-driven timer state machine (table in
//!                  timers.zig); `next()` deadline, `due()` actions.
//! * `Peer`         Keypairs + Timers wired like the kernel / wireguard-go
//!                  send, receive and handshake paths; what the device calls.
//!
//! Times are i64 nanoseconds on the caller's monotonic clock. Nothing
//! allocates, reads a clock or does I/O. Not thread-safe (one event loop).
pub const constants = @import("constants.zig");
pub const transport = @import("transport.zig");
pub const ReplayWindow = @import("replay.zig").ReplayWindow;
pub const keypair = @import("keypair.zig");
pub const Keypair = keypair.Keypair;
pub const Keypairs = keypair.Keypairs;
pub const Seed = keypair.Seed;
pub const Retired = keypair.Retired;
pub const timers = @import("timers.zig");
pub const Timers = timers.Timers;
pub const Jitter = timers.Jitter;
pub const Actions = timers.Actions;
pub const Peer = @import("peer.zig").Peer;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("constants.zig");
    _ = @import("replay.zig");
    _ = @import("transport.zig");
    _ = @import("keypair.zig");
    _ = @import("timers.zig");
    _ = @import("peer.zig");
}
