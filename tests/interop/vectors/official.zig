//! Transcript recorded from the official WireGuard for Windows by
//! `zwg-interop-live --record tests/interop/vectors/official.zig`.
//! Placeholder until the owner runs the live test once (elevated); the
//! keys in a recorded file are throwaway test keys and safe to commit.
pub const available = false;
pub const our_private: [32]u8 = @splat(0);
pub const official_public: [32]u8 = @splat(0);
pub const initiation: [148]u8 = @splat(0);
pub const response_ephemeral_private: [32]u8 = @splat(0);
pub const response_sender: u32 = 0;
pub const response: [92]u8 = @splat(0);
pub const keepalive: [32]u8 = @splat(0);
pub const echo_payload: []const u8 = "";
pub const echo_reply: [64]u8 = @splat(0);
