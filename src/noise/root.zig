//! noise module: the WireGuard handshake (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s),
//! MAC1/MAC2 and cookies. Contract: DESIGN.md. Pure: no I/O, no clock reads,
//! randomness and time are passed in.
const messages = @import("messages.zig");
const cookie = @import("cookie.zig");
const handshake = @import("handshake.zig");

// Wire format.
pub const MessageType = messages.MessageType;
pub const ParseError = messages.ParseError;
pub const messageType = messages.messageType;
pub const transport_min_len = messages.transport_min_len;
pub const Initiation = messages.Initiation;
pub const Response = messages.Response;
pub const CookieReply = messages.CookieReply;

// MACs and cookies.
pub const CookieChecker = cookie.CookieChecker;
pub const CookieGenerator = cookie.CookieGenerator;
pub const Verdict = cookie.Verdict;
pub const label_mac1 = cookie.label_mac1;
pub const label_cookie = cookie.label_cookie;
pub const cookie_secret_max_age_ns = cookie.cookie_secret_max_age_ns;
pub const cookie_secret_latency_ns = cookie.cookie_secret_latency_ns;

// Handshake.
pub const construction = handshake.construction;
pub const identifier = handshake.identifier;
pub const initiations_per_second = handshake.initiations_per_second;
pub const min_initiation_interval_ns = handshake.min_initiation_interval_ns;
pub const Error = handshake.Error;
pub const Local = handshake.Local;
pub const Keys = handshake.Keys;
pub const State = handshake.State;
pub const InitiationStart = handshake.InitiationStart;
pub const Handshake = handshake.Handshake;
pub const consumeInitiationStatic = handshake.consumeInitiationStatic;

test {
    _ = messages;
    _ = cookie;
    _ = handshake;
    _ = @import("tests.zig");
}
