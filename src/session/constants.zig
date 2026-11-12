//! Protocol constants for transport data, replay protection and timers.
//!
//! Sources:
//!   [WP]  WireGuard whitepaper (Donenfeld, NDSS 2017, rev. e2da747), §5.4.6
//!         ("Subsequent Messages: Transport Data Messages") and §6 ("Timers &
//!         Stateless UX"), table in §6.1 ("Preliminaries").
//!   [LK]  Linux kernel drivers/net/wireguard/messages.h (`enum counter_values`,
//!         `enum limits`), timers.c, noise.c, send.c, receive.c.
//!   [GO]  wireguard-go device/constants.go, device/timers.go, replay/replay.go.
//!
//! All times in this module are `i64` nanoseconds on a monotonic clock chosen
//! by the caller (the device). Nothing here reads a clock.

const std = @import("std");

const s = std.time.ns_per_s;
const ms = std.time.ns_per_ms;

/// [WP §6.1] Rekey-After-Messages = 2^60. [LK] `REKEY_AFTER_MESSAGES = 1ULL << 60`,
/// [GO] `RekeyAfterMessages = (1 << 60)`.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// [WP §6.1] Reject-After-Messages = 2^64 − 2^13 − 1. Identical in [GO]
/// (`RejectAfterMessages = (1 << 64) - (1 << 13) - 1`).
/// Note: [LK] uses `U64_MAX - COUNTER_WINDOW_SIZE - 1` = 2^64 − 8130 on 64-bit,
/// which is 63 larger; we use the whitepaper / wireguard-go value (the smaller,
/// i.e. stricter, bound), so we never send a counter the kernel would reject.
pub const REJECT_AFTER_MESSAGES: u64 = std.math.maxInt(u64) - (1 << 13); // 2^64 - 2^13 - 1

/// [WP §6.1] Rekey-After-Time = 120 s.
pub const REKEY_AFTER_TIME: i64 = 120 * s;
/// [WP §6.1] Reject-After-Time = 180 s.
pub const REJECT_AFTER_TIME: i64 = 180 * s;
/// [WP §6.1] Rekey-Attempt-Time = 90 s.
pub const REKEY_ATTEMPT_TIME: i64 = 90 * s;
/// [WP §6.1] Rekey-Timeout = 5 s.
pub const REKEY_TIMEOUT: i64 = 5 * s;
/// [WP §6.1] Keepalive-Timeout = 10 s.
pub const KEEPALIVE_TIMEOUT: i64 = 10 * s;

/// Jitter added to REKEY_TIMEOUT based timers: uniformly 0..333 ms.
/// [WP §6]: jitter of up to 1/3 s on Rekey-Timeout based timers;
/// [LK] `REKEY_TIMEOUT_JITTER_MAX_JIFFIES = HZ / 3`, `get_random_u32_below(...)`;
/// [GO] `RekeyTimeoutJitterMaxMs = 334`, `fastrandn(334)` → [0, 333] ms.
pub const REKEY_TIMEOUT_JITTER_MAX_MS: u64 = 333;

/// Number of *retries* after the first initiation before giving up.
/// [LK] `MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT` = 18,
/// [GO] `MaxTimerHandshakes = 90 / 5`. The retransmit timer gives up when
/// `attempts > MAX_TIMER_HANDSHAKES`, i.e. after 1 + 19 initiations ≈ 100 s;
/// this is how both implementations realise REKEY_ATTEMPT_TIME.
pub const MAX_TIMER_HANDSHAKES: u32 = @intCast(@divExact(REKEY_ATTEMPT_TIME, REKEY_TIMEOUT));

/// Key material is zeroed this long after the last session was derived:
/// [WP §6]: after 3 × Reject-After-Time, [LK]/[GO] `REJECT_AFTER_TIME * 3`.
pub const ZERO_KEY_MATERIAL_AFTER: i64 = REJECT_AFTER_TIME * 3;

/// Initiator sends a "last minute" handshake when receiving on a keypair this
/// old, [WP §6]: Reject-After-Time − Keepalive-Timeout − Rekey-Timeout.
pub const REKEY_ON_RECEIVE_AFTER_TIME: i64 = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;

/// New-handshake timer after sending data with no reply:
/// [WP §6] Keepalive-Timeout + Rekey-Timeout (+ jitter in [LK]/[GO]).
pub const NEW_HANDSHAKE_AFTER: i64 = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

/// Replay window. [LK] messages.h: `COUNTER_BITS_TOTAL = 8192`,
/// `COUNTER_REDUNDANT_BITS = BITS_PER_LONG`, `COUNTER_WINDOW_SIZE =
/// COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS` = 8192 − 64 = 8128 on 64-bit.
/// [GO] replay.go: `ringBlocks = 1 << 7`, `blockBits = 64`,
/// `windowSize = (ringBlocks - 1) * blockBits` = 8128. RFC 6479 §2 design.
pub const COUNTER_BITS_TOTAL: u64 = 8192;
pub const COUNTER_REDUNDANT_BITS: u64 = 64;
pub const COUNTER_WINDOW_SIZE: u64 = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS;

/// [WP §5.4.6] plaintext is zero-padded to a multiple of 16 bytes.
pub const PADDING_MULTIPLE: usize = 16;

comptime {
    std.debug.assert(REJECT_AFTER_MESSAGES == 18446744073709543423);
    std.debug.assert(MAX_TIMER_HANDSHAKES == 18);
    std.debug.assert(COUNTER_WINDOW_SIZE == 8128);
    std.debug.assert(REKEY_ON_RECEIVE_AFTER_TIME == 165 * s);
}

test "constants" {
    try std.testing.expectEqual(@as(u64, 1152921504606846976), REKEY_AFTER_MESSAGES);
    // 2^64 - 2^13 - 1
    try std.testing.expectEqual(@as(u128, (1 << 64) - (1 << 13) - 1), @as(u128, REJECT_AFTER_MESSAGES));
    _ = ms;
}
