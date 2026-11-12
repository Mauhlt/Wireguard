//! Per-peer WireGuard timers as a pure, event-driven state machine.
//!
//! Nothing ticks. The owner (the device event loop) reports events with
//! `on` / `packetSent` / `packetReceived`, asks `next()` for the earliest
//! deadline, waits until then (or until the next packet), and calls
//! `due(now)` to collect the actions that fell due. When nothing is pending,
//! `next()` is null and the device can sleep indefinitely for this peer.
//!
//! Semantics follow Linux drivers/net/wireguard/timers.c and wireguard-go
//! device/timers.go one-to-one (function names in brackets), with the five
//! kernel timers represented as optional deadlines:
//!
//! | timer                | armed by                                          | disarmed by                     | on expiry                                                                                   |
//! |----------------------|---------------------------------------------------|---------------------------------|---------------------------------------------------------------------------------------------|
//! | retransmit_handshake | handshake initiation sent: +REKEY_TIMEOUT+jitter  | handshake complete              | attempts > MAX_TIMER_HANDSHAKES (18): give up, stop send_keepalive, arm zero_key_material if not pending; else attempts += 1 and retry initiation (rate-limited) |
//! | send_keepalive       | data received, if not pending: +KEEPALIVE_TIMEOUT; else set need_another | any authenticated packet sent | send keepalive; if need_another: clear it and re-arm +KEEPALIVE_TIMEOUT                  |
//! | new_handshake        | data sent, if not pending: +KEEPALIVE_TIMEOUT+REKEY_TIMEOUT+jitter | any authenticated packet received | initiate handshake (attempts reset, rate-limited)                                          |
//! | zero_key_material    | session derived: +3×REJECT_AFTER_TIME; give up (if not pending) | —                     | zero all keypairs and handshake state                                                       |
//! | persistent_keepalive | any authenticated packet sent or received (traversal), if interval > 0: +interval | interval set to 0 | send keepalive (if interval > 0)                                             |
//!
//! Other state: `handshake_attempts` (reset by handshake complete and by any
//! non-retry initiation request), `sent_lastminute_handshake` (reset by
//! handshake complete), `last_sent_handshake` (initiations are rate-limited
//! to one per REKEY_TIMEOUT, kernel `wg_packet_send_queued_handshake_initiation`,
//! wireguard-go `SendHandshakeInitiation`).
//!
//! "Active" = the device is up and the peer running (kernel/go
//! `timers_active`). Inactive timers arm nothing and fire nothing.
//!
//! Note (kept for fidelity): when the send_keepalive timer fires with
//! `need_another_keepalive` set it re-arms itself, but sending that very
//! keepalive is an authenticated packet sent, which disarms it again. In the
//! kernel and wireguard-go the same happens (the re-arm runs before the
//! asynchronous send completes), so we reproduce it rather than "fix" it.
//!
//! Times are i64 nanoseconds on the caller's monotonic clock.

const std = @import("std");
const c = @import("constants.zig");

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

/// Caller-supplied randomness for the 0..333 ms jitter (deterministic in
/// tests). `nextFn` returns any u64; it is reduced modulo 334.
pub const Jitter = struct {
    ctx: ?*anyopaque = null,
    nextFn: *const fn (ctx: ?*anyopaque) u64,

    /// Always 0 ms of jitter.
    pub const none: Jitter = .{ .nextFn = zeroFn };

    fn zeroFn(_: ?*anyopaque) u64 {
        return 0;
    }

    /// Draw jitter from a `std.Random` (e.g. backed by std.crypto.random);
    /// `r` must outlive the Timers.
    pub fn fromRandom(r: *const std.Random) Jitter {
        return .{ .ctx = @constCast(r), .nextFn = randomFn };
    }

    fn randomFn(ctx: ?*anyopaque) u64 {
        const r: *const std.Random = @ptrCast(@alignCast(ctx.?));
        return r.int(u64);
    }

    /// Jitter in nanoseconds, uniformly 0..333 ms (whole milliseconds, like
    /// wireguard-go's `fastrandn(334)`).
    pub fn sample(self: Jitter) i64 {
        const msec = self.nextFn(self.ctx) % (c.REKEY_TIMEOUT_JITTER_MAX_MS + 1);
        return @as(i64, @intCast(msec)) * ns_per_ms;
    }
};

pub const Event = enum {
    /// An authenticated data packet (non-keepalive) was sent [timers_data_sent].
    data_sent,
    /// An authenticated data packet (non-keepalive) was received [timers_data_received].
    data_received,
    /// Any authenticated packet (handshake, keepalive, data) was sent [timers_any_authenticated_packet_sent].
    any_authenticated_packet_sent,
    /// Any authenticated packet was received [timers_any_authenticated_packet_received].
    any_authenticated_packet_received,
    /// Any authenticated packet was sent or received [timers_any_authenticated_packet_traversal].
    any_authenticated_packet_traversal,
    /// A handshake initiation was sent [timers_handshake_initiated].
    handshake_initiated,
    /// Handshake response consumed (initiator), or first data on the `next`
    /// keypair received (responder) [timers_handshake_complete].
    handshake_complete,
    /// A new keypair was derived: before sending a response, or after
    /// consuming one [timers_session_derived].
    session_derived,
};

/// Kind of authenticated packet for `packetSent` / `packetReceived`.
/// (Cookie replies are not authenticated packets and touch no timers.)
pub const PacketKind = enum { handshake_initiation, handshake_response, keepalive, data };

pub const Actions = packed struct {
    /// Send a keepalive (empty transport message). If no key is usable, the
    /// device queues it and requests a handshake, as the kernel does.
    send_keepalive: bool = false,
    /// Send a handshake initiation now (already rate-limited; the device
    /// should also clear the cached endpoint source address, like the
    /// kernel's `wg_socket_clear_peer_endpoint_src`). Report it with
    /// `packetSent(.handshake_initiation)`.
    initiate_handshake: bool = false,
    /// The initiation is a retransmission (informational / logging).
    handshake_retry: bool = false,
    /// Retransmissions exhausted (≈ REKEY_ATTEMPT_TIME): drop queued packets.
    handshake_gave_up: bool = false,
    /// Wipe all keypairs and the handshake state of this peer.
    zero_keys: bool = false,

    pub fn any(self: Actions) bool {
        return self.send_keepalive or self.initiate_handshake or self.handshake_gave_up or self.zero_keys;
    }
};

pub const Timers = struct {
    jitter: Jitter,
    active: bool = false,
    /// Seconds; 0 = off.
    persistent_keepalive_interval: u16 = 0,

    retransmit_handshake: ?i64 = null,
    send_keepalive: ?i64 = null,
    new_handshake: ?i64 = null,
    zero_key_material: ?i64 = null,
    persistent_keepalive: ?i64 = null,

    handshake_attempts: u32 = 0,
    need_another_keepalive: bool = false,
    sent_lastminute_handshake: bool = false,
    last_sent_handshake: ?i64 = null,
    /// Time of the last completed handshake (for status display).
    last_handshake: ?i64 = null,

    pub fn init(jitter: Jitter) Timers {
        return .{ .jitter = jitter };
    }

    /// The peer starts running (device up / peer added). Like the kernel's
    /// `wg_open` and wireguard-go's `upLocked`, a peer with a persistent
    /// keepalive sends one immediately.
    pub fn start(self: *Timers) Actions {
        self.active = true;
        return .{ .send_keepalive = self.persistent_keepalive_interval > 0 };
    }

    /// The peer stops (device down / peer removed): every timer is
    /// disarmed [wg_timers_stop / timersStop].
    pub fn stop(self: *Timers) void {
        self.active = false;
        self.retransmit_handshake = null;
        self.send_keepalive = null;
        self.new_handshake = null;
        self.zero_key_material = null;
        self.persistent_keepalive = null;
        self.need_another_keepalive = false;
    }

    /// Change the persistent keepalive interval (seconds, 0 = off). Turning
    /// it on (0 → n) on a running peer sends a keepalive right away (kernel
    /// netlink.c `send_keepalive`, wireguard-go uapi `pkaOn`). Changing a
    /// non-zero interval takes effect at the next packet, as in both.
    pub fn setPersistentKeepalive(self: *Timers, seconds: u16) Actions {
        const old = self.persistent_keepalive_interval;
        self.persistent_keepalive_interval = seconds;
        // An expiring timer with interval 0 does nothing; dropping the
        // deadline is equivalent and keeps `next()` quiet.
        if (seconds == 0) self.persistent_keepalive = null;
        return .{ .send_keepalive = old == 0 and seconds != 0 and self.active };
    }

    pub fn on(self: *Timers, event: Event, now: i64) void {
        switch (event) {
            .data_sent => if (self.active and self.new_handshake == null) {
                self.new_handshake = now + c.NEW_HANDSHAKE_AFTER + self.jitter.sample();
            },
            .data_received => if (self.active) {
                if (self.send_keepalive == null) {
                    self.send_keepalive = now + c.KEEPALIVE_TIMEOUT;
                } else {
                    self.need_another_keepalive = true;
                }
            },
            .any_authenticated_packet_sent => if (self.active) {
                self.send_keepalive = null;
            },
            .any_authenticated_packet_received => if (self.active) {
                self.new_handshake = null;
            },
            .any_authenticated_packet_traversal => if (self.active and self.persistent_keepalive_interval > 0) {
                self.persistent_keepalive = now + @as(i64, self.persistent_keepalive_interval) * ns_per_s;
            },
            .handshake_initiated => {
                self.last_sent_handshake = now;
                if (self.active) self.retransmit_handshake = now + c.REKEY_TIMEOUT + self.jitter.sample();
            },
            .handshake_complete => {
                if (self.active) self.retransmit_handshake = null;
                self.handshake_attempts = 0;
                self.sent_lastminute_handshake = false;
                self.last_handshake = now;
            },
            .session_derived => if (self.active) {
                self.zero_key_material = now + c.ZERO_KEY_MATERIAL_AFTER;
            },
        }
    }

    /// Record an authenticated packet we sent, firing the same timer hooks
    /// as the kernel / wireguard-go send paths.
    pub fn packetSent(self: *Timers, kind: PacketKind, now: i64) void {
        self.on(.any_authenticated_packet_traversal, now);
        self.on(.any_authenticated_packet_sent, now);
        switch (kind) {
            .data => self.on(.data_sent, now),
            .handshake_initiation => self.on(.handshake_initiated, now),
            .keepalive, .handshake_response => {},
        }
    }

    /// Record an authenticated packet we received (after it verified).
    pub fn packetReceived(self: *Timers, kind: PacketKind, now: i64) void {
        self.on(.any_authenticated_packet_traversal, now);
        self.on(.any_authenticated_packet_received, now);
        if (kind == .data) self.on(.data_received, now);
    }

    /// May a handshake initiation be sent now? Resets the attempt counter
    /// unless this is a retry, and enforces at most one initiation per
    /// REKEY_TIMEOUT. Used for every initiation trigger outside `due`
    /// (no usable key, rekey-after-time/messages, last-minute rekey).
    pub fn requestHandshake(self: *Timers, now: i64, is_retry: bool) bool {
        if (!is_retry) self.handshake_attempts = 0;
        if (!self.active) return false;
        if (self.last_sent_handshake) |t| if (now - t < c.REKEY_TIMEOUT) return false;
        return true;
    }

    /// Earliest pending deadline, or null if nothing is pending (then the
    /// device need not wake up for this peer at all). A deadline ≤ `now`
    /// means `due` should be called immediately.
    pub fn next(self: *const Timers, now: i64) ?i64 {
        _ = now;
        var best: ?i64 = null;
        for ([_]?i64{
            self.retransmit_handshake,
            self.send_keepalive,
            self.new_handshake,
            self.zero_key_material,
            self.persistent_keepalive,
        }) |d| {
            if (d) |t| best = if (best) |b| @min(b, t) else t;
        }
        return best;
    }

    fn take(deadline: *?i64, now: i64) bool {
        if (deadline.*) |t| if (t <= now) {
            deadline.* = null;
            return true;
        };
        return false;
    }

    /// Fire every timer whose deadline is ≤ `now` and return what to do.
    pub fn due(self: *Timers, now: i64) Actions {
        var a: Actions = .{};
        if (!self.active) return a;

        if (take(&self.retransmit_handshake, now)) {
            // [wg_expired_retransmit_handshake / expiredRetransmitHandshake]
            if (self.handshake_attempts > c.MAX_TIMER_HANDSHAKES) {
                self.send_keepalive = null;
                a.handshake_gave_up = true;
                if (self.zero_key_material == null)
                    self.zero_key_material = now + c.ZERO_KEY_MATERIAL_AFTER;
            } else {
                self.handshake_attempts += 1;
                if (self.requestHandshake(now, true)) {
                    a.initiate_handshake = true;
                    a.handshake_retry = true;
                }
            }
        }
        if (take(&self.send_keepalive, now)) {
            // [wg_expired_send_keepalive / expiredSendKeepalive]
            a.send_keepalive = true;
            if (self.need_another_keepalive) {
                self.need_another_keepalive = false;
                self.send_keepalive = now + c.KEEPALIVE_TIMEOUT;
            }
        }
        if (take(&self.new_handshake, now)) {
            // [wg_expired_new_handshake / expiredNewHandshake]
            if (self.requestHandshake(now, false)) a.initiate_handshake = true;
        }
        if (take(&self.zero_key_material, now)) {
            // [wg_expired_zero_key_material / expiredZeroKeyMaterial]
            a.zero_keys = true;
        }
        if (take(&self.persistent_keepalive, now)) {
            // [wg_expired_send_persistent_keepalive / expiredPersistentKeepalive]
            if (self.persistent_keepalive_interval > 0) a.send_keepalive = true;
        }
        return a;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const s = ns_per_s;
const ms = ns_per_ms;

/// Jitter that always returns the same number of milliseconds.
fn fixedJitter(comptime msec: u64) Jitter {
    const F = struct {
        fn f(_: ?*anyopaque) u64 {
            return msec;
        }
    };
    return .{ .nextFn = F.f };
}

fn started(j: Jitter) Timers {
    var t = Timers.init(j);
    _ = t.start();
    return t;
}

test "jitter range and determinism" {
    try testing.expectEqual(@as(i64, 0), Jitter.none.sample());
    try testing.expectEqual(@as(i64, 333 * ms), fixedJitter(333).sample());
    try testing.expectEqual(@as(i64, 0), fixedJitter(334).sample());
    try testing.expectEqual(@as(i64, 1 * ms), fixedJitter(335).sample());
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    const j = Jitter.fromRandom(&r);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const v = j.sample();
        try testing.expect(v >= 0 and v <= 333 * ms and @rem(v, ms) == 0);
    }
}

test "no tick: idle peer has no deadline" {
    var t = Timers.init(Jitter.none);
    try testing.expectEqual(@as(?i64, null), t.next(0));
    try testing.expect(!t.start().any());
    try testing.expectEqual(@as(?i64, null), t.next(0));
    try testing.expect(!t.due(std.math.maxInt(i64)).any());
    // Keepalives (sent or received) do not arm anything without a
    // persistent keepalive.
    t.packetSent(.keepalive, 1 * s);
    t.packetReceived(.keepalive, 2 * s);
    try testing.expectEqual(@as(?i64, null), t.next(2 * s));
}

test "passive keepalive: only after receiving data without sending" {
    var t = started(Jitter.none);
    t.packetReceived(.data, 0);
    try testing.expectEqual(@as(?i64, 10 * s), t.next(0));
    try testing.expect(!t.due(10 * s - 1).any());
    const a = t.due(10 * s);
    try testing.expect(a.send_keepalive and !a.initiate_handshake);
    t.packetSent(.keepalive, 10 * s);
    try testing.expectEqual(@as(?i64, null), t.next(10 * s));

    // Replying with data within 10 s suppresses the keepalive.
    t.packetReceived(.data, 20 * s);
    t.packetSent(.data, 21 * s);
    try testing.expectEqual(@as(?i64, null), t.send_keepalive);
    // (data_sent armed new_handshake; a reply clears it)
    t.packetReceived(.keepalive, 22 * s);
    try testing.expectEqual(@as(?i64, null), t.next(22 * s));

    // A received keepalive (not data) never triggers a keepalive.
    t.packetReceived(.keepalive, 30 * s);
    try testing.expectEqual(@as(?i64, null), t.next(30 * s));
}

test "passive keepalive: need_another re-arms but the keepalive send disarms" {
    var t = started(Jitter.none);
    t.packetReceived(.data, 0);
    t.packetReceived(.data, 5 * s); // already pending: need another
    try testing.expect(t.need_another_keepalive);
    try testing.expectEqual(@as(?i64, 10 * s), t.next(5 * s)); // not pushed back
    const a = t.due(10 * s);
    try testing.expect(a.send_keepalive);
    try testing.expectEqual(@as(?i64, 20 * s), t.send_keepalive);
    try testing.expect(!t.need_another_keepalive);
    // Sending that keepalive is an authenticated packet: disarms (kernel/go).
    t.packetSent(.keepalive, 10 * s);
    try testing.expectEqual(@as(?i64, null), t.next(10 * s));
}

test "new handshake after sending data with no reply (15 s + jitter)" {
    var t = started(fixedJitter(200));
    t.packetSent(.data, 0);
    const d = 15 * s + 200 * ms;
    try testing.expectEqual(@as(?i64, d), t.next(0));
    // More data does not push the deadline.
    t.packetSent(.data, 3 * s);
    try testing.expectEqual(@as(?i64, d), t.next(3 * s));
    try testing.expect(!t.due(d - 1).any());
    const a = t.due(d);
    try testing.expect(a.initiate_handshake and !a.handshake_retry);
    try testing.expectEqual(@as(?i64, null), t.next(d));

    // Any authenticated packet received in time cancels it — even a keepalive.
    t.packetSent(.data, 100 * s);
    t.packetReceived(.keepalive, 110 * s);
    try testing.expectEqual(@as(?i64, null), t.next(110 * s));
    // A sent keepalive (not data) does not arm it.
    t.packetSent(.keepalive, 120 * s);
    try testing.expectEqual(@as(?i64, null), t.next(120 * s));
}

test "handshake retransmission, give up after 1+19 attempts, zero keys 540 s later" {
    var t = started(fixedJitter(100));
    var now: i64 = 0;
    try testing.expect(t.requestHandshake(now, false));
    t.packetSent(.handshake_initiation, now);
    var initiations: usize = 1;
    var gave_up_at: ?i64 = null;
    while (true) {
        const d = t.next(now) orelse break;
        try testing.expect(d > now);
        now = d;
        const a = t.due(now);
        if (a.initiate_handshake) {
            try testing.expect(a.handshake_retry);
            try testing.expectEqual(5 * s + 100 * ms, now - t.last_sent_handshake.?);
            t.packetSent(.handshake_initiation, now);
            initiations += 1;
        }
        if (a.handshake_gave_up) {
            try testing.expectEqual(@as(?i64, null), gave_up_at);
            gave_up_at = now;
            try testing.expectEqual(@as(?i64, now + 540 * s), t.next(now));
        }
        if (a.zero_keys) {
            try testing.expectEqual(gave_up_at.? + 540 * s, now);
        }
    }
    try testing.expectEqual(@as(usize, 20), initiations);
    try testing.expectEqual(@as(i64, 20 * (5 * s + 100 * ms)), gave_up_at.?);
    try testing.expectEqual(@as(u32, 19), t.handshake_attempts);
    try testing.expectEqual(@as(?i64, null), t.next(now));
}

test "handshake complete stops retransmission and resets attempts" {
    var t = started(Jitter.none);
    t.packetSent(.handshake_initiation, 0);
    var a = t.due(5 * s);
    try testing.expect(a.initiate_handshake and a.handshake_retry);
    t.packetSent(.handshake_initiation, 5 * s);
    try testing.expectEqual(@as(u32, 1), t.handshake_attempts);
    t.packetReceived(.handshake_response, 6 * s);
    t.on(.session_derived, 6 * s);
    t.on(.handshake_complete, 6 * s);
    try testing.expectEqual(@as(u32, 0), t.handshake_attempts);
    try testing.expectEqual(@as(?i64, 6 * s), t.last_handshake);
    // Only the zero-key-material timer remains.
    try testing.expectEqual(@as(?i64, 6 * s + 540 * s), t.next(6 * s));
    a = t.due(6 * s + 539 * s);
    try testing.expect(!a.any());
}

test "a give-up does not postpone an already pending zero_key_material" {
    var t = started(Jitter.none);
    t.on(.session_derived, 0);
    t.handshake_attempts = c.MAX_TIMER_HANDSHAKES + 1;
    t.packetSent(.handshake_initiation, 100 * s);
    t.handshake_attempts = c.MAX_TIMER_HANDSHAKES + 1; // packetSent doesn't reset; explicit
    const a = t.due(105 * s);
    try testing.expect(a.handshake_gave_up and !a.initiate_handshake);
    try testing.expectEqual(@as(?i64, 540 * s), t.zero_key_material);
}

test "give up disarms the passive keepalive" {
    var t = started(Jitter.none);
    t.handshake_attempts = c.MAX_TIMER_HANDSHAKES + 1;
    t.packetSent(.handshake_initiation, 0);
    t.packetReceived(.data, 1 * s); // arms send_keepalive at 11 s
    const a = t.due(5 * s);
    try testing.expect(a.handshake_gave_up);
    try testing.expectEqual(@as(?i64, null), t.send_keepalive);
}

test "initiations are rate-limited to one per REKEY_TIMEOUT" {
    var t = started(Jitter.none);
    try testing.expect(t.requestHandshake(0, false));
    t.packetSent(.handshake_initiation, 0);
    try testing.expect(!t.requestHandshake(1 * s, false));
    try testing.expect(!t.requestHandshake(5 * s - 1, true));
    try testing.expect(t.requestHandshake(5 * s, false));
    // new_handshake expiring within REKEY_TIMEOUT of an initiation is dropped
    // (the retransmit timer already covers it).
    t.packetSent(.handshake_initiation, 100 * s);
    t.new_handshake = 102 * s;
    const a = t.due(102 * s);
    try testing.expect(!a.initiate_handshake);
    // Non-retry requests reset the attempt counter even when rate-limited.
    t.handshake_attempts = 7;
    _ = t.requestHandshake(103 * s, false);
    try testing.expectEqual(@as(u32, 0), t.handshake_attempts);
}

test "zero key material 3 x REJECT_AFTER_TIME after last session" {
    var t = started(Jitter.none);
    t.on(.session_derived, 0);
    t.on(.session_derived, 100 * s); // new session pushes it
    try testing.expectEqual(@as(?i64, 640 * s), t.next(100 * s));
    try testing.expect(!t.due(639 * s).any());
    const a = t.due(640 * s);
    try testing.expect(a.zero_keys and !a.send_keepalive and !a.initiate_handshake);
    try testing.expectEqual(@as(?i64, null), t.next(640 * s));
}

test "persistent keepalive" {
    var t = Timers.init(Jitter.none);
    // Configured before start: start() sends one keepalive.
    try testing.expect(!t.setPersistentKeepalive(25).any()); // inactive
    try testing.expect(t.start().send_keepalive);
    t.packetSent(.keepalive, 0);
    try testing.expectEqual(@as(?i64, 25 * s), t.next(0));
    // Any authenticated traffic pushes it.
    t.packetReceived(.data, 10 * s); // also arms passive keepalive at 20 s
    try testing.expectEqual(@as(?i64, 20 * s), t.next(10 * s));
    var a = t.due(20 * s);
    try testing.expect(a.send_keepalive);
    t.packetSent(.keepalive, 20 * s);
    try testing.expectEqual(@as(?i64, 45 * s), t.next(20 * s));
    a = t.due(45 * s);
    try testing.expect(a.send_keepalive);
    t.packetSent(.keepalive, 45 * s);
    try testing.expectEqual(@as(?i64, 70 * s), t.next(45 * s));
    // Changing a non-zero interval takes effect at the next packet.
    try testing.expect(!t.setPersistentKeepalive(5).any());
    try testing.expectEqual(@as(?i64, 70 * s), t.next(45 * s));
    t.packetReceived(.keepalive, 50 * s);
    try testing.expectEqual(@as(?i64, 55 * s), t.next(50 * s));
    // Turning it off: no deadline left (no tick).
    _ = t.setPersistentKeepalive(0);
    try testing.expectEqual(@as(?i64, null), t.next(50 * s));
    // 0 → n on a running peer: immediate keepalive.
    try testing.expect(t.setPersistentKeepalive(15).send_keepalive);
}

test "stop disarms everything; inactive timers neither arm nor fire" {
    var t = started(Jitter.none);
    _ = t.setPersistentKeepalive(25);
    t.packetSent(.data, 0);
    t.packetReceived(.data, 0);
    t.packetSent(.handshake_initiation, 0);
    t.on(.session_derived, 0);
    try testing.expect(t.next(0) != null);
    t.stop();
    try testing.expectEqual(@as(?i64, null), t.next(0));
    t.packetSent(.data, 1 * s);
    t.packetReceived(.data, 1 * s);
    t.packetSent(.handshake_initiation, 1 * s);
    t.on(.session_derived, 1 * s);
    try testing.expectEqual(@as(?i64, null), t.next(1 * s));
    try testing.expect(!t.due(1000 * s).any());
    try testing.expect(!t.requestHandshake(1000 * s, false));
}

test "a timer fires once" {
    var t = started(Jitter.none);
    t.packetReceived(.data, 0);
    try testing.expect(t.due(10 * s).send_keepalive);
    try testing.expect(!t.due(10 * s).any());
    try testing.expect(!t.due(100 * s).any());
}

test "late due() fires every overdue timer at once" {
    var t = started(Jitter.none);
    t.on(.session_derived, 0);
    t.packetSent(.data, 0); // new_handshake at 15 s
    t.on(.data_received, 0); // send_keepalive at 10 s
    const a = t.due(1000 * s);
    try testing.expect(a.send_keepalive and a.initiate_handshake and a.zero_keys);
}

/// Simulated device: answers actions the way a device would (sending the
/// requested packets and reporting them). No peer replies.
fn drive(t: *Timers, now: i64) Actions {
    const a = t.due(now);
    if (a.initiate_handshake) t.packetSent(.handshake_initiation, now);
    if (a.send_keepalive) t.packetSent(.keepalive, now);
    return a;
}

test "no tick property: any event history settles to next() == null without persistent keepalive" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const r = prng.random();
    const jr = r;
    var round: usize = 0;
    while (round < 300) : (round += 1) {
        var t = started(Jitter.fromRandom(&jr));
        var now: i64 = 0;
        var k: usize = 0;
        const n_events = r.uintLessThan(usize, 40);
        while (k < n_events) : (k += 1) {
            now += r.intRangeAtMost(i64, 0, 30 * s);
            // Fire whatever became due on the way.
            while (t.next(now)) |d| {
                if (d > now) break;
                _ = drive(&t, d);
            }
            switch (r.uintLessThan(u8, 9)) {
                0 => t.packetSent(.data, now),
                1 => t.packetReceived(.data, now),
                2 => t.packetSent(.keepalive, now),
                3 => t.packetReceived(.keepalive, now),
                4 => if (t.requestHandshake(now, false)) t.packetSent(.handshake_initiation, now),
                5 => {
                    t.packetReceived(.handshake_response, now);
                    t.on(.session_derived, now);
                    t.on(.handshake_complete, now);
                },
                6 => {
                    t.packetReceived(.handshake_initiation, now);
                    t.on(.session_derived, now);
                    t.packetSent(.handshake_response, now);
                },
                7 => t.on(.handshake_complete, now),
                else => _ = t.setPersistentKeepalive(0),
            }
        }
        // Now silence: follow deadlines only. Must terminate (bounded by
        // retransmissions + zero-key) and every deadline must be in the future
        // of the previous one or now.
        var steps: usize = 0;
        while (t.next(now)) |d| {
            try testing.expect(steps < 100);
            now = @max(now, d);
            _ = drive(&t, now);
            steps += 1;
        }
        try testing.expectEqual(@as(?i64, null), t.next(now));
        try testing.expect(!t.due(now + 10_000 * s).any());
    }
}

test "with persistent keepalive the peer keeps a deadline forever" {
    var t = started(Jitter.none);
    try testing.expect(t.setPersistentKeepalive(25).send_keepalive);
    t.packetSent(.keepalive, 0);
    var now: i64 = 0;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const d = t.next(now).?;
        try testing.expectEqual(now + 25 * s, d);
        now = d;
        try testing.expect(drive(&t, now).send_keepalive);
    }
}
