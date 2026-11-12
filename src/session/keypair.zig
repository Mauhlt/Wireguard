//! Keypairs and per-peer keypair rotation (current / previous / next).
//!
//! Rotation rules — identical to Linux noise.c `add_new_keypair` /
//! `wg_noise_received_with_keypair` and wireguard-go
//! `BeginSymmetricSession` / `ReceivedWithKeypair`:
//!
//! * New keypair, we are the INITIATOR (we just consumed a handshake
//!   response, so the peer already holds the same keys and we may send at
//!   once):
//!     - if a `next` exists: previous ← next, next ← ∅, old current and old
//!       previous are destroyed;
//!     - else: previous ← current, old previous destroyed;
//!     - current ← new.
//! * New keypair, we are the RESPONDER (we just sent a handshake response;
//!   the initiator has not yet proven it received it):
//!     - next ← new (an older unconfirmed next is destroyed),
//!       previous destroyed, current unchanged (may keep sending on it).
//! * First authenticated packet received on `next` (key confirmation for
//!   the responder): previous destroyed, previous ← current,
//!   current ← next, next ← ∅. This is reported as `confirmed`, which the
//!   caller turns into the "handshake complete" timer event and a flush of
//!   queued packets.
//! * Sending always uses `current` only. Receiving accepts any of the three.
//! * `clear` (zero-key-material timer, peer removal) destroys all three.
//!
//! "Destroyed" means wiped with `std.crypto.secureZero`; the local indices of
//! destroyed keypairs are returned so the device can drop them from its
//! receiver-index table.
//!
//! Expiry (checked at use, kernel send.c/receive.c, wireguard-go send.go /
//! receive.go): a keypair can neither send nor receive once
//! `now - created >= REJECT_AFTER_TIME` (kernel `wg_birthdate_has_expired`
//! uses `<=` on the deadline; wireguard-go uses a strict compare — the 1 ns
//! difference is immaterial), nor send once its counter reaches
//! REJECT_AFTER_MESSAGES, nor receive counters ≥ REJECT_AFTER_MESSAGES.
//!
//! Not thread-safe: owned by the device's single event loop.

const std = @import("std");
const c = @import("constants.zig");
const transport = @import("transport.zig");
const ReplayWindow = @import("replay.zig").ReplayWindow;

pub const SymKey = transport.SymKey;

/// What the handshake (noise) hands over after deriving a session.
pub const Seed = struct {
    send: SymKey,
    recv: SymKey,
    /// Our index: peers address their packets to it (receiver_index).
    local_index: u32,
    /// The peer's index: we put it in the packets we send.
    remote_index: u32,
    is_initiator: bool,

    pub fn wipe(self: *Seed) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const EncryptError = error{
    /// No usable sending key: expired by time, counter exhausted, or
    /// invalidated. The caller queues the packet and requests a handshake.
    NoKey,
    BufferTooSmall,
};

pub const DecryptError = error{
    Malformed,
    /// The receiver index is not one of this keypair / peer.
    UnknownIndex,
    /// The keypair is too old (REJECT_AFTER_TIME) or invalidated.
    KeyExpired,
    /// Counter already seen, too far behind, or ≥ REJECT_AFTER_MESSAGES.
    Replay,
    AuthenticationFailed,
    BufferTooSmall,
};

pub const Keypair = struct {
    send_key: SymKey,
    recv_key: SymKey,
    local_index: u32,
    remote_index: u32,
    /// Creation time (ns, caller's monotonic clock).
    created: i64,
    is_initiator: bool,
    /// Next counter to send with.
    send_counter: u64 = 0,
    sending_valid: bool = true,
    receiving_valid: bool = true,
    replay: ReplayWindow = .{},

    /// Build a keypair from a handshake seed and wipe the seed.
    pub fn init(seed: *Seed, now: i64) Keypair {
        const kp: Keypair = .{
            .send_key = seed.send,
            .recv_key = seed.recv,
            .local_index = seed.local_index,
            .remote_index = seed.remote_index,
            .created = now,
            .is_initiator = seed.is_initiator,
        };
        seed.wipe();
        return kp;
    }

    pub fn wipe(self: *Keypair) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    fn expired(self: *const Keypair, now: i64) bool {
        return now - self.created >= c.REJECT_AFTER_TIME;
    }

    /// May this keypair be used to send at `now`?
    pub fn canSend(self: *const Keypair, now: i64) bool {
        return self.sending_valid and !self.expired(now) and self.send_counter < c.REJECT_AFTER_MESSAGES;
    }

    /// Encrypt `plaintext` (empty = keepalive) into `out` with the next
    /// counter. The counter is consumed only on success.
    pub fn encrypt(self: *Keypair, now: i64, plaintext: []const u8, mtu: usize, out: []u8) EncryptError!usize {
        if (!self.canSend(now)) {
            self.sending_valid = false;
            return error.NoKey;
        }
        if (out.len < transport.messageLen(plaintext.len, mtu)) return error.BufferTooSmall;
        const n = transport.seal(&self.send_key, self.remote_index, self.send_counter, plaintext, mtu, out) catch unreachable;
        self.send_counter += 1;
        return n;
    }

    /// Sending-side rekey condition (kernel send.c `keep_key_fresh`,
    /// wireguard-go `keepKeyFreshSending`): after REKEY_AFTER_MESSAGES
    /// messages, or — initiator only — after REKEY_AFTER_TIME.
    pub fn wantsRekeyAfterSend(self: *const Keypair, now: i64) bool {
        return self.sending_valid and (self.send_counter > c.REKEY_AFTER_MESSAGES or
            (self.is_initiator and now - self.created >= c.REKEY_AFTER_TIME));
    }

    /// Authenticate, decrypt and replay-check `packet` addressed to this
    /// keypair. The replay window is only advanced after authentication.
    pub fn decrypt(self: *Keypair, now: i64, packet: []const u8, out: []u8) DecryptError![]u8 {
        const h = try transport.Header.parse(packet);
        if (h.receiver_index != self.local_index) return error.UnknownIndex;
        if (!self.receiving_valid or self.expired(now)) {
            self.receiving_valid = false;
            return error.KeyExpired;
        }
        if (!self.replay.check(h.counter)) return error.Replay;
        const pt = try transport.open(&self.recv_key, packet, out);
        if (!self.replay.update(h.counter)) return error.Replay;
        return pt;
    }
};

/// Local indices of keypairs that were destroyed by an operation.
pub const Retired = struct {
    buf: [3]u32 = undefined,
    len: u8 = 0,

    fn add(self: *Retired, index: u32) void {
        self.buf[self.len] = index;
        self.len += 1;
    }

    pub fn slice(self: *const Retired) []const u32 {
        return self.buf[0..self.len];
    }
};

pub const Slot = enum { current, previous, next };

pub const Sent = struct {
    len: usize,
    /// Rekey condition reached: request a (non-retry) handshake initiation.
    rekey: bool,
};

pub const Received = struct {
    /// Padded plaintext (len 0 = keepalive).
    plaintext: []u8,
    slot: Slot,
    /// This packet confirmed the `next` keypair, which is now `current`
    /// (responder side key confirmation): fire "handshake complete" and
    /// flush queued packets.
    confirmed: bool,
    /// Keypair destroyed by the promotion, if any.
    retired: Retired,
    /// The current keypair is an initiator keypair older than
    /// REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT: the
    /// receive-side "last minute" rekey condition (kernel receive.c
    /// `keep_key_fresh`, wireguard-go `keepKeyFreshReceiving`). The caller
    /// (Peer) gates it with the timers' sent-last-minute flag.
    rekey: bool,
};

pub const Keypairs = struct {
    current: ?Keypair = null,
    previous: ?Keypair = null,
    next: ?Keypair = null,

    fn destroy(slot: *?Keypair, retired: *Retired) void {
        if (slot.*) |*kp| {
            retired.add(kp.local_index);
            kp.wipe();
            slot.* = null;
        }
    }

    /// Move `from` into `to` (which must be empty) and wipe `from`.
    fn move(to: *?Keypair, from: *?Keypair) void {
        std.debug.assert(to.* == null);
        to.* = from.*;
        if (from.*) |*kp| kp.wipe();
        from.* = null;
    }

    /// Install a freshly derived keypair (built from the seed, which is
    /// wiped) following the rotation rules at the top of this file.
    pub fn install(self: *Keypairs, seed: *Seed, now: i64) Retired {
        var retired: Retired = .{};
        const kp = Keypair.init(seed, now);
        if (kp.is_initiator) {
            if (self.next != null) {
                destroy(&self.previous, &retired);
                destroy(&self.current, &retired);
                move(&self.previous, &self.next);
            } else {
                destroy(&self.previous, &retired);
                move(&self.previous, &self.current);
            }
            self.current = kp;
        } else {
            destroy(&self.next, &retired);
            destroy(&self.previous, &retired);
            self.next = kp;
        }
        return retired;
    }

    pub fn get(self: *Keypairs, slot: Slot) ?*Keypair {
        const p = switch (slot) {
            .current => &self.current,
            .previous => &self.previous,
            .next => &self.next,
        };
        return if (p.*) |*kp| kp else null;
    }

    /// Which slot holds the keypair with this local (receiver) index.
    pub fn find(self: *Keypairs, local_index: u32) ?Slot {
        inline for (.{ Slot.current, Slot.next, Slot.previous }) |s| {
            if (self.get(s)) |kp| if (kp.local_index == local_index) return s;
        }
        return null;
    }

    /// Is there a keypair we may send with right now?
    pub fn canSend(self: *const Keypairs, now: i64) bool {
        return if (self.current) |*kp| kp.canSend(now) else false;
    }

    /// Encrypt with the current keypair. `error.NoKey` means: queue the
    /// packet and request a handshake.
    pub fn encrypt(self: *Keypairs, now: i64, plaintext: []const u8, mtu: usize, out: []u8) EncryptError!Sent {
        const kp = self.get(.current) orelse return error.NoKey;
        const n = try kp.encrypt(now, plaintext, mtu, out);
        return .{ .len = n, .rekey = kp.wantsRekeyAfterSend(now) };
    }

    /// Decrypt a transport message addressed to one of our keypairs.
    pub fn decrypt(self: *Keypairs, now: i64, packet: []const u8, out: []u8) DecryptError!Received {
        const h = try transport.Header.parse(packet);
        const slot = self.find(h.receiver_index) orelse return error.UnknownIndex;
        const pt = try self.get(slot).?.decrypt(now, packet, out);
        var r: Received = .{ .plaintext = pt, .slot = slot, .confirmed = false, .retired = .{}, .rekey = false };
        if (slot == .next) {
            destroy(&self.previous, &r.retired);
            move(&self.previous, &self.current);
            move(&self.current, &self.next);
            r.confirmed = true;
        }
        if (self.current) |*cur| {
            r.rekey = cur.sending_valid and cur.is_initiator and
                now - cur.created >= c.REKEY_ON_RECEIVE_AFTER_TIME;
        }
        return r;
    }

    /// Stop sending on current and next (kernel
    /// `wg_noise_expire_current_peer_keypairs`, used e.g. when our private
    /// key changes). They can still receive until they expire.
    pub fn expireSending(self: *Keypairs) void {
        if (self.current) |*kp| kp.sending_valid = false;
        if (self.next) |*kp| kp.sending_valid = false;
    }

    /// Destroy all keypairs (zero-key-material timer, peer removal).
    pub fn clear(self: *Keypairs) Retired {
        var retired: Retired = .{};
        destroy(&self.current, &retired);
        destroy(&self.previous, &retired);
        destroy(&self.next, &retired);
        return retired;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const sec = std.time.ns_per_s;

/// Two seeds that talk to each other (as noise would derive them).
fn pairSeeds(tag: u8, initiator_index: u32, responder_index: u32) [2]Seed {
    var k1: SymKey = undefined;
    var k2: SymKey = undefined;
    @memset(&k1, tag);
    @memset(&k2, tag ^ 0xff);
    return .{
        .{ .send = k1, .recv = k2, .local_index = initiator_index, .remote_index = responder_index, .is_initiator = true },
        .{ .send = k2, .recv = k1, .local_index = responder_index, .remote_index = initiator_index, .is_initiator = false },
    };
}

fn isZero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

test "keypair round trip, counters, replay, wrong index" {
    var seeds = pairSeeds(1, 10, 20);
    var a = Keypair.init(&seeds[0], 0);
    var b = Keypair.init(&seeds[1], 0);
    try testing.expect(isZero(std.mem.asBytes(&seeds[0])));

    var pkt: [128]u8 = undefined;
    var buf: [128]u8 = undefined;
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        const n = try a.encrypt(sec, "ping", 1420, &pkt);
        const h = try transport.Header.parse(pkt[0..n]);
        try testing.expectEqual(i, h.counter);
        try testing.expectEqual(@as(u32, 20), h.receiver_index);
        const pt = try b.decrypt(sec, pkt[0..n], &buf);
        try testing.expectEqualSlices(u8, "ping", pt[0..4]);
        // Same packet again is a replay.
        try testing.expectError(error.Replay, b.decrypt(sec, pkt[0..n], &buf));
    }
    // Packet addressed to someone else.
    const n = try a.encrypt(sec, "x", 1420, &pkt);
    std.mem.writeInt(u32, pkt[4..8], 21, .little);
    try testing.expectError(error.UnknownIndex, b.decrypt(sec, pkt[0..n], &buf));
    // Wrong direction: a cannot decrypt its own packet (different key, index).
    std.mem.writeInt(u32, pkt[4..8], 10, .little);
    try testing.expectError(error.AuthenticationFailed, a.decrypt(sec, pkt[0..n], &buf));
}

test "forged packet does not advance the replay window" {
    var seeds = pairSeeds(2, 1, 2);
    var a = Keypair.init(&seeds[0], 0);
    var b = Keypair.init(&seeds[1], 0);
    var pkt: [64]u8 = undefined;
    var buf: [64]u8 = undefined;
    const n = try a.encrypt(0, "", 0, &pkt);
    // Forge a huge counter: tag fails and window must stay put.
    var forged = pkt;
    std.mem.writeInt(u64, forged[8..16], 1 << 40, .little);
    try testing.expectError(error.AuthenticationFailed, b.decrypt(0, forged[0..n], &buf));
    try testing.expectEqual(@as(u64, 0), b.replay.last);
    _ = try b.decrypt(0, pkt[0..n], &buf);
}

test "out of order and out of window delivery" {
    var seeds = pairSeeds(3, 1, 2);
    var a = Keypair.init(&seeds[0], 0);
    var b = Keypair.init(&seeds[1], 0);
    var pkts: [3][48]u8 = undefined;
    var buf: [48]u8 = undefined;
    _ = try a.encrypt(0, "a", 0, &pkts[0]); // counter 0
    a.send_counter = c.COUNTER_WINDOW_SIZE; // skip ahead (simulates loss)
    _ = try a.encrypt(0, "b", 0, &pkts[1]); // counter W
    a.send_counter = c.COUNTER_WINDOW_SIZE + 1;
    _ = try a.encrypt(0, "c", 0, &pkts[2]); // counter W+1
    _ = try b.decrypt(0, &pkts[2], &buf);
    _ = try b.decrypt(0, &pkts[1], &buf);
    // counter 0 is W+1 behind: out of window.
    try testing.expectError(error.Replay, b.decrypt(0, &pkts[0], &buf));
}

test "expiry by time on both sides" {
    var seeds = pairSeeds(4, 1, 2);
    var a = Keypair.init(&seeds[0], 100);
    var b = Keypair.init(&seeds[1], 100);
    var pkt: [48]u8 = undefined;
    var buf: [48]u8 = undefined;
    const t_last = 100 + c.REJECT_AFTER_TIME - 1;
    const n = try a.encrypt(t_last, "", 0, &pkt);
    _ = try b.decrypt(t_last, pkt[0..n], &buf);
    try testing.expectError(error.NoKey, a.encrypt(t_last + 1, "", 0, &pkt));
    try testing.expect(!a.sending_valid);
    try testing.expectError(error.KeyExpired, b.decrypt(t_last + 1, pkt[0..n], &buf));
}

test "counter exhaustion: REJECT_AFTER_MESSAGES" {
    var seeds = pairSeeds(5, 1, 2);
    var a = Keypair.init(&seeds[0], 0);
    var b = Keypair.init(&seeds[1], 0);
    var pkt: [48]u8 = undefined;
    var buf: [48]u8 = undefined;
    a.send_counter = c.REJECT_AFTER_MESSAGES - 1;
    const n = try a.encrypt(0, "", 0, &pkt);
    try testing.expectEqual(c.REJECT_AFTER_MESSAGES - 1, (try transport.Header.parse(pkt[0..n])).counter);
    _ = try b.decrypt(0, pkt[0..n], &buf);
    try testing.expectError(error.NoKey, a.encrypt(0, "", 0, &pkt));
    // A (forged-index) counter == REJECT_AFTER_MESSAGES is rejected before decryption.
    std.mem.writeInt(u64, pkt[8..16], c.REJECT_AFTER_MESSAGES, .little);
    try testing.expectError(error.Replay, b.decrypt(0, pkt[0..n], &buf));
}

test "rekey-after-send conditions" {
    var seeds = pairSeeds(6, 1, 2);
    var a = Keypair.init(&seeds[0], 0);
    var b = Keypair.init(&seeds[1], 0);
    try testing.expect(!a.wantsRekeyAfterSend(c.REKEY_AFTER_TIME - 1));
    try testing.expect(a.wantsRekeyAfterSend(c.REKEY_AFTER_TIME));
    // Responder never rekeys by time when sending.
    try testing.expect(!b.wantsRekeyAfterSend(c.REJECT_AFTER_TIME - 1));
    b.send_counter = c.REKEY_AFTER_MESSAGES;
    try testing.expect(!b.wantsRekeyAfterSend(0));
    b.send_counter = c.REKEY_AFTER_MESSAGES + 1;
    try testing.expect(b.wantsRekeyAfterSend(0));
}

test "buffer too small does not consume a counter" {
    var seeds = pairSeeds(7, 1, 2);
    var a = Keypair.init(&seeds[0], 0);
    var small: [40]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, a.encrypt(0, "abc", 0, &small));
    try testing.expectEqual(@as(u64, 0), a.send_counter);
}

/// Two peers' Keypairs plus helpers to run handshakes and traffic.
const Pair = struct {
    i: Keypairs = .{}, // the side that initiates handshakes in these tests
    r: Keypairs = .{},
    pkt: [64]u8 = undefined,
    buf: [64]u8 = undefined,

    /// Complete a handshake initiated by `i`. Order as on the wire: the
    /// responder derives (sends its response), then the initiator derives.
    /// Indices: initiator 2·tag, responder 2·tag+1.
    fn handshake(self: *Pair, tag: u8, now: i64) void {
        var seeds = pairSeeds(tag, @as(u32, tag) * 2, @as(u32, tag) * 2 + 1);
        _ = self.r.install(&seeds[1], now);
        _ = self.i.install(&seeds[0], now);
    }

    fn send(from: *Keypairs, to: *Keypairs, pkt: []u8, buf: []u8, now: i64) !Received {
        const s = try from.encrypt(now, "", 0, pkt);
        return to.decrypt(now, pkt[0..s.len], buf);
    }
};

fn idx(kp: ?Keypair) ?u32 {
    return if (kp) |k| k.local_index else null;
}

test "rotation: responder confirms on first packet; initiator rotates at once" {
    var p: Pair = .{};
    p.handshake(1, 0);
    // Initiator: current = new. Responder: next = new, current empty.
    try testing.expectEqual(@as(?u32, 2), idx(p.i.current));
    try testing.expectEqual(@as(?u32, null), idx(p.r.current));
    try testing.expectEqual(@as(?u32, 3), idx(p.r.next));
    // Responder cannot send yet.
    try testing.expectError(error.NoKey, p.r.encrypt(0, "", 0, &p.pkt));
    // Initiator's first packet (the confirming keepalive) promotes next.
    const rx = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 1);
    try testing.expect(rx.confirmed);
    try testing.expectEqual(Slot.next, rx.slot);
    try testing.expectEqual(@as(?u32, 3), idx(p.r.current));
    try testing.expectEqual(@as(?u32, null), idx(p.r.next));
    try testing.expectEqual(@as(usize, 0), rx.retired.len);
    // Second packet: already current, no further confirmation.
    const rx2 = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 2);
    try testing.expect(!rx2.confirmed);
    try testing.expectEqual(Slot.current, rx2.slot);
    // Responder can send back now.
    _ = try Pair.send(&p.r, &p.i, &p.pkt, &p.buf, 3);
}

test "rotation: second handshake, previous keeps receiving in-flight packets" {
    var p: Pair = .{};
    p.handshake(1, 0);
    _ = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 0);
    // Responder sends a packet on the old session that is delayed in flight.
    const old = try p.r.encrypt(0, "", 0, &p.pkt);
    var delayed: [64]u8 = undefined;
    @memcpy(delayed[0..old.len], p.pkt[0..old.len]);

    p.handshake(2, 10);
    // Initiator: previous = session 1, current = session 2.
    try testing.expectEqual(@as(?u32, 4), idx(p.i.current));
    try testing.expectEqual(@as(?u32, 2), idx(p.i.previous));
    // Responder: current = session 1 still, next = session 2, previous empty.
    try testing.expectEqual(@as(?u32, 3), idx(p.r.current));
    try testing.expectEqual(@as(?u32, 5), idx(p.r.next));
    try testing.expectEqual(@as(?u32, null), idx(p.r.previous));
    // The delayed packet still decrypts at the initiator via `previous`.
    const rx = try p.i.decrypt(11, delayed[0..old.len], &p.buf);
    try testing.expectEqual(Slot.previous, rx.slot);
    try testing.expect(!rx.confirmed);
    // Responder still sends on session 1 until confirmation.
    const s = try p.r.encrypt(11, "", 0, &p.pkt);
    try testing.expectEqual(@as(u32, 2), (try transport.Header.parse(p.pkt[0..s.len])).receiver_index);
    // Confirmation.
    const rx2 = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 12);
    try testing.expect(rx2.confirmed);
    try testing.expectEqual(@as(?u32, 5), idx(p.r.current));
    try testing.expectEqual(@as(?u32, 3), idx(p.r.previous));
    try testing.expectEqual(@as(?u32, null), idx(p.r.next));

    // Third handshake: session 1 is destroyed on both sides.
    p.handshake(3, 20);
    try testing.expectEqual(@as(?u32, 6), idx(p.i.current));
    try testing.expectEqual(@as(?u32, 4), idx(p.i.previous));
    // Responder: install as responder destroys previous (session 1, index 3).
    try testing.expectEqual(@as(?u32, null), idx(p.r.previous));
    try testing.expectEqual(@as(?u32, 7), idx(p.r.next));
    // A packet for the destroyed session is now unknown.
    try testing.expectError(error.UnknownIndex, p.i.decrypt(21, delayed[0..old.len], &p.buf));
}

test "rotation: install reports retired indices and wipes them" {
    var ks: Keypairs = .{};
    var s1 = pairSeeds(1, 100, 0)[0];
    try testing.expectEqual(@as(usize, 0), ks.install(&s1, 0).len);
    var s2 = pairSeeds(2, 101, 0)[0];
    try testing.expectEqual(@as(usize, 0), ks.install(&s2, 0).len); // 100 → previous
    var s3 = pairSeeds(3, 102, 0)[0];
    const r3 = ks.install(&s3, 0); // 100 destroyed, 101 → previous
    try testing.expectEqualSlices(u32, &.{100}, r3.slice());
    // Now a responder install: destroys previous (101), next ← 103.
    var s4 = pairSeeds(4, 0, 103)[1];
    const r4 = ks.install(&s4, 0);
    try testing.expectEqualSlices(u32, &.{101}, r4.slice());
    try testing.expectEqual(@as(?u32, 102), idx(ks.current));
    try testing.expectEqual(@as(?u32, 103), idx(ks.next));
    // Another responder install replaces the unconfirmed next.
    var s5 = pairSeeds(5, 0, 104)[1];
    try testing.expectEqualSlices(u32, &.{103}, ks.install(&s5, 0).slice());
    // Initiator install while a next exists (simultaneous handshakes):
    // previous ← next, current and previous destroyed.
    var s6 = pairSeeds(6, 105, 0)[0];
    const r6 = ks.install(&s6, 0);
    try testing.expectEqualSlices(u32, &.{102}, r6.slice());
    try testing.expectEqual(@as(?u32, 105), idx(ks.current));
    try testing.expectEqual(@as(?u32, 104), idx(ks.previous));
    try testing.expectEqual(@as(?u32, null), idx(ks.next));
    // Clear destroys everything; storage is zero.
    const rc = ks.clear();
    try testing.expectEqual(@as(usize, 2), rc.len);
    try testing.expect(ks.current == null and ks.previous == null and ks.next == null);
}

test "wipe zeroes key material" {
    var s = pairSeeds(9, 1, 2)[0];
    var kp = Keypair.init(&s, 0);
    try testing.expect(!isZero(&kp.send_key));
    kp.wipe();
    try testing.expect(isZero(std.mem.asBytes(&kp)));
}

test "receive-side last-minute rekey hint (initiator only)" {
    var p: Pair = .{};
    p.handshake(1, 0);
    _ = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 0);
    const t = c.REKEY_ON_RECEIVE_AFTER_TIME;
    try testing.expect(!(try Pair.send(&p.r, &p.i, &p.pkt, &p.buf, t - 1)).rekey);
    try testing.expect((try Pair.send(&p.r, &p.i, &p.pkt, &p.buf, t)).rekey);
    // The responder side never gets the hint.
    try testing.expect(!(try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, t)).rekey);
}

test "expireSending stops sending but not receiving" {
    var p: Pair = .{};
    p.handshake(1, 0);
    _ = try Pair.send(&p.i, &p.r, &p.pkt, &p.buf, 0);
    p.i.expireSending();
    try testing.expectError(error.NoKey, p.i.encrypt(0, "", 0, &p.pkt));
    try testing.expect(!p.i.canSend(0));
    _ = try Pair.send(&p.r, &p.i, &p.pkt, &p.buf, 0);
}
