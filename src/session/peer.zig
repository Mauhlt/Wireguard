//! Per-peer session state: keypairs + timers, wired together exactly as
//! the kernel / wireguard-go data and handshake paths fire their hooks, so
//! the device only has to move bytes and act on the returned flags.
//!
//! Device obligations (what the flags mean):
//! * `error.NoKey` from `encrypt`: queue the packet (bounded), then
//!   `if (peer.wantHandshake(now))` create + send an initiation and call
//!   `initiationSent(now)`.
//! * `initiate_handshake` in any result: same (already rate-limited, so the
//!   device sends without calling `wantHandshake`).
//! * `confirmed` in a receive result, or after `initiatorSession`: flush
//!   queued packets; after `initiatorSession` with an empty queue send a
//!   keepalive (kernel `wg_packet_send_keepalive` after a response).
//! * `retired` indices: remove from the receiver-index table.
//! * `Due.actions` — see `timers.Actions`; `zero_keys` has already wiped the
//!   keypairs here (the device also clears the noise handshake state).
//!
//! Timer hooks fire when a packet is encrypted for sending, i.e. the device
//! sends what it encrypts (wireguard-go also fires them regardless of the
//! UDP send result).

const std = @import("std");
const c = @import("constants.zig");
const kp = @import("keypair.zig");
const tm = @import("timers.zig");

pub const Keypairs = kp.Keypairs;
pub const Seed = kp.Seed;
pub const Retired = kp.Retired;
pub const Timers = tm.Timers;
pub const Jitter = tm.Jitter;
pub const Actions = tm.Actions;

pub const Peer = struct {
    keypairs: Keypairs = .{},
    timers: Timers,

    pub fn init(jitter: Jitter) Peer {
        return .{ .timers = Timers.init(jitter) };
    }

    /// Wipe all key material (peer removed).
    pub fn deinit(self: *Peer) Retired {
        self.timers.stop();
        return self.keypairs.clear();
    }

    pub fn start(self: *Peer) Actions {
        return self.timers.start();
    }

    pub fn setPersistentKeepalive(self: *Peer, seconds: u16) Actions {
        return self.timers.setPersistentKeepalive(seconds);
    }

    pub const Sent = struct {
        len: usize,
        initiate_handshake: bool,
    };

    /// Encrypt one outgoing packet (empty = keepalive) with the current
    /// keypair into `out`. See `transport.seal` for buffer rules.
    pub fn encrypt(self: *Peer, now: i64, plaintext: []const u8, mtu: usize, out: []u8) kp.EncryptError!Sent {
        const r = try self.keypairs.encrypt(now, plaintext, mtu, out);
        self.timers.packetSent(if (plaintext.len == 0) .keepalive else .data, now);
        return .{
            .len = r.len,
            .initiate_handshake = r.rekey and self.timers.requestHandshake(now, false),
        };
    }

    /// No usable key (after `error.NoKey`): may we start a handshake now?
    pub fn wantHandshake(self: *Peer, now: i64) bool {
        return self.timers.requestHandshake(now, false);
    }

    pub const Received = struct {
        /// Padded plaintext; empty = keepalive.
        plaintext: []u8,
        confirmed: bool,
        initiate_handshake: bool,
        retired: Retired,
    };

    /// Decrypt one incoming transport message whose receiver index the
    /// device mapped to this peer. Errors fire no timers (unauthenticated).
    pub fn decrypt(self: *Peer, now: i64, packet: []const u8, out: []u8) kp.DecryptError!Received {
        const r = try self.keypairs.decrypt(now, packet, out);
        if (r.confirmed) self.timers.on(.handshake_complete, now);
        var initiate = false;
        if (r.rekey and !self.timers.sent_lastminute_handshake) {
            self.timers.sent_lastminute_handshake = true;
            initiate = self.timers.requestHandshake(now, false);
        }
        self.timers.packetReceived(if (r.plaintext.len == 0) .keepalive else .data, now);
        return .{
            .plaintext = r.plaintext,
            .confirmed = r.confirmed,
            .initiate_handshake = initiate,
            .retired = r.retired,
        };
    }

    /// We sent a handshake initiation.
    pub fn initiationSent(self: *Peer, now: i64) void {
        self.timers.packetSent(.handshake_initiation, now);
    }

    /// We consumed a valid handshake initiation and are about to send the
    /// response: install the new keypair as `next` (seed is wiped).
    pub fn responderSession(self: *Peer, seed: *Seed, now: i64) Retired {
        std.debug.assert(!seed.is_initiator);
        self.timers.packetReceived(.handshake_initiation, now);
        const retired = self.keypairs.install(seed, now);
        self.timers.on(.session_derived, now);
        self.timers.packetSent(.handshake_response, now);
        return retired;
    }

    /// We consumed a valid handshake response: install the new keypair as
    /// `current` (seed is wiped). The device then flushes queued packets or
    /// sends a keepalive to confirm the session to the responder.
    pub fn initiatorSession(self: *Peer, seed: *Seed, now: i64) Retired {
        std.debug.assert(seed.is_initiator);
        self.timers.packetReceived(.handshake_response, now);
        const retired = self.keypairs.install(seed, now);
        self.timers.on(.session_derived, now);
        self.timers.on(.handshake_complete, now);
        return retired;
    }

    pub fn next(self: *const Peer, now: i64) ?i64 {
        return self.timers.next(now);
    }

    pub const Due = struct {
        actions: Actions,
        retired: Retired = .{},
    };

    pub fn due(self: *Peer, now: i64) Due {
        var d: Due = .{ .actions = self.timers.due(now) };
        if (d.actions.zero_keys) d.retired = self.keypairs.clear();
        return d;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const s = std.time.ns_per_s;
const transport = @import("transport.zig");

/// Two peers on a lossless in-memory link, `a` initiates handshakes unless
/// a test says otherwise. Plays the device's role.
const Net = struct {
    a: Peer = Peer.init(Jitter.none),
    b: Peer = Peer.init(Jitter.none),
    pkt: [256]u8 = undefined,
    buf: [256]u8 = undefined,
    next_index: u32 = 1,

    fn up(self: *Net) void {
        _ = self.a.start();
        _ = self.b.start();
    }

    fn handshake(self: *Net, from_a: bool, now: i64) void {
        const ini = if (from_a) &self.a else &self.b;
        const res = if (from_a) &self.b else &self.a;
        ini.initiationSent(now);
        var k1: [32]u8 = @splat(@truncate(self.next_index));
        var k2: [32]u8 = @splat(@truncate(self.next_index +% 0x80));
        var si: Seed = .{ .send = k1, .recv = k2, .local_index = self.next_index, .remote_index = self.next_index + 1, .is_initiator = true };
        var sr: Seed = .{ .send = k2, .recv = k1, .local_index = self.next_index + 1, .remote_index = self.next_index, .is_initiator = false };
        std.crypto.secureZero(u8, &k1);
        std.crypto.secureZero(u8, &k2);
        self.next_index += 2;
        _ = res.responderSession(&sr, now);
        _ = ini.initiatorSession(&si, now);
    }

    fn send(self: *Net, from_a: bool, data: []const u8, now: i64) !struct { tx: Peer.Sent, rx: Peer.Received } {
        const from = if (from_a) &self.a else &self.b;
        const to = if (from_a) &self.b else &self.a;
        const tx = try from.encrypt(now, data, 1420, &self.pkt);
        const rx = try to.decrypt(now, self.pkt[0..tx.len], &self.buf);
        return .{ .tx = tx, .rx = rx };
    }
};

test "first contact: no key -> handshake -> confirmation keepalive -> both directions" {
    var n: Net = .{};
    n.up();
    try testing.expectError(error.NoKey, n.a.encrypt(0, "hi", 1420, &n.pkt));
    try testing.expect(n.a.wantHandshake(0));
    n.handshake(true, 0);
    // a's retransmit timer was disarmed by handshake complete.
    try testing.expectEqual(@as(?i64, null), n.a.timers.retransmit_handshake);
    // b (responder) cannot send before confirmation.
    try testing.expectError(error.NoKey, n.b.encrypt(0, "x", 1420, &n.pkt));
    try testing.expectEqual(@as(?i64, null), n.b.timers.last_handshake);
    // a confirms with a keepalive.
    const r = try n.send(true, "", 1 * s);
    try testing.expect(r.rx.confirmed);
    try testing.expectEqual(@as(usize, 0), r.rx.plaintext.len);
    try testing.expectEqual(@as(?i64, 1 * s), n.b.timers.last_handshake);
    const r2 = try n.send(false, "hello", 2 * s);
    try testing.expectEqualSlices(u8, "hello", r2.rx.plaintext[0..5]);
    try testing.expectEqual(@as(usize, 16), r2.rx.plaintext.len);
    // b received data and has not replied: passive keepalive 10 s later? No —
    // a received data from b: a owes a keepalive.
    try testing.expectEqual(@as(?i64, 12 * s), n.a.timers.send_keepalive);
}

test "initiator rekeys after REKEY_AFTER_TIME when sending; responder does not" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    _ = try n.send(true, "", 0);
    const t1 = c.REKEY_AFTER_TIME - 1;
    try testing.expect(!(try n.send(true, "d", t1)).tx.initiate_handshake);
    try testing.expect(!(try n.send(false, "d", t1)).tx.initiate_handshake);
    const t2 = c.REKEY_AFTER_TIME;
    try testing.expect(!(try n.send(false, "d", t2)).tx.initiate_handshake);
    try testing.expect((try n.send(true, "d", t2)).tx.initiate_handshake);
    n.a.initiationSent(t2);
    // Rate limit: the next packet does not ask again within REKEY_TIMEOUT.
    try testing.expect(!(try n.send(true, "d", t2 + 1)).tx.initiate_handshake);
}

test "receive-side last-minute rekey, once per handshake" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    _ = try n.send(true, "", 0);
    const t = c.REKEY_ON_RECEIVE_AFTER_TIME;
    try testing.expect(!(try n.send(false, "d", t - 1)).rx.initiate_handshake);
    try testing.expect((try n.send(false, "d", t)).rx.initiate_handshake);
    try testing.expect(n.a.timers.sent_lastminute_handshake);
    // Not again, even after the rate limit has passed.
    try testing.expect(!(try n.send(false, "d", t + 6 * s)).rx.initiate_handshake);
    // The new handshake resets the flag.
    n.handshake(true, t + 7 * s);
    try testing.expect(!n.a.timers.sent_lastminute_handshake);
}

test "keys expire at REJECT_AFTER_TIME on both sides" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    _ = try n.send(true, "", 0);
    _ = try n.send(false, "", c.REJECT_AFTER_TIME - 1);
    try testing.expectError(error.NoKey, n.a.encrypt(c.REJECT_AFTER_TIME, "x", 1420, &n.pkt));
    try testing.expectError(error.NoKey, n.b.encrypt(c.REJECT_AFTER_TIME, "x", 1420, &n.pkt));
}

test "zero key material after 3 x REJECT_AFTER_TIME of no new session" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    _ = try n.send(true, "", 0);
    try testing.expectEqual(@as(?i64, c.ZERO_KEY_MATERIAL_AFTER), n.a.next(0));
    const d = n.a.due(c.ZERO_KEY_MATERIAL_AFTER);
    try testing.expect(d.actions.zero_keys);
    try testing.expectEqualSlices(u32, &.{1}, d.retired.slice());
    try testing.expect(n.a.keypairs.current == null);
    try testing.expectEqual(@as(?i64, null), n.a.next(c.ZERO_KEY_MATERIAL_AFTER));
}

test "rekey cycle keeps traffic flowing; old session decrypts in-flight packets" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    _ = try n.send(true, "", 0);
    // b has an old-session packet in flight while a rekeys.
    const old = try n.b.encrypt(130 * s, "late", 1420, &n.pkt);
    var inflight: [256]u8 = undefined;
    @memcpy(inflight[0..old.len], n.pkt[0..old.len]);
    n.handshake(true, 130 * s);
    const rx = try n.a.decrypt(131 * s, inflight[0..old.len], &n.buf);
    try testing.expectEqualSlices(u8, "late", rx.plaintext[0..4]);
    // b confirms the new session on a's next packet, retiring nothing (its
    // previous was dropped when the response was sent).
    const r = try n.send(true, "new", 131 * s);
    try testing.expect(r.rx.confirmed);
    try testing.expectEqual(@as(usize, 0), r.rx.retired.len);
    // Traffic after the first session expired still flows on the second.
    _ = try n.send(false, "ok", 200 * s);
    _ = try n.send(true, "ok", 200 * s);
}

test "persistent keepalive on start and after traffic" {
    var p = Peer.init(Jitter.none);
    _ = p.setPersistentKeepalive(25);
    try testing.expect(p.start().send_keepalive);
    // No key yet: the keepalive needs a handshake first.
    var out: [64]u8 = undefined;
    try testing.expectError(error.NoKey, p.encrypt(0, "", 0, &out));
    try testing.expect(p.wantHandshake(0));
    p.initiationSent(0);
    // Initiation counted as traffic: persistent keepalive 25 s later,
    // retransmission 5 s later.
    try testing.expectEqual(@as(?i64, 5 * s), p.next(0));
    try testing.expectEqual(@as(?i64, 25 * s), p.timers.persistent_keepalive);
}

test "deinit wipes everything" {
    var n: Net = .{};
    n.up();
    n.handshake(true, 0);
    n.handshake(true, 1);
    const r = n.a.deinit();
    try testing.expectEqual(@as(usize, 2), r.len);
    try testing.expectEqual(@as(?i64, null), n.a.next(0));
    _ = transport;
}
