//! Handshake known-answer, negative and fuzz tests.
//!
//! Golden vectors come from testdata/noise_ref.py: an independent Python
//! implementation written from the wireguard.com/protocol pseudocode (stdlib
//! hashlib/hmac for BLAKE2s, plus textbook X25519 / ChaCha20-Poly1305 /
//! XChaCha20 self-tested against their RFC vectors). Static keys are
//! `wg genkey` output (see crypto.zig); everything else is fixed bytes.
const std = @import("std");
const testing = std.testing;
const crypto = @import("../crypto.zig");
const noise = @import("root.zig");
const hexTo = crypto.hexTo;

const ns_per_s = std.time.ns_per_s;

/// A `std.Random` that hands out the given bytes in order (test only).
const FixedRandom = struct {
    data: []const u8,
    pos: usize = 0,

    fn fill(self: *FixedRandom, buf: []u8) void {
        @memcpy(buf, self.data[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }
    fn random(self: *FixedRandom) std.Random {
        return std.Random.init(self, fill);
    }
    fn done(self: *const FixedRandom) bool {
        return self.pos == self.data.len;
    }
};

const s_i_priv = "CN3URi7MiszI1nhIbL8L7T6sGLUDBmGEDw2g2WNXW3Q=";
const s_r_priv = "kGiTcwU7NANVTOLotHQsBwXaMqfDP+CHO0Tj0lOp1EE=";
const e_i: [32]u8 = @splat(0x11);
const e_r: [32]u8 = @splat(0x22);
const e_i2: [32]u8 = @splat(0x55);
const psk: [32]u8 = blk: {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i);
    break :blk k;
};
const i_idx: u32 = 0x12345678;
const r_idx: u32 = 0x9abcdef0;
const wall: i96 = 1_700_000_000_123_456_789;
const cookie_secret: [32]u8 = @splat(0x33);
const cookie_nonce: [24]u8 = @splat(0x44);
const src = [_]u8{ 192, 0, 2, 1, 0xca, 0x6c }; // 192.0.2.1:51820, BE port

const golden_psk = struct {
    const initiation = hexTo(148, "01000000785634127b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13e040f4e9ca34c4e43917d52acd7a5f311d44efb6b40cd71e89af873e01e2e9d84f91155a1e52add9285c5a7adc880f308b59ae75431efcfcc7a3e845722f36ac9ac29032b91546c1c851efbe366dc684f4453b79a29d0e405398ee6300000000000000000000000000000000");
    const response = hexTo(92, "02000000f0debc9a785634120faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f2093899d277601d5c7d45d87bc1726738340b95c6bb4b7c60712dde015e27a629100000000000000000000000000000000");
    const i_send = hexTo(32, "9fc15e39890ad35f042d6f10f05cd83f637057ebcff913200656f8a4b63eab1e");
    const i_recv = hexTo(32, "1df94da119bba9a874d5b3ec9375f69b9b1e0d1e7ba852211810a124fd56e4a5");
};
const golden_nopsk = struct {
    const initiation = golden_psk.initiation; // the psk only enters at message 2
    const response = hexTo(92, "02000000f0debc9a785634120faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f209e8b50b9e74fd10e1faedbc30dacd7fe2c3e1a62003fe6b5780e2e0e7b2c741900000000000000000000000000000000");
    const i_send = hexTo(32, "c0c1231352a7954732536f8fffa67529b8894087f2d8005bb0291b0175a74380");
    const i_recv = hexTo(32, "ab78143b8bff4b5805e3f70df1646c5b74a4b717996907d82ee911ebdd0ef7bc");
};
const golden_cookie = struct {
    const reply = hexTo(64, "030000007856341244444444444444444444444444444444444444444444444472d5e49600c704b74ab616020d0d58c28bccc7582a8b8ed7853215b36a85c2a8");
    const cookie = hexTo(16, "254b56e7a7b4dcf1db68602c8467fb01");
    const initiation2 = hexTo(148, "010000007856341238ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67c697de9da3d506dc964c3b6ce02ce1b50eaa7332d860fd8718301ac96a6038c868317e922adcf94d8afbbaeda727cb9690aec2c387b069f4fcc0772bc525ed04377ef9e0fdbb0d4afe6dead0343067890255e124949f808be637b5264e6bf37d4f4c9531442e80300bc615c3");
};

/// Two configured peers: I (initiator) and R (responder).
const Pair = struct {
    li: noise.Local,
    lr: noise.Local,
    hi: noise.Handshake, // I's state for peer R
    hr: noise.Handshake, // R's state for peer I
    ci: noise.CookieChecker,
    cr: noise.CookieChecker,

    fn init(p: [32]u8) !Pair {
        const li = noise.Local.init(try crypto.keyFromBase64(s_i_priv));
        const lr = noise.Local.init(try crypto.keyFromBase64(s_r_priv));
        return .{
            .li = li,
            .lr = lr,
            .hi = noise.Handshake.init(&li, lr.public, p),
            .hr = noise.Handshake.init(&lr, li.public, p),
            .ci = noise.CookieChecker.init(&li.public),
            .cr = noise.CookieChecker.init(&lr.public),
        };
    }

    fn initiate(self: *Pair, eph: [32]u8, wall_ns: i96, now: i64) !noise.Initiation {
        var r: FixedRandom = .{ .data = &eph };
        return self.hi.createInitiation(&self.li, wall_ns, now, i_idx, r.random());
    }

    /// Responder side of message 1, without the cookie check.
    fn receive(self: *Pair, msg: *const noise.Initiation, now: i64) !void {
        var start = try noise.consumeInitiationStatic(&self.lr, msg);
        try testing.expectEqual(self.li.public, start.remote_static);
        try self.hr.consumeInitiation(&start, now);
    }

    fn respond(self: *Pair, now: i64) !noise.Response {
        var r: FixedRandom = .{ .data = &e_r };
        return self.hr.createResponse(now, r_idx, r.random());
    }
};

var no_rng_state: FixedRandom = .{ .data = "" };
fn noRng() std.Random {
    return no_rng_state.random();
}

test "initial chaining key and hash constants" {
    const ck = crypto.hash(&.{noise.construction});
    try testing.expectEqual(ck, @import("handshake.zig").initial_chaining_key);
    try testing.expectEqual(crypto.hash(&.{ &ck, noise.identifier }), @import("handshake.zig").initial_hash);
}

fn goldenRoundTrip(p: [32]u8, comptime G: type) !void {
    var pair = try Pair.init(p);
    const now: i64 = 1000 * ns_per_s;

    const m1 = try pair.initiate(e_i, wall, now);
    try testing.expectEqualSlices(u8, &G.initiation, m1.asBytes());
    try testing.expectEqual(noise.State.created_initiation, pair.hi.state);

    // Responder: shape, mac1, static, peer.
    const in1 = try noise.Initiation.parse(m1.asBytes());
    try testing.expectEqual(noise.MessageType.initiation, noise.messageType(m1.asBytes()).?);
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m1.asBytes(), &src, now, false, noRng()));
    try pair.receive(in1, now);
    try testing.expectEqual(noise.State.consumed_initiation, pair.hr.state);
    try testing.expectEqual(i_idx, pair.hr.remote_index);

    const m2 = try pair.respond(now);
    try testing.expectEqualSlices(u8, &G.response, m2.asBytes());
    var kr = try pair.hr.deriveKeys();
    try testing.expectEqual(noise.State.zeroed, pair.hr.state);
    try testing.expect(crypto.isZero(32, &pair.hr.chaining_key));
    try testing.expect(crypto.isZero(32, &pair.hr.ephemeral_private));

    const in2 = try noise.Response.parse(m2.asBytes());
    try testing.expectEqual(noise.Verdict.ok, pair.ci.check(m2.asBytes(), &src, now, false, noRng()));
    try pair.hi.consumeResponse(&pair.li, in2);
    var ki = try pair.hi.deriveKeys();
    try testing.expect(crypto.isZero(32, &pair.hi.ephemeral_private));

    try testing.expectEqual(G.i_send, ki.send);
    try testing.expectEqual(G.i_recv, ki.recv);
    try testing.expectEqual(ki.send, kr.recv);
    try testing.expectEqual(ki.recv, kr.send);
    try testing.expect(ki.is_initiator and !kr.is_initiator);
    try testing.expectEqual(i_idx, ki.local_index);
    try testing.expectEqual(r_idx, ki.remote_index);
    try testing.expectEqual(r_idx, kr.local_index);
    try testing.expectEqual(i_idx, kr.remote_index);
    ki.wipe();
    kr.wipe();
    try testing.expect(crypto.isZero(32, &ki.send));
}

test "golden round trip with preshared key (Python reference)" {
    try goldenRoundTrip(psk, golden_psk);
}

test "golden round trip without preshared key (Python reference)" {
    try goldenRoundTrip(@splat(0), golden_nopsk);
}

test "golden cookie reply and mac2 under load (Python reference)" {
    var pair = try Pair.init(psk);
    const t0: i64 = 1000 * ns_per_s;
    const m1 = try pair.initiate(e_i, wall, t0);

    // Under load, no cookie yet: the responder asks for one. The secret is
    // generated lazily here (32 bytes from rng).
    var secret_rng: FixedRandom = .{ .data = &cookie_secret };
    try testing.expectEqual(noise.Verdict.need_cookie, pair.cr.check(m1.asBytes(), &src, t0, true, secret_rng.random()));
    try testing.expect(secret_rng.done());
    var nonce_rng: FixedRandom = .{ .data = &cookie_nonce };
    const reply = pair.cr.createReply(m1.asBytes(), &src, t0, nonce_rng.random());
    try testing.expect(nonce_rng.done());
    try testing.expectEqualSlices(u8, &golden_cookie.reply, reply.asBytes());

    // Initiator stores the cookie and retries 1 s later with mac2.
    const parsed = try noise.CookieReply.parse(reply.asBytes());
    try testing.expectEqual(i_idx, parsed.receiverIndex());
    try pair.hi.cookie.consumeReply(parsed, t0 + ns_per_s);
    try testing.expectEqual(golden_cookie.cookie, pair.hi.cookie.cookie);
    // One reply per sent message.
    try testing.expectError(error.NoMac1Sent, pair.hi.cookie.consumeReply(parsed, t0 + ns_per_s));

    const m1b = try pair.initiate(e_i2, wall + ns_per_s, t0 + ns_per_s);
    try testing.expectEqualSlices(u8, &golden_cookie.initiation2, m1b.asBytes());
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m1b.asBytes(), &src, t0 + ns_per_s, true, noRng()));
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m1b.asBytes(), &src, t0 + ns_per_s, false, noRng()));
    // mac2 is bound to the source address.
    const other_src = [_]u8{ 192, 0, 2, 2, 0xca, 0x6c };
    try testing.expectEqual(noise.Verdict.need_cookie, pair.cr.check(m1b.asBytes(), &other_src, t0 + ns_per_s, true, noRng()));
    // And the whole exchange still completes.
    try pair.receive(try noise.Initiation.parse(m1b.asBytes()), t0 + ns_per_s);
}

test "mac1: any modification invalidates; wrong responder key invalidates" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    var buf = m1.asBytes().*;
    for ([_]usize{ 0, 4, 8, 40, 100, 115, 116, 131 }) |i| {
        buf = m1.asBytes().*;
        buf[i] ^= 0x01;
        try testing.expectEqual(noise.Verdict.invalid, pair.cr.check(&buf, &src, 0, false, noRng()));
    }
    // mac2 is not covered by mac1.
    buf = m1.asBytes().*;
    buf[140] ^= 1;
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(&buf, &src, 0, false, noRng()));
    // The initiator's checker (other static key) rejects it.
    try testing.expectEqual(noise.Verdict.invalid, pair.ci.check(m1.asBytes(), &src, 0, false, noRng()));
    // Wrong length.
    try testing.expectEqual(noise.Verdict.invalid, pair.cr.check(m1.asBytes()[0..147], &src, 0, false, noRng()));
}

test "mac2 under load: missing, corrupted, expired cookie" {
    var pair = try Pair.init(psk);
    const t0: i64 = 50 * ns_per_s;
    var rng_state = std.Random.DefaultPrng.init(1);
    const rng = rng_state.random();

    const m1 = try pair.initiate(e_i, wall, t0);
    try testing.expectEqual(noise.Verdict.need_cookie, pair.cr.check(m1.asBytes(), &src, t0, true, rng));
    const reply = pair.cr.createReply(m1.asBytes(), &src, t0, rng);

    // A reply tampered with is rejected and does not consume the mac1.
    var bad = reply;
    bad.encrypted_cookie[3] ^= 1;
    try testing.expectError(error.AuthenticationFailed, pair.hi.cookie.consumeReply(&bad, t0));
    try pair.hi.cookie.consumeReply(&reply, t0);

    var m = try pair.initiate(e_i2, wall + ns_per_s, t0);
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m.asBytes(), &src, t0, true, rng));
    m.mac2[0] ^= 1;
    try testing.expectEqual(noise.Verdict.need_cookie, pair.cr.check(m.asBytes(), &src, t0, true, rng));
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m.asBytes(), &src, t0, false, rng));

    // Initiator stops using the cookie after 120 - 5 s.
    m = try pair.initiate(e_i2, wall + 2 * ns_per_s, t0 + 115 * ns_per_s - 1);
    try testing.expect(!crypto.isZero(16, &m.mac2));
    m = try pair.initiate(e_i2, wall + 3 * ns_per_s, t0 + 115 * ns_per_s);
    try testing.expect(crypto.isZero(16, &m.mac2));

    // Responder secret rotates after 120 s: a cookie from before is refused.
    try pair.hi.cookie.consumeReply(&pair.cr.createReply(m.asBytes(), &src, t0 + 115 * ns_per_s, rng), t0 + 119 * ns_per_s);
    m = try pair.initiate(e_i2, wall + 4 * ns_per_s, t0 + 119 * ns_per_s);
    try testing.expectEqual(noise.Verdict.ok, pair.cr.check(m.asBytes(), &src, t0 + 119 * ns_per_s, true, rng));
    try testing.expectEqual(noise.Verdict.need_cookie, pair.cr.check(m.asBytes(), &src, t0 + 120 * ns_per_s, true, rng));
}

test "cookie reply for a response is addressed to the responder's index" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    try pair.receive(&m1, 0);
    const m2 = try pair.respond(0);
    var rng_state = std.Random.DefaultPrng.init(2);
    try testing.expectEqual(noise.Verdict.need_cookie, pair.ci.check(m2.asBytes(), &src, 0, true, rng_state.random()));
    const reply = pair.ci.createReply(m2.asBytes(), &src, 0, rng_state.random());
    try testing.expectEqual(r_idx, reply.receiverIndex());
    try pair.hr.cookie.consumeReply(&reply, 0);
}

test "replayed initiation is rejected; state survives" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    try pair.receive(&m1, 0);
    const hash_before = pair.hr.hash;
    // Same message again, long after the flood window.
    try testing.expectError(error.ReplayedTimestamp, pair.receive(&m1, 10 * ns_per_s));
    try testing.expectEqual(noise.State.consumed_initiation, pair.hr.state);
    try testing.expectEqual(hash_before, pair.hr.hash);
    // An older timestamp.
    const old = try pair.initiate(e_i2, wall - ns_per_s, 0);
    try testing.expectError(error.ReplayedTimestamp, pair.receive(&old, 20 * ns_per_s));
    // Same whitened timestamp (within 2^24 ns) counts as a replay too.
    const same = try pair.initiate(e_i2, wall + 1000, 0);
    try testing.expectError(error.ReplayedTimestamp, pair.receive(&same, 30 * ns_per_s));
    // A newer one is fine.
    const newer = try pair.initiate(e_i2, wall + ns_per_s, 0);
    try pair.receive(&newer, 40 * ns_per_s);
}

test "initiation flood: at most one per 20 ms per peer" {
    var pair = try Pair.init(psk);
    const t0: i64 = 7 * ns_per_s;
    try pair.receive(&(try pair.initiate(e_i, wall, 0)), t0);
    const next = try pair.initiate(e_i2, wall + ns_per_s, 0);
    try testing.expectError(error.InitiationFlood, pair.receive(&next, t0 + noise.min_initiation_interval_ns - 1));
    // The rejected attempt did not advance the replay timestamp, so the same
    // message is accepted once the window has passed.
    try pair.receive(&next, t0 + noise.min_initiation_interval_ns);
}

test "wrong static: initiation for another responder, or from another peer" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    // A third party's identity cannot open the static.
    var other = noise.Local.init(try crypto.keyFromBase64("mOgFQxhFVe3FMZ37X5wAB5jBzHz9ckVAynAjYHXU5kw="));
    try testing.expectError(error.AuthenticationFailed, noise.consumeInitiationStatic(&other, &m1));
    // Responder found the static but hands it to the wrong peer's handshake.
    var start = try noise.consumeInitiationStatic(&pair.lr, &m1);
    var wrong_peer = noise.Handshake.init(&pair.lr, other.public, psk);
    try testing.expectError(error.PeerMismatch, wrong_peer.consumeInitiation(&start, 0));
    try testing.expect(crypto.isZero(32, &start.chaining_key)); // wiped
    // Corrupted encrypted static / timestamp.
    var bad = m1;
    bad.encrypted_static[5] ^= 1;
    try testing.expectError(error.AuthenticationFailed, noise.consumeInitiationStatic(&pair.lr, &bad));
    bad = m1;
    bad.encrypted_timestamp[0] ^= 1;
    start = try noise.consumeInitiationStatic(&pair.lr, &bad);
    try testing.expectError(error.AuthenticationFailed, pair.hr.consumeInitiation(&start, 0));
    try testing.expectEqual(noise.State.zeroed, pair.hr.state);
}

test "response: wrong state, wrong index, tampered, psk mismatch" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    try pair.receive(&m1, 0);
    const m2 = try pair.respond(0);

    // Responder cannot consume a response; createResponse twice is refused.
    try testing.expectError(error.InvalidState, pair.hr.consumeResponse(&pair.lr, &m2));
    try testing.expectError(error.InvalidState, pair.respond(0));

    var bad = m2;
    noiseWriteIndex(&bad.receiver, i_idx + 1);
    try testing.expectError(error.IndexMismatch, pair.hi.consumeResponse(&pair.li, &bad));
    bad = m2;
    bad.encrypted_nothing[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, pair.hi.consumeResponse(&pair.li, &bad));
    bad = m2;
    bad.ephemeral[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, pair.hi.consumeResponse(&pair.li, &bad));
    try testing.expectEqual(noise.State.created_initiation, pair.hi.state);
    try testing.expectError(error.InvalidState, pair.hi.deriveKeys());

    // The genuine response still works after the forgeries.
    try pair.hi.consumeResponse(&pair.li, &m2);
    _ = try pair.hi.deriveKeys();
    try testing.expectError(error.InvalidState, pair.hi.consumeResponse(&pair.li, &m2));

    // Mismatched preshared keys fail at message 2.
    var p2 = try Pair.init(psk);
    p2.hi.setPresharedKey(@splat(9));
    const n1 = try p2.initiate(e_i, wall, 0);
    try p2.receive(&n1, 0);
    const n2 = try p2.respond(0);
    try testing.expectError(error.AuthenticationFailed, p2.hi.consumeResponse(&p2.li, &n2));
}

fn noiseWriteIndex(dst: *[4]u8, v: u32) void {
    std.mem.writeInt(u32, dst, v, .little);
}

test "low-order keys are refused" {
    const li = noise.Local.init(try crypto.keyFromBase64(s_i_priv));
    var h = noise.Handshake.init(&li, @splat(0), psk);
    var r: FixedRandom = .{ .data = &e_i };
    try testing.expectError(error.InvalidPublicKey, h.createInitiation(&li, wall, 0, 1, r.random()));

    var pair = try Pair.init(psk);
    var m1 = try pair.initiate(e_i, wall, 0);
    m1.ephemeral = @splat(0);
    try testing.expectError(error.InvalidPublicKey, noise.consumeInitiationStatic(&pair.lr, &m1));
}

test "new initiation replaces the one in progress; setLocal clears" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    try pair.receive(&m1, 0);
    const m2 = try pair.respond(0);
    _ = try pair.initiate(e_i2, wall + ns_per_s, 0); // new ephemeral
    try testing.expectError(error.AuthenticationFailed, pair.hi.consumeResponse(&pair.li, &m2));
    pair.hi.setLocal(&pair.li);
    try testing.expectEqual(noise.State.zeroed, pair.hi.state);
}

test "timestamps are whitened to 2^24 ns" {
    var pair = try Pair.init(psk);
    const m1 = try pair.initiate(e_i, wall, 0);
    var start = try noise.consumeInitiationStatic(&pair.lr, &m1);
    try pair.hr.consumeInitiation(&start, 0);
    const ns = std.mem.readInt(u32, pair.hr.latest_timestamp[8..12], .big);
    try testing.expectEqual(@as(u32, 0), ns & 0xffffff);
    try testing.expectEqual(@as(u32, 123_456_789 & ~@as(u32, 0xffffff)), ns);
}

test "random keys round trip many times" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rng = prng.random();
    for (0..32) |n| {
        var ki: [32]u8 = undefined;
        var kr: [32]u8 = undefined;
        rng.bytes(&ki);
        rng.bytes(&kr);
        var p: [32]u8 = @splat(0);
        if (n % 2 == 0) rng.bytes(&p);
        const li = noise.Local.init(ki);
        const lr = noise.Local.init(kr);
        var hi = noise.Handshake.init(&li, lr.public, p);
        var hr = noise.Handshake.init(&lr, li.public, p);
        var cr = noise.CookieChecker.init(&lr.public);
        var ci = noise.CookieChecker.init(&li.public);
        const m1 = try hi.createInitiation(&li, wall + n, @intCast(n), @intCast(n), rng);
        try testing.expectEqual(noise.Verdict.ok, cr.check(m1.asBytes(), &src, 0, false, rng));
        var start = try noise.consumeInitiationStatic(&lr, &m1);
        try hr.consumeInitiation(&start, 0);
        const m2 = try hr.createResponse(0, @intCast(n + 1000), rng);
        try testing.expectEqual(noise.Verdict.ok, ci.check(m2.asBytes(), &src, 0, false, rng));
        try hi.consumeResponse(&li, &m2);
        const a = try hi.deriveKeys();
        const b = try hr.deriveKeys();
        try testing.expectEqual(a.send, b.recv);
        try testing.expectEqual(a.recv, b.send);
    }
}

// ------------------------------------------------------------------ fuzz

const keepalive_shape: [32]u8 = blk: {
    var b: [32]u8 = @splat(0);
    b[0] = 4;
    break :blk b;
};

const FuzzCtx = struct {
    local: noise.Local,
    peer: noise.Local,
};

fn fuzzOne(ctx: FuzzCtx, smith: *testing.Smith) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    try exercise(ctx, buf[0..len]);
}

/// Feed arbitrary bytes through dispatch, parsing, MAC checks and the
/// consumers. Must never crash, and must never accept a forged response or
/// cookie reply (the handshake state has no matching ephemeral / mac1).
fn exercise(ctx: FuzzCtx, bytes: []const u8) !void {
    var prng = std.Random.DefaultPrng.init(bytes.len);
    const rng = prng.random();
    var checker = noise.CookieChecker.init(&ctx.local.public);
    var hs = noise.Handshake.init(&ctx.local, ctx.peer.public, psk);
    hs.state = .created_initiation;
    const t = noise.messageType(bytes) orelse return;
    switch (t) {
        .initiation => {
            const m = try noise.Initiation.parse(bytes);
            _ = checker.check(bytes, &src, 0, true, rng);
            _ = checker.createReply(bytes, &src, 0, rng);
            var start = noise.consumeInitiationStatic(&ctx.local, m) catch return;
            hs.consumeInitiation(&start, 0) catch return;
        },
        .response => {
            const m = try noise.Response.parse(bytes);
            _ = checker.check(bytes, &src, 0, true, rng);
            hs.local_index = m.receiverIndex();
            hs.consumeResponse(&ctx.local, m) catch return;
            return error.ForgedResponseAccepted;
        },
        .cookie_reply => {
            const m = try noise.CookieReply.parse(bytes);
            hs.cookie.have_sent_mac1 = true;
            hs.cookie.consumeReply(m, 0) catch return;
            return error.ForgedCookieAccepted;
        },
        .transport => {},
    }
}

test "fuzz message parsers and consumers" {
    const ctx: FuzzCtx = .{
        .local = noise.Local.init(try crypto.keyFromBase64(s_r_priv)),
        .peer = noise.Local.init(try crypto.keyFromBase64(s_i_priv)),
    };
    try testing.fuzz(ctx, fuzzOne, .{ .corpus = &.{
        &golden_psk.initiation,
        &golden_psk.response,
        &golden_cookie.reply,
        &golden_cookie.initiation2,
        &keepalive_shape,
    } });
}

test "mutation fuzz (deterministic; std.testing.fuzz is not available on Windows)" {
    const ctx: FuzzCtx = .{
        .local = noise.Local.init(try crypto.keyFromBase64(s_r_priv)),
        .peer = noise.Local.init(try crypto.keyFromBase64(s_i_priv)),
    };
    const corpus = [_][]const u8{
        &golden_psk.initiation,     &golden_psk.response, &golden_cookie.reply,
        &golden_cookie.initiation2, &keepalive_shape,
    };
    var prng = std.Random.DefaultPrng.init(0xf022);
    const r = prng.random();
    var buf: [256]u8 = undefined;
    for (0..5000) |_| {
        const seed = corpus[r.uintLessThan(usize, corpus.len)];
        var len = seed.len;
        @memcpy(buf[0..len], seed);
        for (0..r.intRangeAtMost(usize, 1, 4)) |_| switch (r.uintLessThan(u8, 4)) {
            0 => buf[r.uintLessThan(usize, len)] ^= @as(u8, 1) << r.int(u3),
            1 => buf[r.uintLessThan(usize, len)] = r.int(u8),
            2 => len = r.intRangeAtMost(usize, 1, len),
            else => {
                const add = r.uintLessThan(usize, buf.len - len + 1);
                r.bytes(buf[len..][0..add]);
                len += add;
            },
        };
        try exercise(ctx, buf[0..len]);
    }
}
