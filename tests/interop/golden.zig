//! Known-answer and cross-implementation tests (`zig build interop`).
//!
//! Three sources of truth, none of them the code under test:
//!   1. Values produced by the official tools (wg.exe pubkey) and constants
//!      published in the Linux kernel (drivers/net/wireguard/noise.c).
//!   2. `spec.zig`, an independent model written straight from the
//!      whitepaper. noise/session must interoperate with it byte for byte,
//!      in both roles.
//!   3. A transcript recorded from the official WireGuard for Windows by
//!      `live.zig --record` (vectors/official.zig; skipped until recorded).
const std = @import("std");
const wg = @import("WireGuard");
const spec = @import("spec.zig");
const ip = @import("ip.zig");
const official = @import("vectors/official.zig");

const crypto = wg.crypto;
const noise = wg.noise;
const session = wg.session;
const testing = std.testing;

fn b64(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, s) catch unreachable;
    return out;
}

/// private -> public as printed by `wg pubkey` (wireguard-tools v1.0.20260223,
/// "C:\Program Files\WireGuard\wg.exe"). The 77076d0a / 5dab087e rows are
/// also the RFC 7748 section 6.1 Alice/Bob keys.
const wg_pubkey_vectors = [_][2][]const u8{
    .{ "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=" },
    .{ "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" },
    .{ "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=", "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=" },
    .{ "//////////////////////////////////////////8=", "hHwNLDdSNPNl5mCVUYejc1oPdhPRYJ06ak2MU66qWiI=" },
    .{ "2M/KNY1fpe3HyvQdiFNl1mH9ToL4ob2qY/3h9sdHFGg=", "lTW8PtzbI1BZpCxRJfDE+xCnNOMSqPagZ5yRMJOemBM=" },
    .{ "YK3XpND0jwx2f8kjJq78UE1Q5Ul8ya7JpbZT+z85XGA=", "bMYjA7sn0nv9+poFK/FfXHT0Eeobpx6CoEtGF4uk9DM=" },
};

test "X25519 public keys match wg.exe" {
    for (wg_pubkey_vectors) |v| {
        const priv = b64(v[0]);
        const want = b64(v[1]);
        try testing.expectEqual(want, crypto.publicKey(priv));
        try testing.expectEqual(want, spec.publicKey(priv));
    }
}

test "initial chaining key and hash match the Linux kernel constants" {
    var want_ck: [32]u8 = undefined;
    var want_h: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_ck, "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    _ = try std.fmt.hexToBytes(&want_h, "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");
    try testing.expectEqual(want_ck, spec.initialChainingKey());
    try testing.expectEqual(want_h, spec.hash(&.{ &want_ck, spec.identifier }));
    // noise keeps these private; the handshake tests below prove it uses them.
}

test "wire layout: sizes and field offsets per the whitepaper" {
    try testing.expectEqual(@as(usize, spec.initiation_len), @sizeOf(noise.Initiation));
    try testing.expectEqual(@as(usize, spec.response_len), @sizeOf(noise.Response));
    try testing.expectEqual(@as(usize, spec.cookie_reply_len), @sizeOf(noise.CookieReply));
    try testing.expectEqual(@as(usize, spec.Initiation.sender), @offsetOf(noise.Initiation, "sender"));
    try testing.expectEqual(@as(usize, spec.Initiation.ephemeral), @offsetOf(noise.Initiation, "ephemeral"));
    try testing.expectEqual(@as(usize, spec.Initiation.static), @offsetOf(noise.Initiation, "encrypted_static"));
    try testing.expectEqual(@as(usize, spec.Initiation.timestamp), @offsetOf(noise.Initiation, "encrypted_timestamp"));
    try testing.expectEqual(@as(usize, spec.Initiation.mac1), @offsetOf(noise.Initiation, "mac1"));
    try testing.expectEqual(@as(usize, spec.Initiation.mac2), @offsetOf(noise.Initiation, "mac2"));
    try testing.expectEqual(@as(usize, spec.Response.mac1), @offsetOf(noise.Response, "mac1"));
    try testing.expectEqual(@as(usize, spec.Response.mac2), @offsetOf(noise.Response, "mac2"));
    try testing.expectEqual(@as(usize, spec.transport_header_len), session.transport.header_len);
}

test "crypto primitives agree with the reference model" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    for (0..32) |round| {
        var key: [32]u8 = undefined;
        var data: [200]u8 = undefined;
        r.bytes(&key);
        r.bytes(&data);
        const d = data[0 .. round * 6];
        try testing.expectEqual(spec.hash(&.{ &key, d }), crypto.hash(&.{ &key, d }));
        try testing.expectEqual(spec.mac(&key, d), crypto.mac(&key, &.{d}));
        try testing.expectEqual(spec.hmac(&key, &.{d}), crypto.hmac(&key, d));
        try testing.expectEqual(spec.kdf(1, key, d)[0], crypto.kdf1(&key, d));
        try testing.expectEqual(spec.kdf(2, key, d), crypto.kdf2(&key, d));
        try testing.expectEqual(spec.kdf(3, key, d), crypto.kdf3(&key, d));

        var a: [216]u8 = undefined;
        var b: [216]u8 = undefined;
        spec.aeadSeal(a[0 .. d.len + 16], key, round, d, "ad");
        crypto.aeadEncrypt(b[0 .. d.len + 16], &key, round, d, "ad");
        try testing.expectEqualSlices(u8, a[0 .. d.len + 16], b[0 .. d.len + 16]);
    }
}

const Party = struct {
    priv: [32]u8,
    fn public(p: Party) [32]u8 {
        return spec.publicKey(p.priv);
    }
};

fn keyFrom(byte: u8) [32]u8 {
    var k: [32]u8 = @splat(byte);
    crypto.clampPrivateKey(&k);
    return k;
}

const wall_ns: i96 = 1_700_000_000_123_456_789;

/// Transport data sealed by one side opens on the other, both directions.
fn checkTransport(noise_seed: session.Seed, spec_keys: spec.Keys) !void {
    var pkt: [256]u8 = undefined;
    var out: [256]u8 = undefined;
    var ipbuf: [64]u8 = undefined;
    const payload = ip.buildUdp4(&ipbuf, .{ 10, 0, 0, 1 }, 1, .{ 10, 0, 0, 2 }, 2, "golden", 9);

    // noise/session -> spec
    const n = try session.transport.seal(&noise_seed.send, noise_seed.remote_index, 3, payload, 1420, &pkt);
    const o = try spec.openTransport(&out, spec_keys, pkt[0..n]);
    try testing.expectEqualStrings("golden", ip.parseUdp4(o.plain).?.payload);

    // spec -> noise/session
    const p = spec.sealTransport(&pkt, spec_keys, 4, payload);
    const pt = try session.transport.open(&noise_seed.recv, p, &out);
    try testing.expectEqualStrings("golden", ip.parseUdp4(pt).?.payload);
}

test "noise initiator <-> reference responder" {
    var prng = std.Random.DefaultPrng.init(1);
    const ini = Party{ .priv = keyFrom(0x31) };
    const res = Party{ .priv = keyFrom(0x32) };
    var psk: [32]u8 = undefined;
    prng.random().bytes(&psk);

    const local = noise.Local.init(ini.priv);
    var hs = noise.Handshake.init(&local, res.public(), psk);
    const m1 = try hs.createInitiation(&local, wall_ns, 0, 0x11223344, prng.random());

    var r = spec.Responder.init(res.priv, psk);
    try r.consumeInitiation(m1.asBytes());
    try testing.expectEqual(ini.public(), r.peer_static);

    const r2 = try r.createResponse(keyFrom(0x77), 0x55667788);
    try hs.consumeResponse(&local, try noise.Response.parse(&r2.msg));
    const seed = try hs.deriveKeys();
    try testing.expect(seed.is_initiator);
    try testing.expectEqual(r2.keys.recv, seed.send);
    try testing.expectEqual(r2.keys.send, seed.recv);
    try testing.expectEqual(@as(u32, 0x11223344), seed.local_index);
    try testing.expectEqual(@as(u32, 0x55667788), seed.remote_index);
    try checkTransport(seed, r2.keys);
}

test "reference initiator <-> noise responder" {
    var prng = std.Random.DefaultPrng.init(2);
    const ini = Party{ .priv = keyFrom(0x41) };
    const res = Party{ .priv = keyFrom(0x42) };
    const psk: [32]u8 = @splat(0); // no PSK: the common case

    var i = spec.Initiator.init(ini.priv, res.public(), psk);
    const m1 = try i.createInitiation(keyFrom(0x43), 0xaabbccdd, spec.tai64n(1_700_000_000, 0), null);

    const local = noise.Local.init(res.priv);
    const msg = try noise.Initiation.parse(&m1);
    var start = try noise.consumeInitiationStatic(&local, msg);
    try testing.expectEqual(ini.public(), start.remote_static);
    var hs = noise.Handshake.init(&local, start.remote_static, psk);
    try hs.consumeInitiation(&start, 0);
    const r2 = try hs.createResponse(0, 0x01020304, prng.random());
    const keys = try i.consumeResponse(r2.asBytes());
    const seed = try hs.deriveKeys();
    try testing.expect(!seed.is_initiator);
    try testing.expectEqual(keys.send, seed.recv);
    try testing.expectEqual(keys.recv, seed.send);
    try checkTransport(seed, keys);
}

test "mac1 from the reference is accepted by noise's CookieChecker, and vice versa" {
    var prng = std.Random.DefaultPrng.init(3);
    const res = Party{ .priv = keyFrom(0x52) };
    var i = spec.Initiator.init(keyFrom(0x51), res.public(), @splat(0));
    const m1 = try i.createInitiation(keyFrom(0x53), 7, spec.tai64n(1, 0), null);
    const local = noise.Local.init(res.priv);
    var checker = noise.CookieChecker.init(&local.public);
    const src = [_]u8{ 127, 0, 0, 1, 0xca, 0x6c };
    try testing.expectEqual(noise.Verdict.ok, checker.check(&m1, &src, 0, false, prng.random()));
    var bad = m1;
    bad[spec.Initiation.mac1] ^= 1;
    try testing.expectEqual(noise.Verdict.invalid, checker.check(&bad, &src, 0, false, prng.random()));

    // Under load without a cookie: noise asks for one; the reference opens
    // the reply and its cookie makes a mac2 that noise then accepts.
    try testing.expectEqual(noise.Verdict.need_cookie, checker.check(&m1, &src, 0, true, prng.random()));
    const reply = checker.createReply(&m1, &src, 0, prng.random());
    const cookie = try spec.openCookieReply(std.mem.asBytes(&reply), res.public(), m1[spec.Initiation.mac1..][0..16].*);
    const m1c = try i.createInitiation(keyFrom(0x53), 7, spec.tai64n(1, 0), cookie);
    try testing.expectEqual(noise.Verdict.ok, checker.check(&m1c, &src, 0, true, prng.random()));
}

test "official WireGuard for Windows transcript (recorded by live.zig --record)" {
    if (!official.available) return error.SkipZigTest;
    // Our side was the responder; the official service initiated.
    var r = spec.Responder.init(official.our_private, @splat(0));
    try r.consumeInitiation(&official.initiation);
    try testing.expectEqual(official.official_public, r.peer_static);
    const r2 = try r.createResponse(official.response_ephemeral_private, official.response_sender);
    try testing.expectEqualSlices(u8, &official.response, &r2.msg);
    var out: [2048]u8 = undefined;
    // The official keepalive after the handshake, and its echo reply.
    const k = try spec.openTransport(&out, r2.keys, &official.keepalive);
    try testing.expectEqual(@as(usize, 0), k.plain.len);
    const e = try spec.openTransport(&out, r2.keys, &official.echo_reply);
    try testing.expectEqualStrings(official.echo_payload, ip.parseUdp4(e.plain).?.payload);

    // Same transcript through noise + session.
    const local = noise.Local.init(official.our_private);
    const start = try noise.consumeInitiationStatic(&local, try noise.Initiation.parse(&official.initiation));
    try testing.expectEqual(official.official_public, start.remote_static);
    const seed_keys = r2.keys;
    const pt = try session.transport.open(&seed_keys.recv, &official.echo_reply, &out);
    try testing.expectEqualStrings(official.echo_payload, ip.parseUdp4(pt).?.payload);
}

test {
    _ = spec;
    _ = ip;
}
