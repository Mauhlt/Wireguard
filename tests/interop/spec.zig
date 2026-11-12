//! Reference model of the WireGuard protocol, written straight from the
//! whitepaper (rev. e2da747, sections 5.4.2-5.4.7) over std.crypto only.
//!
//! It is deliberately independent of src/noise and src/session: the golden
//! tests check those modules against this model, and the live interop driver
//! checks this model against the official WireGuard for Windows. Nothing here
//! is optimized, constant-time-audited or meant for production; it exists to
//! be obviously correct and easy to compare with the paper.
const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s256);
const ChaChaPoly = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const XChaChaPoly = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const label_mac1 = "mac1----";
pub const label_cookie = "cookie--";

// Message types and exact sizes (section 5.4).
pub const msg_initiation: u8 = 1;
pub const msg_response: u8 = 2;
pub const msg_cookie_reply: u8 = 3;
pub const msg_transport: u8 = 4;
pub const initiation_len = 148;
pub const response_len = 92;
pub const cookie_reply_len = 64;
pub const transport_header_len = 16;
pub const tag_len = 16;

// Field offsets (little-endian integers; type byte + 3 zero bytes first).
pub const Initiation = struct {
    pub const sender = 4;
    pub const ephemeral = 8;
    pub const static = 40; // 32 + 16 tag
    pub const timestamp = 88; // 12 + 16 tag
    pub const mac1 = 116;
    pub const mac2 = 132;
};
pub const Response = struct {
    pub const sender = 4;
    pub const receiver = 8;
    pub const ephemeral = 12;
    pub const empty = 44; // 0 + 16 tag
    pub const mac1 = 60;
    pub const mac2 = 76;
};
pub const CookieReply = struct {
    pub const receiver = 4;
    pub const nonce = 8; // 24
    pub const cookie = 32; // 16 + 16 tag
};
pub const Transport = struct {
    pub const receiver = 4;
    pub const counter = 8;
    pub const payload = 16;
};

// ---- primitives (section 5.4) ---------------------------------------------

pub fn hash(parts: []const []const u8) [32]u8 {
    var h = Blake2s256.init(.{});
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn mac(key: []const u8, data: []const u8) [16]u8 {
    var h = Blake2s128.init(.{ .key = key });
    h.update(data);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn hmac(key: []const u8, parts: []const []const u8) [32]u8 {
    var h = HmacBlake2s.init(key);
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// HKDF with HMAC-BLAKE2s, n outputs (Kdf_n in the paper).
pub fn kdf(comptime n: usize, key: [32]u8, input: []const u8) [n][32]u8 {
    const t0 = hmac(&key, &.{input});
    var out: [n][32]u8 = undefined;
    out[0] = hmac(&t0, &.{"\x01"});
    var i: usize = 1;
    while (i < n) : (i += 1) out[i] = hmac(&t0, &.{ &out[i - 1], &[1]u8{@intCast(i + 1)} });
    return out;
}

pub fn dh(priv: [32]u8, pub_: [32]u8) ![32]u8 {
    return X25519.scalarmult(priv, pub_);
}

pub fn publicKey(priv: [32]u8) [32]u8 {
    return X25519.recoverPublicKey(priv);
}

fn nonce12(counter: u64) [12]u8 {
    var n: [12]u8 = @splat(0);
    std.mem.writeInt(u64, n[4..12], counter, .little);
    return n;
}

pub fn aeadSeal(out: []u8, key: [32]u8, counter: u64, plain: []const u8, ad: []const u8) void {
    std.debug.assert(out.len == plain.len + tag_len);
    ChaChaPoly.encrypt(out[0..plain.len], out[plain.len..][0..tag_len], plain, ad, nonce12(counter), key);
}

pub fn aeadOpen(out: []u8, key: [32]u8, counter: u64, sealed: []const u8, ad: []const u8) !void {
    if (sealed.len < tag_len) return error.AuthenticationFailed;
    const n = sealed.len - tag_len;
    std.debug.assert(out.len == n);
    try ChaChaPoly.decrypt(out, sealed[0..n], sealed[n..][0..tag_len].*, ad, nonce12(counter), key);
}

/// TAI64N: big-endian (2^62 + seconds) then big-endian nanoseconds.
pub fn tai64n(unix_seconds: u64, nanos: u32) [12]u8 {
    var t: [12]u8 = undefined;
    std.mem.writeInt(u64, t[0..8], (@as(u64, 1) << 62) + unix_seconds, .big);
    std.mem.writeInt(u32, t[8..12], nanos, .big);
    return t;
}

pub fn initialChainingKey() [32]u8 {
    return hash(&.{construction});
}

pub fn initialHash(responder_static_pub: [32]u8) [32]u8 {
    const ck = initialChainingKey();
    const h = hash(&.{ &ck, identifier });
    return hash(&.{ &h, &responder_static_pub });
}

pub fn mac1Key(receiver_static_pub: [32]u8) [32]u8 {
    return hash(&.{ label_mac1, &receiver_static_pub });
}

pub fn cookieKey(receiver_static_pub: [32]u8) [32]u8 {
    return hash(&.{ label_cookie, &receiver_static_pub });
}

// ---- handshake -------------------------------------------------------------

pub const Keys = struct {
    send: [32]u8,
    recv: [32]u8,
    local_index: u32,
    remote_index: u32,
};

pub const Initiator = struct {
    static_priv: [32]u8,
    static_pub: [32]u8,
    peer_pub: [32]u8,
    psk: [32]u8,
    eph_priv: [32]u8 = undefined,
    ck: [32]u8 = undefined,
    h: [32]u8 = undefined,
    sender: u32 = 0,

    pub fn init(static_priv: [32]u8, peer_pub: [32]u8, psk: [32]u8) Initiator {
        return .{ .static_priv = static_priv, .static_pub = publicKey(static_priv), .peer_pub = peer_pub, .psk = psk };
    }

    /// Message 1 with the given ephemeral key and timestamp (deterministic,
    /// for golden vectors). mac2 is zero unless `cookie` is given.
    pub fn createInitiation(i: *Initiator, eph_priv: [32]u8, sender: u32, timestamp: [12]u8, cookie: ?[16]u8) ![initiation_len]u8 {
        var m: [initiation_len]u8 = @splat(0);
        m[0] = msg_initiation;
        std.mem.writeInt(u32, m[Initiation.sender..][0..4], sender, .little);
        i.sender = sender;
        i.eph_priv = eph_priv;
        i.ck = initialChainingKey();
        i.h = initialHash(i.peer_pub);

        const eph_pub = publicKey(eph_priv);
        i.ck = kdf(1, i.ck, &eph_pub)[0];
        m[Initiation.ephemeral..][0..32].* = eph_pub;
        i.h = hash(&.{ &i.h, &eph_pub });

        var k = kdf(2, i.ck, &try dh(eph_priv, i.peer_pub));
        i.ck = k[0];
        aeadSeal(m[Initiation.static..][0..48], k[1], 0, &i.static_pub, &i.h);
        i.h = hash(&.{ &i.h, m[Initiation.static..][0..48] });

        k = kdf(2, i.ck, &try dh(i.static_priv, i.peer_pub));
        i.ck = k[0];
        aeadSeal(m[Initiation.timestamp..][0..28], k[1], 0, &timestamp, &i.h);
        i.h = hash(&.{ &i.h, m[Initiation.timestamp..][0..28] });

        m[Initiation.mac1..][0..16].* = mac(&mac1Key(i.peer_pub), m[0..Initiation.mac1]);
        if (cookie) |c| m[Initiation.mac2..][0..16].* = mac(&c, m[0..Initiation.mac2]);
        return m;
    }

    pub fn consumeResponse(i: *Initiator, m: []const u8) !Keys {
        if (m.len != response_len or m[0] != msg_response) return error.InvalidMessage;
        if (!std.mem.eql(u8, m[1..4], &.{ 0, 0, 0 })) return error.InvalidMessage;
        const expect_mac1 = mac(&mac1Key(i.static_pub), m[0..Response.mac1]);
        if (!std.crypto.timing_safe.eql([16]u8, expect_mac1, m[Response.mac1..][0..16].*)) return error.BadMac1;
        if (std.mem.readInt(u32, m[Response.receiver..][0..4], .little) != i.sender) return error.UnknownReceiver;

        const eph_r = m[Response.ephemeral..][0..32].*;
        i.ck = kdf(1, i.ck, &eph_r)[0];
        i.h = hash(&.{ &i.h, &eph_r });
        i.ck = kdf(1, i.ck, &try dh(i.eph_priv, eph_r))[0];
        i.ck = kdf(1, i.ck, &try dh(i.static_priv, eph_r))[0];
        const k3 = kdf(3, i.ck, &i.psk);
        i.ck = k3[0];
        i.h = hash(&.{ &i.h, &k3[1] });
        var empty: [0]u8 = .{};
        try aeadOpen(&empty, k3[2], 0, m[Response.empty..][0..16], &i.h);
        i.h = hash(&.{ &i.h, m[Response.empty..][0..16] });

        const t = kdf(2, i.ck, "");
        return .{
            .send = t[0],
            .recv = t[1],
            .local_index = i.sender,
            .remote_index = std.mem.readInt(u32, m[Response.sender..][0..4], .little),
        };
    }
};

pub const Responder = struct {
    static_priv: [32]u8,
    static_pub: [32]u8,
    psk: [32]u8,
    ck: [32]u8 = undefined,
    h: [32]u8 = undefined,
    peer_static: [32]u8 = undefined,
    peer_eph: [32]u8 = undefined,
    peer_sender: u32 = 0,
    timestamp: [12]u8 = undefined,

    pub fn init(static_priv: [32]u8, psk: [32]u8) Responder {
        return .{ .static_priv = static_priv, .static_pub = publicKey(static_priv), .psk = psk };
    }

    /// Verifies MAC1, decrypts the initiator's static key and timestamp.
    pub fn consumeInitiation(r: *Responder, m: []const u8) !void {
        if (m.len != initiation_len or m[0] != msg_initiation) return error.InvalidMessage;
        if (!std.mem.eql(u8, m[1..4], &.{ 0, 0, 0 })) return error.InvalidMessage;
        const expect_mac1 = mac(&mac1Key(r.static_pub), m[0..Initiation.mac1]);
        if (!std.crypto.timing_safe.eql([16]u8, expect_mac1, m[Initiation.mac1..][0..16].*)) return error.BadMac1;

        r.peer_sender = std.mem.readInt(u32, m[Initiation.sender..][0..4], .little);
        r.ck = initialChainingKey();
        r.h = initialHash(r.static_pub);
        r.peer_eph = m[Initiation.ephemeral..][0..32].*;
        r.ck = kdf(1, r.ck, &r.peer_eph)[0];
        r.h = hash(&.{ &r.h, &r.peer_eph });

        var k = kdf(2, r.ck, &try dh(r.static_priv, r.peer_eph));
        r.ck = k[0];
        try aeadOpen(&r.peer_static, k[1], 0, m[Initiation.static..][0..48], &r.h);
        r.h = hash(&.{ &r.h, m[Initiation.static..][0..48] });

        k = kdf(2, r.ck, &try dh(r.static_priv, r.peer_static));
        r.ck = k[0];
        try aeadOpen(&r.timestamp, k[1], 0, m[Initiation.timestamp..][0..28], &r.h);
        r.h = hash(&.{ &r.h, m[Initiation.timestamp..][0..28] });
    }

    pub fn createResponse(r: *Responder, eph_priv: [32]u8, sender: u32) !struct { msg: [response_len]u8, keys: Keys } {
        var m: [response_len]u8 = @splat(0);
        m[0] = msg_response;
        std.mem.writeInt(u32, m[Response.sender..][0..4], sender, .little);
        std.mem.writeInt(u32, m[Response.receiver..][0..4], r.peer_sender, .little);

        const eph_pub = publicKey(eph_priv);
        r.ck = kdf(1, r.ck, &eph_pub)[0];
        m[Response.ephemeral..][0..32].* = eph_pub;
        r.h = hash(&.{ &r.h, &eph_pub });
        r.ck = kdf(1, r.ck, &try dh(eph_priv, r.peer_eph))[0];
        r.ck = kdf(1, r.ck, &try dh(eph_priv, r.peer_static))[0];
        const k3 = kdf(3, r.ck, &r.psk);
        r.ck = k3[0];
        r.h = hash(&.{ &r.h, &k3[1] });
        aeadSeal(m[Response.empty..][0..16], k3[2], 0, "", &r.h);
        r.h = hash(&.{ &r.h, m[Response.empty..][0..16] });
        m[Response.mac1..][0..16].* = mac(&mac1Key(r.peer_static), m[0..Response.mac1]);

        const t = kdf(2, r.ck, "");
        return .{ .msg = m, .keys = .{ .send = t[1], .recv = t[0], .local_index = sender, .remote_index = r.peer_sender } };
    }
};

// ---- transport data (section 5.4.6) ----------------------------------------

/// Encrypts `plain` (zero-padded to a multiple of 16) into `out`; returns the
/// packet. Keepalive = empty plaintext.
pub fn sealTransport(out: []u8, keys: Keys, counter: u64, plain: []const u8) []u8 {
    const padded = std.mem.alignForward(usize, plain.len, 16);
    const total = transport_header_len + padded + tag_len;
    std.debug.assert(out.len >= total);
    out[0] = msg_transport;
    @memset(out[1..4], 0);
    std.mem.writeInt(u32, out[Transport.receiver..][0..4], keys.remote_index, .little);
    std.mem.writeInt(u64, out[Transport.counter..][0..8], counter, .little);
    var pbuf: [65536]u8 = undefined;
    @memcpy(pbuf[0..plain.len], plain);
    @memset(pbuf[plain.len..padded], 0);
    aeadSeal(out[Transport.payload..total], keys.send, counter, pbuf[0..padded], "");
    return out[0..total];
}

/// Decrypts a transport packet addressed to `keys.local_index`; returns the
/// padded plaintext (an IP packet's own length field tells the real size).
pub fn openTransport(out: []u8, keys: Keys, packet: []const u8) !struct { counter: u64, plain: []u8 } {
    if (packet.len < transport_header_len + tag_len or packet[0] != msg_transport) return error.InvalidMessage;
    if (std.mem.readInt(u32, packet[Transport.receiver..][0..4], .little) != keys.local_index) return error.UnknownReceiver;
    const counter = std.mem.readInt(u64, packet[Transport.counter..][0..8], .little);
    const n = packet.len - transport_header_len - tag_len;
    try aeadOpen(out[0..n], keys.recv, counter, packet[Transport.payload..], "");
    return .{ .counter = counter, .plain = out[0..n] };
}

// ---- cookies (section 5.4.7) -----------------------------------------------

/// Cookie the responder hands out: MAC(Rm, initiator IP || port), where
/// `source` is the raw address bytes followed by the big-endian port.
pub fn cookieValue(secret: [32]u8, source: []const u8) [16]u8 {
    return mac(&secret, source);
}

pub fn createCookieReply(receiver_static_pub: [32]u8, receiver_index: u32, nonce: [24]u8, cookie: [16]u8, mac1_of_msg: [16]u8) [cookie_reply_len]u8 {
    var m: [cookie_reply_len]u8 = @splat(0);
    m[0] = msg_cookie_reply;
    std.mem.writeInt(u32, m[CookieReply.receiver..][0..4], receiver_index, .little);
    m[CookieReply.nonce..][0..24].* = nonce;
    XChaChaPoly.encrypt(m[CookieReply.cookie..][0..16], m[CookieReply.cookie + 16 ..][0..16], &cookie, &mac1_of_msg, nonce, cookieKey(receiver_static_pub));
    return m;
}

pub fn openCookieReply(m: []const u8, receiver_static_pub: [32]u8, mac1_of_msg: [16]u8) ![16]u8 {
    if (m.len != cookie_reply_len or m[0] != msg_cookie_reply) return error.InvalidMessage;
    var cookie: [16]u8 = undefined;
    try XChaChaPoly.decrypt(&cookie, m[CookieReply.cookie..][0..16], m[CookieReply.cookie + 16 ..][0..16].*, &mac1_of_msg, m[CookieReply.nonce..][0..24].*, cookieKey(receiver_static_pub));
    return cookie;
}

// ---- self-consistency --------------------------------------------------------

fn seed(b: u8) [32]u8 {
    return @splat(b);
}

test "reference initiator and responder agree, transport round trip" {
    const i_priv = seed(0x11);
    const r_priv = seed(0x22);
    const psk = seed(0x33);
    var ini = Initiator.init(i_priv, publicKey(r_priv), psk);
    var res = Responder.init(r_priv, psk);

    const m1 = try ini.createInitiation(seed(0x44), 0x01020304, tai64n(1_700_000_000, 5), null);
    try std.testing.expectEqual(@as(u8, 1), m1[0]);
    try res.consumeInitiation(&m1);
    try std.testing.expectEqualSlices(u8, &ini.static_pub, &res.peer_static);
    try std.testing.expectEqualSlices(u8, &tai64n(1_700_000_000, 5), &res.timestamp);

    const r2 = try res.createResponse(seed(0x55), 0xa0b0c0d0);
    const ik = try ini.consumeResponse(&r2.msg);
    try std.testing.expectEqualSlices(u8, &ik.send, &r2.keys.recv);
    try std.testing.expectEqualSlices(u8, &ik.recv, &r2.keys.send);
    try std.testing.expectEqual(ik.remote_index, r2.keys.local_index);
    try std.testing.expectEqual(ik.local_index, r2.keys.remote_index);

    var pkt: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const p = sealTransport(&pkt, ik, 7, "hello wireguard");
    try std.testing.expectEqual(@as(usize, 16 + 16 + 16), p.len);
    const o = try openTransport(&plain, r2.keys, p);
    try std.testing.expectEqual(@as(u64, 7), o.counter);
    try std.testing.expectEqualStrings("hello wireguard\x00", o.plain);

    // Keepalive: header + tag only.
    try std.testing.expectEqual(@as(usize, 32), sealTransport(&pkt, r2.keys, 0, "").len);

    // Tampering is detected.
    const q = sealTransport(&pkt, r2.keys, 1, "x");
    q[20] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, openTransport(&plain, ik, q));
}

test "mac1 rejects a message for another responder; cookie reply round trip" {
    var ini = Initiator.init(seed(1), publicKey(seed(2)), seed(0));
    const m1 = try ini.createInitiation(seed(3), 1, tai64n(0, 0), null);
    var other = Responder.init(seed(9), seed(0));
    try std.testing.expectError(error.BadMac1, other.consumeInitiation(&m1));

    const cookie = cookieValue(seed(7), &.{ 127, 0, 0, 1, 0xca, 0x6c });
    const mac1_of = m1[Initiation.mac1..][0..16].*;
    const nonce: [24]u8 = @splat(8);
    const reply = createCookieReply(publicKey(seed(2)), 1, nonce, cookie, mac1_of);
    try std.testing.expectEqual(cookie, try openCookieReply(&reply, publicKey(seed(2)), mac1_of));
    var bad = mac1_of;
    bad[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, openCookieReply(&reply, publicKey(seed(2)), bad));

    // With the cookie, mac2 covers everything before it.
    const m1c = try ini.createInitiation(seed(3), 1, tai64n(0, 0), cookie);
    try std.testing.expectEqual(mac(&cookie, m1c[0..Initiation.mac2]), m1c[Initiation.mac2..][0..16].*);
}
