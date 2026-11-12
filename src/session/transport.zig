//! Transport data messages (type 4), whitepaper §5.4.6:
//!
//! ```
//! msg = packet_data {
//!     u8  message_type        = 4
//!     u8  reserved_zero[3]
//!     u32 receiver_index      (little-endian)
//!     u64 counter             (little-endian)
//!     u8  encrypted_encapsulated_packet[]
//! }
//! encrypted = AEAD(T_send, counter, P ‖ zero padding, ε)
//! ```
//!
//! AEAD is ChaCha20-Poly1305 (RFC 8439) with a 96-bit nonce of 32 zero bits
//! followed by the 64-bit little-endian counter, and empty associated data.
//! The plaintext is zero-padded to a multiple of 16 bytes, but never beyond
//! the MTU (Linux `calculate_skb_padding`, wireguard-go `calculatePaddingSize`).
//! A keepalive is an empty plaintext: a 32-byte message.
//!
//! These are the stateless primitives; counter allocation, key selection,
//! expiry and replay protection live in keypair.zig. Nothing here allocates.

const std = @import("std");
const c = @import("constants.zig");
const crypto = @import("../crypto.zig");

pub const SymKey = crypto.SymKey;

pub const message_type: u8 = 4;
pub const header_len: usize = 16;
pub const tag_len: usize = crypto.tag_len;
/// Header + Poly1305 tag.
pub const overhead: usize = header_len + tag_len;
/// Size of a keepalive (empty plaintext) message.
pub const keepalive_len: usize = overhead;

pub const Header = struct {
    receiver_index: u32,
    counter: u64,

    /// Parse and validate the fixed header. The first four bytes must be the
    /// little-endian u32 4 (type 4, reserved bytes zero), as both the kernel
    /// (`SKB_TYPE_LE32`) and wireguard-go (`binary.LittleEndian.Uint32`) read
    /// them. Shorter than a keepalive is malformed.
    pub fn parse(packet: []const u8) error{Malformed}!Header {
        if (packet.len < keepalive_len) return error.Malformed;
        if (std.mem.readInt(u32, packet[0..4], .little) != message_type) return error.Malformed;
        return .{
            .receiver_index = std.mem.readInt(u32, packet[4..8], .little),
            .counter = std.mem.readInt(u64, packet[8..16], .little),
        };
    }

    pub fn write(self: Header, out: *[header_len]u8) void {
        std.mem.writeInt(u32, out[0..4], message_type, .little);
        std.mem.writeInt(u32, out[4..8], self.receiver_index, .little);
        std.mem.writeInt(u64, out[8..16], self.counter, .little);
    }
};

/// Length of the padded plaintext for a `len`-byte packet. `mtu == 0` means
/// "no MTU known": pad to a multiple of 16. Otherwise the padded size is
/// capped at the MTU; packets larger than the MTU (GSO) pad only their last
/// MTU-sized unit, exactly like the kernel and wireguard-go.
pub fn paddedLen(len: usize, mtu: usize) usize {
    const m = c.PADDING_MULTIPLE;
    if (mtu == 0) return std.mem.alignForward(usize, len, m);
    var last_unit = len;
    if (last_unit > mtu) last_unit %= mtu;
    const padded = @min(mtu, std.mem.alignForward(usize, last_unit, m));
    // padded >= last_unit always (alignForward rounds up, and last_unit <= mtu).
    return len + (padded - last_unit);
}

/// Total wire size of a message carrying `len` plaintext bytes.
pub fn messageLen(len: usize, mtu: usize) usize {
    return header_len + paddedLen(len, mtu) + tag_len;
}

pub const SealError = error{BufferTooSmall};

/// Build a complete transport message in `out` and return its length.
/// `plaintext` may be disjoint from `out` or sit exactly at
/// `out[header_len..][0..plaintext.len]` (in-place); other overlaps are not
/// allowed. Padding bytes are zeroed here.
pub fn seal(
    key: *const SymKey,
    receiver_index: u32,
    counter: u64,
    plaintext: []const u8,
    mtu: usize,
    out: []u8,
) SealError!usize {
    const padded = paddedLen(plaintext.len, mtu);
    const total = header_len + padded + tag_len;
    if (out.len < total) return error.BufferTooSmall;
    const body = out[header_len..][0..padded];
    @memmove(body[0..plaintext.len], plaintext);
    @memset(body[plaintext.len..], 0);
    (Header{ .receiver_index = receiver_index, .counter = counter }).write(out[0..header_len]);
    // ChaCha20-Poly1305, nonce 0^32 ‖ LE64(counter), empty AD; the tag
    // directly follows the padded body. In place: body is both input and output.
    crypto.aeadEncrypt(out[header_len..][0 .. padded + tag_len], key, counter, body, &.{});
    return total;
}

pub const OpenError = error{ Malformed, BufferTooSmall, AuthenticationFailed };

/// Authenticate and decrypt the message `packet` (header already validated
/// by the caller or not — it is re-parsed) into `out`, returning the padded
/// plaintext (the IP layer trims padding using the IP header's length).
/// `out` may be disjoint from `packet` or exactly `packet[header_len..]`
/// (in-place). On error the contents of `out` are unspecified.
pub fn open(key: *const SymKey, packet: []const u8, out: []u8) OpenError![]u8 {
    const h = try Header.parse(packet);
    const ct = packet[header_len .. packet.len - tag_len];
    if (out.len < ct.len) return error.BufferTooSmall;
    try crypto.aeadDecrypt(out[0..ct.len], key, h.counter, packet[header_len..], &.{});
    return out[0..ct.len];
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const test_key: SymKey = blk: {
    var k: SymKey = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i * 7 + 1);
    break :blk k;
};

test "padding sizes" {
    try testing.expectEqual(@as(usize, 0), paddedLen(0, 1420));
    try testing.expectEqual(@as(usize, 16), paddedLen(1, 1420));
    try testing.expectEqual(@as(usize, 16), paddedLen(16, 1420));
    try testing.expectEqual(@as(usize, 32), paddedLen(17, 1420));
    // Capped at the MTU: 1419 would round to 1424 > 1420.
    try testing.expectEqual(@as(usize, 1420), paddedLen(1419, 1420));
    try testing.expectEqual(@as(usize, 1420), paddedLen(1420, 1420));
    // mtu 0: plain multiple of 16.
    try testing.expectEqual(@as(usize, 1424), paddedLen(1419, 0));
    // Larger than MTU (GSO): only the last unit is padded.
    try testing.expectEqual(@as(usize, 1420 + 16), paddedLen(1420 + 3, 1420));
    try testing.expectEqual(@as(usize, 2840), paddedLen(2840, 1420));
    // Odd MTU.
    try testing.expectEqual(@as(usize, 1281), paddedLen(1281, 1281));
    try testing.expectEqual(@as(usize, 1280), paddedLen(1270, 1281));
    try testing.expectEqual(@as(usize, 1281), paddedLen(1280 + 1 - 0, 1281));
    try testing.expectEqual(@as(usize, 32 + 32), messageLen(17, 1420));
}

test "header parse/write" {
    var buf: [32]u8 = @splat(0);
    (Header{ .receiver_index = 0x11223344, .counter = 0x0102030405060708 }).write(buf[0..16]);
    try testing.expectEqualSlices(u8, &.{ 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 8, 7, 6, 5, 4, 3, 2, 1 }, buf[0..16]);
    const h = try Header.parse(&buf);
    try testing.expectEqual(@as(u32, 0x11223344), h.receiver_index);
    try testing.expectEqual(@as(u64, 0x0102030405060708), h.counter);
    try testing.expectError(error.Malformed, Header.parse(buf[0..31]));
    buf[1] = 1; // reserved byte non-zero
    try testing.expectError(error.Malformed, Header.parse(&buf));
    buf[1] = 0;
    buf[0] = 1;
    try testing.expectError(error.Malformed, Header.parse(&buf));
}

test "round trip with padding, disjoint and in place" {
    var out: [1500]u8 = undefined;
    var dec: [1500]u8 = undefined;
    var msg: [1420]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);
    for ([_]usize{ 0, 1, 15, 16, 17, 100, 1419, 1420 }) |len| {
        const n = try seal(&test_key, 0xdeadbeef, len, msg[0..len], 1420, &out);
        try testing.expectEqual(messageLen(len, 1420), n);
        try testing.expect((n - overhead) % 16 == 0 or n - overhead == 1420);
        const pt = try open(&test_key, out[0..n], &dec);
        try testing.expectEqual(paddedLen(len, 1420), pt.len);
        try testing.expectEqualSlices(u8, msg[0..len], pt[0..len]);
        for (pt[len..]) |b| try testing.expectEqual(@as(u8, 0), b);

        // In place, both directions.
        @memcpy(out[header_len..][0..len], msg[0..len]);
        const n2 = try seal(&test_key, 0xdeadbeef, len, out[header_len..][0..len], 1420, &out);
        try testing.expectEqual(n, n2);
        const pt2 = try open(&test_key, out[0..n2], out[header_len .. n2 - tag_len]);
        try testing.expectEqualSlices(u8, msg[0..len], pt2[0..len]);
    }
}

test "keepalive is 32 bytes" {
    var out: [64]u8 = undefined;
    const n = try seal(&test_key, 1, 0, &.{}, 1420, &out);
    try testing.expectEqual(@as(usize, 32), n);
    var dec: [0]u8 = .{};
    const pt = try open(&test_key, out[0..n], &dec);
    try testing.expectEqual(@as(usize, 0), pt.len);
}

test "known answer: RFC 8439 AEAD with WireGuard nonce layout" {
    // Independent check of the nonce layout: seal must equal the raw RFC 8439
    // AEAD with nonce 00000000 ‖ LE64(counter) over the zero-padded plaintext.
    const pt = "hello, wireguard";
    var out: [64]u8 = undefined;
    const n = try seal(&test_key, 7, 0x0a0b0c0d, pt, 0, &out);
    var expect_ct: [16]u8 = undefined;
    var expect_tag: [16]u8 = undefined;
    const nn = [12]u8{ 0, 0, 0, 0, 0x0d, 0x0c, 0x0b, 0x0a, 0, 0, 0, 0 };
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&expect_ct, &expect_tag, pt, "", nn, test_key);
    try testing.expectEqualSlices(u8, &expect_ct, out[16..32]);
    try testing.expectEqualSlices(u8, &expect_tag, out[32..48]);
    try testing.expectEqual(@as(usize, 48), n);
}

test "tampering is detected anywhere" {
    var out: [128]u8 = undefined;
    var dec: [128]u8 = undefined;
    const n = try seal(&test_key, 9, 3, "attack at dawn!!xyz", 1420, &out);
    var i: usize = 4; // header bytes 0..3 tested via parse; tamper index/counter/ct/tag
    while (i < n) : (i += 1) {
        var copy = out;
        copy[i] ^= 0x01;
        if (i < 8) {
            // receiver index is not authenticated by the AEAD (it only selects
            // the key); a different index simply finds a different key.
            _ = open(&test_key, copy[0..n], &dec) catch unreachable;
            continue;
        }
        try testing.expectError(error.AuthenticationFailed, open(&test_key, copy[0..n], &dec));
    }
    // Truncated / extended.
    try testing.expectError(error.AuthenticationFailed, open(&test_key, out[0 .. n - 1], &dec));
    // Wrong key.
    var k2 = test_key;
    k2[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, open(&k2, out[0..n], &dec));
}

test "buffer too small" {
    var out: [47]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, seal(&test_key, 1, 0, "x", 1420, &out));
    var big: [64]u8 = undefined;
    const n = try seal(&test_key, 1, 0, "x", 1420, &big);
    var small: [15]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, open(&test_key, big[0..n], &small));
}
