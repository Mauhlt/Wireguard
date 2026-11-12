//! WireGuard key text form: standard base64 (RFC 4648, with `=` padding) of
//! the 32 raw bytes, always 44 characters. Same as `wg genkey` / `wg pubkey`
//! and the .conf files of wg-quick and WireGuard for Windows.
//!
//! Encoding and decoding run in constant time with respect to the key bytes
//! (no table lookups indexed by secret data), like wg's encoding.c, because
//! private and preshared keys go through here.

const std = @import("std");

pub const key_len = 32;
pub const Key = [key_len]u8;
pub const base64_len = 44;

pub const DecodeError = error{InvalidKey};

/// Encodes one 6-bit value as a base64 character, without branches or tables.
fn encodeSextet(v: u8) u8 {
    const x: i32 = v;
    // 'A'..'Z' for 0..25, 'a'..'z' for 26..51, '0'..'9' for 52..61, '+' 62, '/' 63.
    const r = x + 'A' +
        (((25 - x) >> 8) & 6) -
        (((51 - x) >> 8) & 75) -
        (((61 - x) >> 8) & 15) +
        (((62 - x) >> 8) & 3);
    return @intCast(r);
}

/// Decodes one base64 character; returns -1 (as a negative i32) for an
/// invalid character. Constant time in `c`.
fn decodeChar(c: u8) i32 {
    const x: i32 = c;
    var ret: i32 = -1;
    ret += (((('A' - 1) - x) & (x - ('Z' + 1))) >> 8) & (x - 64);
    ret += (((('a' - 1) - x) & (x - ('z' + 1))) >> 8) & (x - 70);
    ret += (((('0' - 1) - x) & (x - ('9' + 1))) >> 8) & (x + 5);
    ret += ((('+' - 1) - x) & (x - ('+' + 1))) >> 8 & 63;
    ret += ((('/' - 1) - x) & (x - ('/' + 1))) >> 8 & 64;
    return ret;
}

pub fn encode(key: *const Key) [base64_len]u8 {
    var out: [base64_len]u8 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const b = key[i * 3 ..][0..3];
        out[i * 4 + 0] = encodeSextet(b[0] >> 2);
        out[i * 4 + 1] = encodeSextet(((b[0] << 4) | (b[1] >> 4)) & 63);
        out[i * 4 + 2] = encodeSextet(((b[1] << 2) | (b[2] >> 6)) & 63);
        out[i * 4 + 3] = encodeSextet(b[2] & 63);
    }
    out[40] = encodeSextet(key[30] >> 2);
    out[41] = encodeSextet(((key[30] << 4) | (key[31] >> 4)) & 63);
    out[42] = encodeSextet((key[31] << 2) & 63);
    out[43] = '=';
    return out;
}

/// Decodes a 44-character key. Rejects other lengths, missing padding,
/// invalid characters and non-canonical encodings (nonzero unused bits in
/// the last character), the way wg's key_from_base64 does.
pub fn decode(text: []const u8) DecodeError!Key {
    if (text.len != base64_len or text[base64_len - 1] != '=') return error.InvalidKey;
    var key: Key = undefined;
    var bad: i32 = 0;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var val: i32 = 0;
        for (0..4) |j| {
            const d = decodeChar(text[i * 4 + j]);
            bad |= d;
            val |= d << @intCast(18 - 6 * j);
        }
        key[i * 3 + 0] = @truncate(@as(u32, @bitCast(val)) >> 16);
        key[i * 3 + 1] = @truncate(@as(u32, @bitCast(val)) >> 8);
        key[i * 3 + 2] = @truncate(@as(u32, @bitCast(val)));
    }
    var val: i32 = 0;
    for (0..3) |j| {
        const d = decodeChar(text[40 + j]);
        bad |= d;
        val |= d << @intCast(18 - 6 * j);
    }
    // The last character carries 4 data bits and 2 padding bits that must be 0.
    bad |= -(val & 0xff); // nonzero low byte -> negative
    key[30] = @truncate(@as(u32, @bitCast(val)) >> 16);
    key[31] = @truncate(@as(u32, @bitCast(val)) >> 8);
    if (bad < 0) {
        std.crypto.secureZero(u8, &key);
        return error.InvalidKey;
    }
    return key;
}

/// Clamps 32 random bytes into an X25519 private key (RFC 7748), as
/// `wg genkey` does.
pub fn clamp(k: *Key) void {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
}

pub fn generatePrivate(io: std.Io) Key {
    var k: Key = undefined;
    io.random(&k);
    clamp(&k);
    return k;
}

/// Public key for a private key (X25519 base-point multiplication; clamping
/// is applied by the scalar multiplication as wg does).
pub fn publicFromPrivate(priv: *const Key) Key {
    return std.crypto.dh.X25519.recoverPublicKey(priv.*);
}

pub fn isZero(k: *const Key) bool {
    var acc: u8 = 0;
    for (k) |b| acc |= b;
    return acc == 0;
}

test "base64 round trip and std agreement" {
    var k: Key = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i * 7 + 3);
    const t = encode(&k);
    var std_buf: [base64_len]u8 = undefined;
    const s = std.base64.standard.Encoder.encode(&std_buf, &k);
    try std.testing.expectEqualStrings(s, &t);
    try std.testing.expectEqualSlices(u8, &k, &(try decode(&t)));

    // Every value of every byte position.
    for (0..256) |v| {
        for (0..key_len) |pos| {
            var x: Key = @splat(0);
            x[pos] = @intCast(v);
            const e = encode(&x);
            const ss = std.base64.standard.Encoder.encode(&std_buf, &x);
            try std.testing.expectEqualStrings(ss, &e);
            try std.testing.expectEqualSlices(u8, &x, &(try decode(&e)));
        }
    }
}

test "decode rejects malformed keys" {
    const good = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    _ = try decode(good);
    try std.testing.expectError(error.InvalidKey, decode(good[0..43]));
    try std.testing.expectError(error.InvalidKey, decode(good ++ "="));
    try std.testing.expectError(error.InvalidKey, decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmkA"));
    try std.testing.expectError(error.InvalidKey, decode("yAnz5TF-lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
    try std.testing.expectError(error.InvalidKey, decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm =")); // space
    // Non-canonical: 'l' (37 = 0b100101) leaves nonzero padding bits.
    try std.testing.expectError(error.InvalidKey, decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBml="));
    try std.testing.expectError(error.InvalidKey, decode(""));
}

test "whitepaper-independent X25519 vector (RFC 7748 6.1)" {
    // Alice's private key from RFC 7748 section 6.1, and her public key.
    const priv_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pub_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    var priv: Key = undefined;
    var want: Key = undefined;
    _ = try std.fmt.hexToBytes(&priv, priv_hex);
    _ = try std.fmt.hexToBytes(&want, pub_hex);
    try std.testing.expectEqualSlices(u8, &want, &publicFromPrivate(&priv));
}
