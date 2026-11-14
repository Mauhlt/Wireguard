//! Shared primitives over std.crypto (owned by the noise agent). See DESIGN.md.
//!
//! Everything here is a thin, allocation-free wrapper that pins the exact
//! algorithm and parameter choices of WireGuard (whitepaper section 5.4):
//!
//!   DH      X25519 (RFC 7748), private keys clamped
//!   HASH    BLAKE2s-256 (RFC 7693)
//!   MAC     keyed BLAKE2s-128
//!   HMAC    HMAC (RFC 2104) over BLAKE2s-256, 64-byte block
//!   KDFn    t0 = HMAC(key, input), t1 = HMAC(t0, 0x1),
//!           ti = HMAC(t0, t(i-1) || i)          (n = 1, 2, 3)
//!   AEAD    ChaCha20-Poly1305 (RFC 8439), nonce = 4 zero bytes || LE64 counter
//!   XAEAD   XChaCha20-Poly1305, 24-byte random nonce (cookie replies)
//!   TAI64N  12 bytes: BE64 (2^62 + 10 + unix seconds) || BE32 nanoseconds
//!
//! Secrets: callers own their buffers and must `wipe` them; every function
//! here wipes its own intermediates. Comparisons of secret/authenticator
//! values go through `eql` / `isZero` (constant time).
const std = @import("std");

const X25519 = std.crypto.dh.X25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s256);
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_len = 32;
pub const hash_len = 32;
pub const mac_len = 16;
/// Poly1305 tag appended to every AEAD ciphertext.
pub const tag_len = 16;
pub const xnonce_len = 24;
pub const tai64n_len = 12;

/// Clamped X25519 scalar (see `clampPrivateKey`).
pub const PrivateKey = [key_len]u8;
pub const PublicKey = [key_len]u8;
/// All zero means "no preshared key" (the protocol then mixes in 32 zero
/// bytes, which is exactly what an all-zero value does).
pub const PresharedKey = [key_len]u8;
pub const SymKey = [key_len]u8;
pub const Tai64n = [tai64n_len]u8;

pub const AuthError = error{AuthenticationFailed};

// ---------------------------------------------------------------- keys / DH

/// RFC 7748 clamping, as `wg genkey` does.
pub fn clampPrivateKey(k: *PrivateKey) void {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
}

/// A fresh clamped private key from the CSPRNG behind `io`.
pub fn generatePrivateKey(io: std.Io) PrivateKey {
    var k: PrivateKey = undefined;
    io.random(&k);
    clampPrivateKey(&k);
    return k;
}

/// X25519(priv, 9). `priv` is clamped internally, so an unclamped key gives
/// the same result as its clamped form (matches `wg pubkey`).
pub fn publicKey(priv: PrivateKey) PublicKey {
    return X25519.recoverPublicKey(priv);
}

/// X25519(priv, pub_). Fails if the result is all zero (low-order public
/// key); WireGuard rejects the handshake in that case.
pub fn dh(priv: PrivateKey, pub_: PublicKey) error{IdentityElement}![32]u8 {
    return X25519.scalarmult(priv, pub_) catch return error.IdentityElement;
}

// ------------------------------------------------------- hashing / MAC / KDF

/// BLAKE2s-256 over the concatenation of `parts`.
pub fn hash(parts: []const []const u8) [hash_len]u8 {
    var h = Blake2s256.init(.{});
    for (parts) |p| h.update(p);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    wipe(&h);
    return out;
}

/// Keyed BLAKE2s with a 16-byte output over the concatenation of `parts`.
/// `key` must be 1..32 bytes (WireGuard always uses 32).
pub fn mac(key: []const u8, parts: []const []const u8) [mac_len]u8 {
    std.debug.assert(key.len >= 1 and key.len <= 32);
    var h = Blake2s128.init(.{ .key = key });
    for (parts) |p| h.update(p);
    var out: [mac_len]u8 = undefined;
    h.final(&out);
    wipe(&h);
    return out;
}

/// HMAC-BLAKE2s-256 over the concatenation of `parts`.
pub fn hmacParts(key: []const u8, parts: []const []const u8) [hash_len]u8 {
    var h = HmacBlake2s.init(key);
    for (parts) |p| h.update(p);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    wipe(&h);
    return out;
}

/// HMAC-BLAKE2s-256(key, data).
pub fn hmac(key: []const u8, data: []const u8) [hash_len]u8 {
    return hmacParts(key, &.{data});
}

/// Whitepaper KDF_n: n 32-byte outputs keyed by `key` (a chaining key).
/// The caller wipes the result.
pub fn kdf(comptime n: comptime_int, key: *const [key_len]u8, input: []const u8) [n][key_len]u8 {
    comptime std.debug.assert(n >= 1 and n <= 3);
    var t0 = hmac(key, input);
    defer wipe(&t0);
    var out: [n][key_len]u8 = undefined;
    out[0] = hmac(&t0, &.{1});
    inline for (1..n) |i| {
        out[i] = hmacParts(&t0, &.{ &out[i - 1], &.{@as(u8, i + 1)} });
    }
    return out;
}

pub fn kdf1(key: *const [key_len]u8, input: []const u8) [key_len]u8 {
    var out = kdf(1, key, input);
    defer wipe(&out); // runs after the result is copied out
    return out[0];
}
pub fn kdf2(key: *const [key_len]u8, input: []const u8) [2][key_len]u8 {
    return kdf(2, key, input);
}
pub fn kdf3(key: *const [key_len]u8, input: []const u8) [3][key_len]u8 {
    return kdf(3, key, input);
}

// --------------------------------------------------------------------- AEAD

/// The 96-bit ChaCha20-Poly1305 nonce WireGuard uses: 32 zero bits followed
/// by the little-endian 64-bit counter.
pub fn aeadNonce(counter: u64) [12]u8 {
    var n: [12]u8 = @splat(0);
    std.mem.writeInt(u64, n[4..12], counter, .little);
    return n;
}

/// out = ChaCha20Poly1305(key, counter, plain, ad) || tag.
/// `out.len` must be `plain.len + tag_len`. `out[0..plain.len]` may be
/// exactly `plain` (in place) but must not partially overlap it.
pub fn aeadEncrypt(out: []u8, key: *const SymKey, counter: u64, plain: []const u8, ad: []const u8) void {
    std.debug.assert(out.len == plain.len + tag_len);
    ChaCha20Poly1305.encrypt(out[0..plain.len], out[plain.len..][0..tag_len], plain, ad, aeadNonce(counter), key.*);
}

/// Inverse of `aeadEncrypt`. `sealed` = ciphertext || tag; `out.len` must be
/// `sealed.len - tag_len` (else AuthenticationFailed). In place
/// (out == sealed[0..out.len]) is allowed. On failure `out` is zeroed.
pub fn aeadDecrypt(out: []u8, key: *const SymKey, counter: u64, sealed: []const u8, ad: []const u8) AuthError!void {
    if (sealed.len < tag_len or out.len != sealed.len - tag_len) return error.AuthenticationFailed;
    const n = out.len;
    ChaCha20Poly1305.decrypt(out, sealed[0..n], sealed[n..][0..tag_len].*, ad, aeadNonce(counter), key.*) catch {
        std.crypto.secureZero(u8, out);
        return error.AuthenticationFailed;
    };
}

/// out = XChaCha20Poly1305(key, nonce, plain, ad) || tag. Buffer rules as `aeadEncrypt`.
pub fn xaeadEncrypt(out: []u8, key: *const SymKey, nonce: *const [xnonce_len]u8, plain: []const u8, ad: []const u8) void {
    std.debug.assert(out.len == plain.len + tag_len);
    XChaCha20Poly1305.encrypt(out[0..plain.len], out[plain.len..][0..tag_len], plain, ad, nonce.*, key.*);
}

/// Inverse of `xaeadEncrypt`. Buffer rules as `aeadDecrypt`.
pub fn xaeadDecrypt(out: []u8, key: *const SymKey, nonce: *const [xnonce_len]u8, sealed: []const u8, ad: []const u8) AuthError!void {
    if (sealed.len < tag_len or out.len != sealed.len - tag_len) return error.AuthenticationFailed;
    const n = out.len;
    XChaCha20Poly1305.decrypt(out, sealed[0..n], sealed[n..][0..tag_len].*, ad, nonce.*, key.*) catch {
        std.crypto.secureZero(u8, out);
        return error.AuthenticationFailed;
    };
}

// ------------------------------------------------------------------- TAI64N

/// TAI64N label of a wall-clock time in nanoseconds since the Unix epoch.
/// Like the kernel and wireguard-go, the TAI-UTC offset is the fixed 10 s of
/// the TAI64 spec (no leap-second table); only monotonicity matters to peers.
/// Times before 1970 clamp to the epoch. No whitening here (see noise).
pub fn tai64n(now_ns: i96) Tai64n {
    const t: u96 = if (now_ns < 0) 0 else @intCast(now_ns);
    const secs: u64 = @intCast(t / std.time.ns_per_s);
    const nsec: u32 = @intCast(t % std.time.ns_per_s);
    var out: Tai64n = undefined;
    std.mem.writeInt(u64, out[0..8], 0x400000000000000a +% secs, .big);
    std.mem.writeInt(u32, out[8..12], nsec, .big);
    return out;
}

/// Constant-time "a > b" for two TAI64N labels (big-endian byte strings).
pub fn tai64nAfter(a: *const Tai64n, b: *const Tai64n) bool {
    return std.crypto.timing_safe.compare(u8, a, b, .big) == .gt;
}

// ------------------------------------------------------- constant time / wipe

/// Constant-time equality of two equal-length byte arrays (MACs, keys, tags).
pub fn eql(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool {
    return std.crypto.timing_safe.eql([n]u8, a.*, b.*);
}

/// Constant-time all-zero test (e.g. "no preshared key", "no cookie").
pub fn isZero(comptime n: usize, a: *const [n]u8) bool {
    return eql(n, a, &@as([n]u8, @splat(0)));
}

/// Zero the memory behind any single-item pointer or slice in a way the
/// optimizer cannot remove. Use for keys, chaining keys, hashes, hash/HMAC
/// states and whole structs holding them.
pub fn wipe(ptr: anytype) void {
    const info = @typeInfo(@TypeOf(ptr)).pointer;
    switch (info.size) {
        .one => std.crypto.secureZero(u8, std.mem.asBytes(ptr)),
        .slice => std.crypto.secureZero(u8, std.mem.sliceAsBytes(ptr)),
        else => @compileError("wipe: need a single-item pointer or a slice"),
    }
}

/// Alias for the name used in DESIGN.md.
pub const secureZero = wipe;

/// Comptime hex literal to bytes (test vectors).
pub fn hexTo(comptime n: usize, comptime s: []const u8) [n]u8 {
    const bytes = comptime blk: {
        var out: [n]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        break :blk out;
    };
    return bytes;
}

// ==================================================================== tests

const testing = std.testing;

test "X25519: RFC 7748 section 6.1 (Alice/Bob)" {
    const a_priv = hexTo(32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const a_pub = hexTo(32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const b_priv = hexTo(32, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const b_pub = hexTo(32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = hexTo(32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    try testing.expectEqual(a_pub, publicKey(a_priv));
    try testing.expectEqual(b_pub, publicKey(b_priv));
    try testing.expectEqual(shared, try dh(a_priv, b_pub));
    try testing.expectEqual(shared, try dh(b_priv, a_pub));
}

test "X25519: low-order public keys are rejected" {
    const priv = hexTo(32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const zero: PublicKey = @splat(0);
    try testing.expectError(error.IdentityElement, dh(priv, zero));
    var one: PublicKey = @splat(0);
    one[0] = 1;
    try testing.expectError(error.IdentityElement, dh(priv, one));
}

test "BLAKE2s-256: RFC 7693 appendix B ('abc'), split parts" {
    const want = hexTo(32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    try testing.expectEqual(want, hash(&.{"abc"}));
    try testing.expectEqual(want, hash(&.{ "a", "", "bc" }));
}

test "WireGuard initial chaining key and hash" {
    // Ci = Hash(construction), Hi = Hash(Ci || identifier); cross-checked
    // with an independent BLAKE2s reference (recorded values).
    const ck = hash(&.{"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"});
    try testing.expectEqual(hexTo(32, "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"), ck);
    const h = hash(&.{ &ck, "WireGuard v1 zx2c4 Jason@zx2c4.com" });
    try testing.expectEqual(hexTo(32, "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"), h);
}

test "keyed BLAKE2s-128, HMAC-BLAKE2s, KDF: Python hashlib/hmac cross-check" {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i);
    // hashlib.blake2s(b"hello", key=bytes(range(32)), digest_size=16)
    try testing.expectEqual(hexTo(16, "1f946dc212a39570bc06fd378517a91e"), mac(&k, &.{ "hel", "lo" }));
    // hmac.new(bytes(range(32)), b"hello", hashlib.blake2s)
    try testing.expectEqual(hexTo(32, "ca3386d2021b8c299b42476827e7e729b48255da7aee060261072790ea0fc3fa"), hmac(&k, "hello"));
    // KDF3 per the whitepaper definition, built from Python hmac.
    const t = kdf3(&k, "hello");
    try testing.expectEqual(hexTo(32, "0ce1e8e88bc61a7d2e1ea4e73fbe496686adf8073228a74cdb9676e62fc6ad2b"), t[0]);
    try testing.expectEqual(hexTo(32, "cc5a6bea52f8d4c7425bbc06d713fc648928e873d0718d95718f9df74c9ed199"), t[1]);
    try testing.expectEqual(hexTo(32, "613df7c55d617a02a4d5550d18c63f383a9607c32504723d8ea6f9b07d013a55"), t[2]);
    try testing.expectEqual(t[0], kdf1(&k, "hello"));
    try testing.expectEqual(t[0], kdf2(&k, "hello")[0]);
    try testing.expectEqual(t[1], kdf2(&k, "hello")[1]);
}

test "ChaCha20-Poly1305: RFC 8439 2.8.2, WireGuard nonce layout, wrapper" {
    const key = hexTo(32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = hexTo(12, "50515253c0c1c2c3c4c5c6c7");
    // The RFC nonce (07000000 4041..47) is not WireGuard-shaped, so check the
    // primitive directly, then the wrapper.
    var c: [plain.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&c, &tag, plain, &ad, hexTo(12, "070000004041424344454647"), key);
    try testing.expectEqual(hexTo(16, "1ae10b594f09e26a7e902ecbd0600691"), tag);
    try testing.expectEqualSlices(u8, &hexTo(16, "d31a8d34648e60db7b86afbc53ef7ec2"), c[0..16]);

    try testing.expectEqual(hexTo(12, "000000000807060504030201"), aeadNonce(0x0102030405060708));
    var sealed: [plain.len + tag_len]u8 = undefined;
    aeadEncrypt(&sealed, &key, 7, plain, &ad);
    var back: [plain.len]u8 = undefined;
    try aeadDecrypt(&back, &key, 7, &sealed, &ad);
    try testing.expectEqualStrings(plain, &back);
    try testing.expectError(error.AuthenticationFailed, aeadDecrypt(&back, &key, 8, &sealed, &ad));
    try testing.expect(isZero(back.len, &back));
    // In place, both directions.
    var buf = sealed;
    try aeadDecrypt(buf[0..plain.len], &key, 7, &buf, &ad);
    try testing.expectEqualStrings(plain, buf[0..plain.len]);
    var buf2: [plain.len + tag_len]u8 = undefined;
    @memcpy(buf2[0..plain.len], plain);
    aeadEncrypt(&buf2, &key, 7, buf2[0..plain.len], &ad);
    try testing.expectEqual(sealed, buf2);
    // Empty plaintext (keepalive shape) and too-short input.
    var tag_only: [tag_len]u8 = undefined;
    aeadEncrypt(&tag_only, &key, 0, "", "");
    try aeadDecrypt(&.{}, &key, 0, &tag_only, "");
    try testing.expectError(error.AuthenticationFailed, aeadDecrypt(&.{}, &key, 0, tag_only[0..15], ""));
}

test "XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 appendix A.3.1" {
    const key = hexTo(32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = hexTo(24, "404142434445464748494a4b4c4d4e4f5051525354555657");
    const ad = hexTo(12, "50515253c0c1c2c3c4c5c6c7");
    const plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var sealed: [plain.len + tag_len]u8 = undefined;
    xaeadEncrypt(&sealed, &key, &nonce, plain, &ad);
    try testing.expectEqual(hexTo(16, "c0875924c1c7987947deafd8780acf49"), sealed[plain.len..][0..16].*);
    try testing.expectEqualSlices(u8, &hexTo(16, "bd6d179d3e83d43b9576579493c0e939"), sealed[0..16]);
    var back: [plain.len]u8 = undefined;
    try xaeadDecrypt(&back, &key, &nonce, &sealed, &ad);
    try testing.expectEqualStrings(plain, &back);
    sealed[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, xaeadDecrypt(&back, &key, &nonce, &sealed, &ad));
}

test "TAI64N layout and ordering" {
    // 1_700_000_000 = 0x6553f100; + 0x400000000000000a. 123456789 = 0x075bcd15.
    try testing.expectEqual(hexTo(12, "400000006553f10a075bcd15"), tai64n(1_700_000_000 * std.time.ns_per_s + 123_456_789));
    try testing.expectEqual(hexTo(12, "400000000000000a00000000"), tai64n(0));
    try testing.expectEqual(hexTo(12, "400000000000000a00000000"), tai64n(-5));
    const a = tai64n(10);
    const b = tai64n(11);
    const c = tai64n(2 * std.time.ns_per_s);
    try testing.expect(tai64nAfter(&b, &a));
    try testing.expect(!tai64nAfter(&a, &b));
    try testing.expect(!tai64nAfter(&a, &a));
    try testing.expect(tai64nAfter(&c, &b));
}

test "wipe zeroes structs, arrays and slices" {
    var a: [5]u8 = @splat(0xAA);
    wipe(&a);
    try testing.expect(isZero(5, &a));
    var s = struct { x: u32, k: [3]u8 }{ .x = 7, .k = .{ 1, 2, 3 } };
    wipe(&s);
    try testing.expectEqual(@as(u32, 0), s.x);
    try testing.expectEqual([3]u8{ 0, 0, 0 }, s.k);
    var arr: [4]u16 = .{ 1, 2, 3, 4 };
    wipe(arr[1..]);
    try testing.expectEqual([4]u16{ 1, 0, 0, 0 }, arr);
}
