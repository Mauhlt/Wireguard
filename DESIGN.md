# WireGuard in Zig — design contract

Goal (owner, 2026-11-12): a complete WireGuard implementation in pure Zig,
wire-compatible with the official implementations (kernel, wireguard-go,
WireGuard for Windows), to replace wireguard-go (e.g. in Portal's iPhone
tunnel) once it is audited and interop-tested. Std only (std.crypto has
X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s). Event-driven: no
polling, no fixed ticks; timers are expressed as "next deadline" values.

Spec: the WireGuard whitepaper (Donenfeld, NDSS 2017, rev. e2da747) and the
protocol page at wireguard.com/protocol. Where they leave something open, match
the Linux kernel / wireguard-go behaviour and say so in a comment.

## Modules (one agent each, one branch each)

```
src/root.zig          re-exports the modules below
src/crypto.zig        shared primitives (owned by the noise agent; others only import)
src/noise/            handshake: messages 1/2, cookie reply, MAC1/MAC2, state machine  (agent: noise)
src/session/          keypairs, transport data, counters + replay window, timers           (agent: session)
src/device/           peers, allowed-IPs trie, config (.conf), UDP, packet routing, CLI    (agent: device)
src/tun/              TUN per OS + interop/KAT harness                                     (agent: tun)
```

Dependencies point one way: device → session → noise → crypto; device → tun.
No module reaches into another's internals; only the public API below.

## Shared types (src/crypto.zig, owned by noise agent, frozen early)

As implemented (all allocation-free; see the file's doc comments for buffer rules):

```zig
pub const key_len = 32;  hash_len = 32;  mac_len = 16;  tag_len = 16;  xnonce_len = 24;  tai64n_len = 12;
pub const PrivateKey = [32]u8;   // clamped X25519 scalar
pub const PublicKey  = [32]u8;
pub const PresharedKey = [32]u8; // all zero = none
pub const SymKey = [32]u8;
pub const Tai64n = [12]u8;
pub const AuthError = error{AuthenticationFailed};
pub fn clampPrivateKey(k: *PrivateKey) void;
pub fn generatePrivateKey(io: std.Io) PrivateKey;                    // clamped
pub fn publicKey(priv: PrivateKey) PublicKey;                         // clamps internally, = `wg pubkey`
pub fn dh(priv: PrivateKey, pub_: PublicKey) error{IdentityElement}![32]u8;
pub fn hash(parts: []const []const u8) [32]u8;                       // BLAKE2s-256
pub fn mac(key: []const u8, parts: []const []const u8) [16]u8;       // keyed BLAKE2s-128
pub fn hmac(key: []const u8, data: []const u8) [32]u8;               // HMAC-BLAKE2s
pub fn hmacParts(key: []const u8, parts: []const []const u8) [32]u8;
pub fn kdf1(key: *const [32]u8, input: []const u8) [32]u8;           // whitepaper KDF_n
pub fn kdf2(key: *const [32]u8, input: []const u8) [2][32]u8;
pub fn kdf3(key: *const [32]u8, input: []const u8) [3][32]u8;
pub fn aeadNonce(counter: u64) [12]u8;                                // 4 zero bytes || LE64
// out.len == plain.len + 16; out may alias plain exactly (in place)
pub fn aeadEncrypt(out: []u8, key: *const SymKey, counter: u64, plain: []const u8, ad: []const u8) void;
// out.len == sealed.len - 16; in place allowed; out zeroed on failure
pub fn aeadDecrypt(out: []u8, key: *const SymKey, counter: u64, sealed: []const u8, ad: []const u8) AuthError!void;
pub fn xaeadEncrypt(out: []u8, key: *const SymKey, nonce: *const [24]u8, plain: []const u8, ad: []const u8) void;
pub fn xaeadDecrypt(out: []u8, key: *const SymKey, nonce: *const [24]u8, sealed: []const u8, ad: []const u8) AuthError!void;
pub fn tai64n(now_ns: i96) Tai64n;                                    // wall clock, ns since Unix epoch
pub fn tai64nAfter(a: *const Tai64n, b: *const Tai64n) bool;          // constant-time a > b
pub fn eql(comptime n: usize, a: *const [n]u8, b: *const [n]u8) bool; // constant time
pub fn isZero(comptime n: usize, a: *const [n]u8) bool;               // constant time
pub fn wipe(ptr: anytype) void;                                       // *T or []T; secureZero is an alias
pub const key_b64_len = 44;
pub fn keyToBase64(key: *const [32]u8) [44]u8;                        // wg / .conf format
pub fn keyFromBase64(s: []const u8) error{InvalidKey}![32]u8;          // strict, canonical only
pub fn hexTo(comptime n: usize, comptime s: []const u8) [n]u8;        // test-vector helper
```

## noise (src/noise)

Pure, no I/O, no clock reads (time passed in). Message structs with exact wire
layout (little-endian, type byte + 3 reserved zero bytes):
`Initiation` (148 B, type 1), `Response` (92 B, type 2), `CookieReply` (64 B,
type 3). API: `Handshake.init(local static, peer static, psk)`,
`createInitiation(now, sender_index) -> Initiation`,
`consumeInitiation(msg, now) -> peer static + state`, `createResponse`,
`consumeResponse`, `deriveKeys() -> session.Keypair seeds {send, recv, local_index, remote_index}`.
MAC1 always; MAC2 + cookie mechanism (`CookieChecker`, `CookieGenerator`, under-load
handling with a caller-supplied `under_load: bool`). Replay protection on
initiations via TAI64N monotonic timestamp per peer. Constant-time compares.
Known-answer tests against published vectors / values produced by `wg`.

## session (src/session)

`Keypair { send: SymKey, recv: SymKey, local_index: u32, remote_index: u32, created: i64, is_initiator }`.
Transport data message (type 4): 16-byte header + ChaCha20Poly1305 ciphertext,
plaintext zero-padded to a multiple of 16, 64-bit little-endian counter as nonce.
`encrypt(keypair, plaintext, out) !usize`, `decrypt(keypairs, packet, out) !struct{ peer_index, len }`.
Replay window: RFC 6479-style bitmap, window ≥ 2048 (kernel uses 8192 - 64).
Keypair rotation: current / previous / next per peer.
Timers as a pure state machine per peer: constants REKEY_AFTER_MESSAGES = 2^60,
REJECT_AFTER_MESSAGES = 2^64 - 2^13 - 1, REKEY_AFTER_TIME = 120 s,
REJECT_AFTER_TIME = 180 s, REKEY_ATTEMPT_TIME = 90 s, REKEY_TIMEOUT = 5 s (+ jitter),
KEEPALIVE_TIMEOUT = 10 s, COOKIE_SECRET_MAX_AGE = 120 s, persistent keepalive.
API: `Timers.on(event, now)` for events (data sent/received, handshake
initiated/completed, any authenticated packet), `Timers.next(now) ?i64` = the
next deadline, `Timers.due(now) -> actions` (send keepalive, initiate handshake,
expire keys, zero keys). The device waits until that deadline; nothing ticks.

## device (src/device)

Peers (public key, psk, endpoint, allowed IPs, persistent keepalive), a
cryptokey-routing table (longest-prefix-match trie for IPv4 + IPv6), the
`[Interface]/[Peer]` .conf format (as wg-quick / WireGuard for Windows write
it), endpoint roaming (update endpoint from authenticated packets), handshake
rate limiting / under-load detection, UDP sockets (IPv4 + IPv6) and the main
event loop: waits on {UDP readable, TUN readable, earliest timer deadline};
outbound: TUN → route by dst IP → peer → encrypt → UDP; inbound: UDP →
type dispatch → noise / decrypt → check source IP against allowed IPs → TUN.
A small CLI `zwg` (up/down a .conf, show status like `wg show`, genkey/pubkey).

## tun (src/tun)

`Tun` interface: `open(name, mtu)`, `readable event handle` (for the device's
wait), `read(buf) ?[]u8`, `write(packet)`, `setAddress(cidr)`, `mtu`, `close`.
Backends: Windows (Wintun — a signed kernel driver; load wintun.dll at
runtime, do NOT ship it; document the exception: a userspace TUN on Windows
needs a signed driver), Linux (/dev/net/tun), macOS (utun via
PF_SYSTEM/SYSPROTO_CONTROL), iOS (NEPacketTunnelProvider packetFlow: a
callback adapter, no fd). Plus the test harness: known-answer tests for every
crypto/handshake step, a two-device in-process loopback test (no TUN: a fake
Tun), and a live interop test against the installed official WireGuard for
Windows (wg.exe / wireguard.exe), documented step by step (needs admin once).

## Rules

* Pure Zig, std only (Wintun is the one runtime-loaded OS component).
* Secrets wiped after use; constant-time comparisons for MACs/tags.
* Everything bounded: no unbounded allocation from network input.
* Event-driven only.
* Each agent: unit tests for its module; `zig build test` must pass on main.
* Commit as the owner's git identity, no attribution trailers.
* Security review + interop sign-off before it replaces wireguard-go anywhere.
