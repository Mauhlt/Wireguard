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
src/netstack/         userspace TCP/IPv4 stack as a Tun (in-process tunnels)          (agent: netstack)
src/service/          Windows tunnel service (zwg installtunnel), control pipe, wg UAPI    (agent: service)
```

Dependencies point one way: device → session → noise → crypto; device → tun;
service → device, tun (design: tests/interop/README.md, "Elevation design").
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
// Key text (base64, 44 chars): device/keys.zig encode / decode, constant time.
pub fn hexTo(comptime n: usize, comptime s: []const u8) [n]u8;        // test-vector helper
```

## noise (src/noise)

Pure, no I/O, no clock reads. Callers pass `wall_ns: i96` (wall clock, only
for the TAI64N timestamp), `now: i64` (monotonic ns: rate limiting, cookie
ages) and a `std.Random` (use a CSPRNG, e.g. `std.Random.IoSource`) for
ephemerals, cookie nonces and cookie secrets. Not thread-safe: the device
serialises. A failed step never modifies the handshake.

Wire layouts (extern structs of byte arrays, align 1, comptime-asserted sizes;
first 4 bytes = LE u32 type, so non-zero reserved bytes are rejected; exact
lengths): `Initiation` (148, type 1), `Response` (92, type 2), `CookieReply`
(64, type 3). `messageType(bytes) ?MessageType` classifies a datagram
(transport = type 4, len >= 32). `X.parse(bytes) !*const X` views without copying.

```zig
Local.init(private) -> Local {private, public}
CookieChecker.init(&local.public)                          // one per device
  .check(msg_bytes, src_bytes, now, under_load, rng) -> .invalid | .ok | .need_cookie
  .createReply(msg_bytes, src_bytes, now, rng) -> CookieReply   // on .need_cookie
Handshake.init(&local, peer_public, psk)                   // one per peer; .cookie = CookieGenerator
  .createInitiation(&local, wall_ns, now, sender_index, rng) !Initiation   (macs filled)
consumeInitiationStatic(&local, *const Initiation) !InitiationStart  // -> .remote_static: look up peer
  peer.hs.consumeInitiation(&start, now) !void             // timestamp replay + flood check
  peer.hs.createResponse(now, sender_index, rng) !Response
  peer.hs.consumeResponse(&local, *const Response) !void   // device found hs by receiverIndex()
  peer.hs.deriveKeys() !session.Seed {send, recv, local_index, remote_index, is_initiator}
  peer.hs.cookie.consumeReply(*const CookieReply, now) !void
```
`.ok` under load means mac2 was valid; the device still applies its
per-source-IP handshake rate limiter. `src_bytes` is opaque to noise but must
be encoded the same way each time (recommended: IP bytes || BE16 port).
Constants: initiations accepted at most once per 1/50 s per peer
(`min_initiation_interval_ns`), cookie secret 120 s, stored cookie used for
115 s (120 - 5 s latency), timestamps whitened to 2^24 ns — all as the kernel.
Golden vectors: produced by an independent reference implementation (not in this repo; Zig-only rule); the recorded bytes live in src/noise/tests.zig.

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
it), endpoint roaming (update endpoint from authenticated packets), endpoint
DNS names looked up again while handshakes go unanswered or after a failed
lookup (resolver.zig: a detached lookup thread, deadlines, no ticks), handshake
rate limiting / under-load detection, UDP sockets (IPv4 + IPv6) and the main
event loop: waits on {UDP readable, TUN readable, earliest timer deadline};
outbound: TUN → route by dst IP → peer → encrypt → UDP; inbound: UDP →
type dispatch → noise / decrypt → check source IP against allowed IPs → TUN.
A small CLI `zwg` (up/down a .conf, show status like `wg show`, genkey/pubkey).

## tun (src/tun)

`Tun` interface: `open(name, mtu)`, `readable event handle` (for the device's
wait), `read(buf) ?[]u8`, `write(packet)`, `setAddress(cidr)`, `mtu`, `close`.
Backends: Windows (Wintun — a signed kernel driver; load wintun.dll at
runtime by full path after checking its Authenticode signer is WireGuard
LLC, do NOT ship it; document the exception: a userspace TUN on Windows
needs a signed driver), Linux (/dev/net/tun), macOS (utun via
PF_SYSTEM/SYSPROTO_CONTROL), iOS (NEPacketTunnelProvider packetFlow: a
callback adapter, no fd). Plus the test harness: known-answer tests for every
crypto/handshake step, a two-device in-process loopback test (no TUN: a fake
Tun), and a live interop test against the installed official WireGuard for
Windows (wg.exe / wireguard.exe), documented step by step (needs admin once).

## service (src/service, Windows only)

`zwg installtunnel` runs a tunnel as a LocalSystem service (full design:
tests/interop/README.md, "The tunnel service"). Its store is
`%ProgramFiles%\zwg` (the known folder, never the environment): only
administrators can create anything there, unlike %ProgramData%, where a user
could pre-create the folder and swap it for a junction under the elevated
installer. The installer resolves each store directory once, never through a
reparse point, verifies and secures that same handle and keeps it open
(no FILE_SHARE_DELETE) while it writes the files relative to it.

## Userspace netstack (src/netstack, `WireGuard.netstack`)

Goal (owner, 2026-11-14): Portal runs zwg in-process (no Wintun adapter,
no driver, no admin, no service). The hub owns UDP 51820 and accepts TCP
on 10.8.0.1:8420/8421 inside the tunnel; devices dial 10.8.0.1:8420. A
minimal TCP/IPv4 stack is the device's Tun. Pure Zig, std only, no C.

Threads and wiring (the device is unchanged):

```
Device.run (device thread)  --Tun.write-->  [inbound tun.queue.Channel]  --> stack thread
Device.run (device thread)  <--Tun.read---  [outbound tun.queue.Channel] <-- stack thread
stack thread: waits on {inbound handle, kick Waker, device.os.DeadlineTimer}
              with the earliest TCP deadline as timeout; runs input, timers, output
host threads: Stream / Listener calls under the stack mutex; blocking calls
              wait on a per-connection std.Io.Condition (with timeout)
```

No polling, no ticks: retransmit, delayed ACK, persist (zero window),
keepalive and TIME-WAIT are deadlines on the device clock (`.boot`).
A full ring drops the packet (like a NIC); TCP recovers.

Public API (`const ns = @import("WireGuard").netstack;`):

```zig
ns.Addr = device.ip.Addr                  // .v4 only for now (IPv6 kept in the types)
ns.Endpoint { addr: Addr, port: u16 }
ns.Limits { max_connections=64, max_listeners=8, send_buffer=256K, recv_buffer=256K,
            syn_backlog=16, accept_backlog=16, max_ooo_segments=32, ring_packets=512,
            time_wait_ns=2s, user_timeout_ns=60s }
ns.Options { address: Addr, mtu=1420, limits, keepalive_idle_ns: ?u64=null, icmp_echo=true }

// Everything in one call (what Portal embeds):
ns.Node.start(gpa, *device.Clock, device.Options, ns.Options) !*Node   // .stack, .device
node.destroy()                                                          // stops both, wipes

// Or by hand:
ns.Stack.create(gpa, *device.Clock, Options) !*Stack;  stack.tun() -> tun.Tun (give to Device.create)
stack.start() / stack.stop() / stack.destroy()
stack.input(packet) / stack.output(buf) ?[]u8 / stack.runTimers() ?i64   // manual drive (tests)

stack.listen(port) !Listener              // bound to Options.address only
stack.dial(Endpoint) !Stream              // returns at once (SYN sent)
stack.dialWait(Endpoint, timeout_ns: ?u64) !Stream
stack.readyHandle() WaitHandle; stack.clearReady()   // event-loop hosts
stack.stats() Stats

listener.accept() !Stream (WouldBlock) | acceptWait(timeout_ns) !Stream | close() | port()
stream.read(buf) !usize        // non-blocking; 0 = EOF; error.WouldBlock
stream.readWait(buf, timeout_ns) !usize
stream.write(data) !usize      // non-blocking; partial; WouldBlock when the send buffer is full
stream.writeAll(data, timeout_ns) !void
stream.waitConnected(timeout_ns) !void
stream.shutdown()              // FIN after buffered data
stream.close()                 // graceful, releases the handle (RST if unread data)
stream.abort()                 // RST, releases the handle
stream.status() Status { state, readable, writable, read_available, write_available }
stream.local() / remote() Endpoint
stream.reader(buf, timeout_ns) Stream.Reader   // .interface: std.Io.Reader, .err
stream.writer(buf, timeout_ns) Stream.Writer   // .interface: std.Io.Writer, .err
```

Errors: WouldBlock, Timeout (the call's own timeout; stream still usable),
Closed (handle closed / stale / stack gone), ConnectionRefused,
ConnectionReset, ConnectionTimedOut (Limits.user_timeout_ns), BrokenPipe
(write after shutdown). Handles are values (stack pointer + slot +
generation), so a stale handle can never touch a reused slot.

Shared code: `netstack.wire` is the one IPv4 / TCP / ICMP parser and
serializer and the Internet checksum (`Checksum`, `pseudoHeader`), used by
the stack, the tests and the fuzz targets; `wire.mssForMtu` is the one MSS
derivation. `netstack.testing` holds the packet-crafting fake peer
(`testing.Peer`) and `ImpairedTun` (seeded loss / reorder / duplication),
for unit tests, tests/netstack and fuzzers alike.

TCP: RFC 9293 state machine (both handshakes, FIN/RST, TIME-WAIT bounded
by Limits.time_wait_ns), MSS from the MTU (1420 -> 1380), window scale
(RFC 7323; SACK-permitted and timestamps parsed and ignored), RTO per
RFC 6298 with Karn's rule, fast retransmit / NewReno (RFC 5681/6582), zero
window probing, delayed ACK, no Nagle. ISNs: keyed SipHash over the
4-tuple plus a clock (RFC 6528); per-listener SYN backlog cap.
Validation: IHL, total length, header checksum, TCP data offset, options,
TCP checksum; fragments dropped; packets not addressed to Options.address
dropped. The device already drops inner packets whose source is not in
the peer's AllowedIPs. Memory: buffers allocated per established
connection, bounded by Limits (defaults: ~33 MiB worst case, rings ~1.4 MiB
idle); wiped when freed.
## Rules

* Pure Zig, std only (Wintun is the one runtime-loaded OS component).
* Secrets wiped after use; constant-time comparisons for MACs/tags.
* Everything bounded: no unbounded allocation from network input.
* Event-driven only.
* Each agent: unit tests for its module; `zig build test` must pass on main.
* Commit as the owner's git identity, no attribution trailers.
* Security review + interop sign-off before it replaces wireguard-go anywhere.
