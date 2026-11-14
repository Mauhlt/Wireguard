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
src/netstack/         userspace TCP/IP stack (IPv4 + IPv6) as a Tun (in-process)         (agent: netstack)
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
`Device.setPeers` replaces the peer table while the tunnel runs (any thread;
applied on the loop thread through its waker, all checks and allocations
before the first change): kept peers keep their sessions, removed ones are
wiped, a new preshared key drops that peer's sessions.

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
minimal TCP/IP stack (IPv4 and IPv6, see "IPv6" below) is the device's
Tun. Pure Zig, std only, no C.

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
ns.Addr = device.ip.Addr                  // .v4 or .v6
ns.Endpoint { addr: Addr, port: u16 }
ns.Limits { max_connections=64, max_listeners=8, send_buffer=256K, recv_buffer=256K,
            syn_backlog=16, accept_backlog=16, max_ooo_segments=32, ring_packets=512,
            time_wait_ns=2s, user_timeout_ns=60s, bulk_unsent_lowat=64K }
ns.Priority = enum { interactive, bulk }
ns.Options { address: Addr, address6: ?Addr=null, mtu=1420, limits, keepalive_idle_ns: ?u64=null, icmp_echo=true }
          // address: IPv4 (or IPv6 for a v6-only stack); address6: IPv6 next to an IPv4 address

// Everything in one call (what Portal embeds):
ns.Node.start(gpa, *device.Clock, device.Options, ns.Options) !*Node   // .stack, .device
node.destroy()                                                          // stops both, wipes

// Or by hand:
ns.Stack.create(gpa, *device.Clock, Options) !*Stack;  stack.tun() -> tun.Tun (give to Device.create)
stack.start() / stack.stop() / stack.destroy()
stack.input(packet) / stack.output(buf) ?[]u8 / stack.runTimers() ?i64   // manual drive (tests)

stack.listen(port) !Listener              // on every configured address (address and address6)
stack.dial(Endpoint) !Stream              // returns at once (SYN sent); .interactive; our address by the destination's family
stack.dialWith(Endpoint, Priority) !Stream
stack.dialWait(Endpoint, timeout_ns: ?u64) !Stream
stack.readyHandle() WaitHandle; stack.clearReady()   // event-loop hosts
stack.setReadyCallback(ctx, ?*const fn (?*anyopaque) void) // called when readyHandle is signalled
stack.abortAll()                          // RST everything, wake every blocked call
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
stream.setPriority(.interactive | .bulk)  // default .interactive
stream.status() Status { state, readable, writable, read_available, write_available }
stream.local() / remote() Endpoint
stream.reader(buf, timeout_ns) Stream.Reader   // .interface: std.Io.Reader, .err
stream.writer(buf, timeout_ns) Stream.Writer   // .interface: std.Io.Writer, .err
```

Interactive vs bulk (a large transfer must never delay a keystroke; bytes in
one stream are ordered, so Portal uses separate connections). Output
scheduler, per packet: control replies (RST, ICMP), then interactive
streams (any segment: data, retransmissions, ACKs), then bulk streams'
control-only segments (pure ACKs, window updates, SYN, bare FIN), then
bulk data; round-robin inside each class. Bulk data may occupy at most
half of the stack -> device ring, so an interactive packet always finds
room. A bulk stream accepts writes only while it has fewer than
`bulk_unsent_lowat` unsent bytes (like TCP_NOTSENT_LOWAT), so its backlog
stays in the application. No Nagle, no delayed sends for anything.

The ready callback runs on the stack thread (or on a host thread whose
call changed state, e.g. close), after the stack lock is released; it
must be quick, must not block and must not call back into the stack.

Errors: WouldBlock, Timeout (the call's own timeout; stream still usable),
Closed (handle closed / stale / stack gone), ConnectionRefused,
ConnectionReset, ConnectionTimedOut (Limits.user_timeout_ns), BrokenPipe
(write after shutdown). Handles are values (stack pointer + slot +
generation), so a stale handle can never touch a reused slot.

Shared code: `netstack.wire` is the one IPv4 / IPv6 / TCP / ICMP / ICMPv6
parser and serializer and the Internet checksum (`Checksum`,
`pseudoHeader` for either family), used by the stack, the tests and the
fuzz targets: `parseIp` / `parseTcp` / `buildTcp` / `writeIpHeader` take
either family; `wire.mssFor(addr, mtu)` is the one MSS derivation.
`netstack.testing` holds the packet-crafting fake peer (`testing.Peer`,
either family), `icmpPacket`, `withExtHeaders6` and `ImpairedTun`
(seeded loss / reorder / duplication, either family), for unit tests,
tests/netstack and fuzzers alike.

TCP: RFC 9293 state machine (both handshakes, simultaneous open, FIN/RST,
TIME-WAIT bounded by Limits.time_wait_ns), MSS from the MTU (1420 ->
1380 over IPv4, 1360 over IPv6), window scale (RFC 7323; timestamps parsed
and ignored), RTO per RFC 6298 with Karn's rule, SACK (below), NewReno
(RFC 5681/6582) when the peer has no SACK, Limited Transmit (RFC 3042),
Early Retransmit (RFC 5827), one duplicate ACK per out-of-order segment,
RFC 5961 is implemented: an in-window RST that is not exactly rcv_nxt
and any SYN on a synchronized connection get a challenge ACK, only an
exact RST resets; tail loss probe for interactive streams (below); zero
window probing and keepalive with an out-of-window probe (snd_una - 1),
delayed ACK (every 2nd segment / 40 ms), receiver and sender SWS
avoidance, no Nagle. Pure ACKs carry snd_max, not snd_nxt (as BSD): after
an RTO rolls snd_nxt back, a peer that already has everything would drop
an ACK at snd_nxt as unacceptable, and two such peers deadlock. ISNs:
keyed SipHash-2-4 over the 4-tuple plus a 4 us clock (RFC 6528); per-
listener SYN backlog cap; half-open connections get no buffers.

Minimum RTO: 200 ms, not RFC 6298's 1 s. A deliberate deviation (Linux
does the same): both ends are ours, one hop through the tunnel, and a
1 s floor would stall a stream for a second on every timeout.

SACK (RFC 2018, recovery per RFC 6675): SACK-permitted is offered on our
SYN and echoed on a SYN-ACK only if the peer's SYN offered it. Receiver:
ACKs carry up to 4 blocks (all the 40-byte option space allows; the
window-scale option is only on SYNs, which carry no blocks), built from
the out-of-order ranges, the most recently changed first. Sender: a
scoreboard of at most 16 SACKed ranges per connection (sorted, disjoint,
inside [snd_una, snd_max]); every block is validated (start < end, inside
[snd_una, snd_max], not longer than what is in flight; partly below
snd_una is clipped, D-SACK and anything else is ignored and counted in
Stats.sack_blocks_ignored). Work per ACK is bounded: at most 4 blocks,
each merged into at most 16 ranges; ranges are sequence numbers, buffers
are never split, so there is no "SACK Panic"-style MSS underflow or
fragmentation. When a block does not fit a full scoreboard the
connection uses NewReno until the scoreboard empties, never more memory.
With SACK, RACK (below) decides what is lost; without SACK information,
recovery starts on DupThresh duplicate ACKs (NewReno). In recovery cwnd =
ssthresh = FlightSize / 2, and while cwnd - pipe >= 1 MSS the sender
sends NextSeg: the first segment RACK marked lost, else new data; pipe
counts bytes neither SACKed nor lost. Reneging (allowed by RFC 2018):
data is freed only by the cumulative ACK, and the scoreboard and RACK's
delivered marks are discarded on every RTO.

RACK-TLP (RFC 8985, src/netstack/rack.zig): every data transmission is
recorded in a bounded per-connection ring (at most 256 records of start,
end, last transmit time, flags; no per-segment allocation; past the cap
new data is folded into the last record with the newer time, which only
delays detection). Each ACK marks the records it cumulatively ACKs or
SACKs as delivered; the most recently sent delivered one sets RACK.xmit_ts,
end_seq and rtt (a retransmission ACKed faster than min RTT is ambiguous
and ignored). A record sent before it is lost once now >= its transmit
time + RACK.rtt + reo_wnd; the earliest pending candidate is the RACK
reorder timer, a deadline in the connection's single next-deadline
function. Retransmissions get new timestamps, so a lost retransmission is
detected by later deliveries instead of the RTO. reo_wnd = min_RTT / 4 *
reo_wnd_mult, capped at SRTT, and 0 while recovering before any
reordering has been seen. The RTO marks everything outstanding lost. RACK-TLP
congestion response (RFC 8985 7.4): a probe's fate is decided by the ACK
that covers it; a D-SACK of the probe means the original had arrived (no
reduction, Stats.tlp_unneeded); a cumulative ACK without one means the
probe repaired a lost tail segment: ssthresh = cwnd = cwnd / 2, once per
episode, skipped when a recovery during the episode already reduced it
(Stats.tlp_loss_repairs). TLP
(the probe of RACK-TLP) stays limited to interactive streams; bulk
streams have enough data in flight for RACK to detect tail losses.

D-SACK (RFC 2883): the receiver reports a duplicate segment (entirely
below rcv_nxt, the old part of an overlapping one, or one already held
out of order) as the first SACK block of its next ACK, once. The sender
recognises a D-SACK (first block below the segment's cumulative ACK, or
inside the second block) and validates it: non-empty, at most 64 KiB,
within one send buffer below snd_una up to snd_max; anything else is
counted in Stats.sack_blocks_ignored. A D-SACK raises reo_wnd_mult by
one, at most once per round trip (snd_una must pass the previous round's
snd_max, so a flood while idle counts once), up to 16; after 16
recoveries without one it returns to 1. Spurious retransmission undo
(RFC 3708 style): when every retransmission of the last recovery comes
back D-SACKed, the window cut is undone (cwnd and ssthresh back to their
values before it, never higher), at most once per episode and once per
second; an RTO disables undo for its episode.

Tail loss probe (RFC 8985 TLP), interactive streams only: when the last
segment of a burst is outstanding and nothing else is queued, a probe
deadline is armed at max(2 * SRTT, 10 ms), below the RTO. On expiry the
last segment is sent again (no cwnd change); its ACK, or the SACK of it,
repairs a lost keystroke in ~2 RTTs instead of a 200 ms RTO. One probe
per tail; an ACK of new data disarms or re-arms it.

Validation: IPv4 IHL, total length, header checksum; IPv6 version,
payload length and the extension-header walk (below); TCP data offset,
options, TCP checksum (pseudo-header of the packet's family); fragments
dropped; packets not addressed to one of our addresses dropped; IPv6
packets from ::, ::1, ff00::/8, ::ffff:0:0/96 or our own address dropped
before TCP or ICMPv6 see them (no RST or echo reply to such a source).
The device already drops inner packets whose source is not in the
peer's AllowedIPs. Memory: buffers allocated per established
connection, bounded by Limits (defaults: ~33 MiB worst case, rings ~1.4 MiB
idle); wiped when freed.

Tests: unit and state-machine tests inline (src/netstack/*.zig, manual
drive with `testing.Peer` and the advanceable device clock, plus two
stacks over a deterministic lossy link); fuzz targets in
src/netstack/fuzz.zig (also run with seeded random inputs, since `--fuzz`
does not run on Windows); `src/netstack/e2e.zig` is its own ReleaseSafe
test binary (`zig build test` runs it; `zig build netstack-e2e` alone):
two real Devices over 127.0.0.1 UDP, 50 MiB each way with and without
loss / reordering / duplication (SHA-256 checked), interactive latency
under a saturating bulk stream, Node with the Reader / Writer adapters.
Adversarial and conformance suites live in tests/netstack (separate agent).
The IPv6 coverage: the state-machine tests that matter for both families
(handshake both ways, data, FIN / RST, RFC 5961 RST, retransmission, fast
retransmit, user timeout, malformed / foreign drop, ICMP echo, the
two-stack lossy transfers) are written once against an address pair and
run over IPv4 and IPv6; IPv6-only tests cover MSS 1360, extension
headers, ICMPv6, v4-mapped and unusable sources, the dual-stack listener
and single-family stacks; the fuzz targets run IPv4-only and dual-stack;
the e2e repeats the 50 MiB transfers and the latency runs over
fd0a:8::1 / fd0a:8::2 on dual-stack nodes (outer UDP still 127.0.0.1).

### IPv6

Addressing (proposal): the tunnel gets a ULA /64, fd0a:8::/64, next to
10.8.0.0/24, with the same host numbers: the hub is 10.8.0.1 and
fd0a:8::1, device n is 10.8.0.n and fd0a:8::n (AllowedIPs 10.8.0.n/32,
fd0a:8::n/128 on the hub; 10.8.0.1/32, fd0a:8::1/128 on a device).
`Options.address` stays the IPv4 address and `address6` adds the IPv6
one, so one listener accepts on both. Portal keeps IPv4 as the primary
(devices dial 10.8.0.1); IPv6 inside the tunnel is available, not
required, and nothing depends on the outer path's family (the outer
transport is whatever UDP the device has). The prefix is fixed rather
than random (RFC 4193 wants a random Global ID): the tunnel is never
routed or merged with another site, and a fixed, readable prefix matches
the fixed 10.8.0.0/24. A deployment that bridges tunnels should pick a
random fdXX:XXXX:XXXX::/48 instead; nothing in the stack assumes fd0a:8.

What the stack does:
  * one address per family: `address` (either family) and `address6`
    (IPv6 next to an IPv4 `address`); create rejects two of a family and
    any v4-mapped address. No v4-mapped IPv6 anywhere: dial to
    ::ffff:a.b.c.d is AddressFamilyUnsupported, an IPv4 connection is an
    IPv4 connection. Dial picks our address by the destination's family
    and refuses a family we have no address for, ::, ::1, multicast and
    our own address.
  * MSS = MTU - 60 (1420 -> 1360), so a full segment fills the MTU
    exactly; the ring slots and the scratch buffer are MTU-sized for
    either family. Minimum MTU 576 (IPv6 itself wants 1280; WireGuard's
    1420 is far above both).
  * extension headers: at most 4, at most 256 bytes. Hop-by-hop (first
    only) and destination options are skipped when they hold only Pad1 /
    PadN; anything else in them (router alert, jumbo payload, ...) drops
    the packet. Fragment headers (atomic fragments included), routing,
    AH, ESP, "no next header", mobility, HIP, shim6 and the experimental
    values drop it. Replies carry no extension headers.
  * ICMPv6: echo request -> echo reply (checksum over the IPv6
    pseudo-header; `icmp_echo` turns it off). Everything else is
    ignored: no NDP, no MLD, no router advertisements (a point-to-point
    tunnel with configured addresses needs none) and no ICMPv6 errors are
    sent (no Packet Too Big: we control the MTU on both ends). Incoming
    ICMPv6 errors are ignored too, as ICMPv4 ones are (PMTUD not needed).
  * the IPv6 header we send: traffic class 0, flow label 0, hop limit 64.
## Rules

* Pure Zig, std only (Wintun is the one runtime-loaded OS component).
* Secrets wiped after use; constant-time comparisons for MACs/tags.
* Everything bounded: no unbounded allocation from network input.
* Event-driven only.
* Each agent: unit tests for its module; `zig build test` must pass on main.
* Commit as the owner's git identity, no attribution trailers.
* Security review + interop sign-off before it replaces wireguard-go anywhere.
