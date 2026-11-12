//! Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s as specified on wireguard.com/protocol
//! and in the whitepaper (section 5.4), structured like the kernel's noise.c.
//!
//! Pure: no I/O, no clock reads, no global state. The caller passes wall-clock
//! time (for the TAI64N timestamp), monotonic time (rate limiting, cookie
//! ages) and a `std.Random` (ephemeral keys). Intermediate secrets live in
//! locals that are wiped on every path, and a `Handshake` only changes when a
//! step fully succeeds, so a failed/forged message never disturbs a
//! handshake in progress.
//!
//! Flow (device side):
//!   initiator                                responder
//!   hs.createInitiation(...)  ---- msg 1 --->  checker.check(...)        (cookie.zig)
//!                                              start = consumeInitiationStatic(local, msg)
//!                                              peer = lookup(start.remote_static)
//!                                              peer.hs.consumeInitiation(&start, now)
//!                             <--- msg 2 ----  peer.hs.createResponse(...)
//!   checker.check(...)                         keys = peer.hs.deriveKeys()
//!   hs = lookup(msg.receiverIndex())
//!   hs.consumeResponse(local, msg)
//!   keys = hs.deriveKeys()
const std = @import("std");
const crypto = @import("../crypto.zig");
const messages = @import("messages.zig");
const cookie = @import("cookie.zig");

const Initiation = messages.Initiation;
const Response = messages.Response;
const PrivateKey = crypto.PrivateKey;
const PublicKey = crypto.PublicKey;
const SymKey = crypto.SymKey;

pub const construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
/// HASH(construction); asserted in tests.
pub const initial_chaining_key = crypto.hexTo(32, "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
/// HASH(initial_chaining_key || identifier); asserted in tests.
pub const initial_hash = crypto.hexTo(32, "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");

/// Kernel/wireguard-go INITIATIONS_PER_SECOND: a peer's initiation is
/// accepted at most once per 1/50 s (flood protection, on top of the strict
/// timestamp increase that blocks replays).
pub const initiations_per_second = 50;
pub const min_initiation_interval_ns: i64 = std.time.ns_per_s / initiations_per_second;
/// The nanosecond part of our TAI64N timestamps is rounded down to a multiple
/// of 2^24 ns (~16.8 ms), as the kernel and wireguard-go do, so the timestamp
/// does not leak precise clock values. Being below 20 ms, it still increases
/// across initiations that pass the flood check.
pub const timestamp_whitener_mask: u32 = (1 << 24) - 1;

pub const Error = error{
    /// Message does not fit the handshake's current state.
    InvalidState,
    /// Response not addressed to this handshake's local index.
    IndexMismatch,
    /// Decrypted static key is not this handshake's peer.
    PeerMismatch,
    /// AEAD failure: wrong keys, forged or corrupted message.
    AuthenticationFailed,
    /// A Diffie-Hellman result was zero (low-order point), or the local and
    /// peer statics produce one (unusable peer).
    InvalidPublicKey,
    /// Initiation timestamp not newer than the last accepted one.
    ReplayedTimestamp,
    /// Initiation within `min_initiation_interval_ns` of the last accepted one.
    InitiationFlood,
};

/// The local static identity. Wipe with `wipe` when discarded.
pub const Local = struct {
    private: PrivateKey,
    public: PublicKey,

    pub fn init(private: PrivateKey) Local {
        var k = private;
        crypto.clampPrivateKey(&k);
        return .{ .private = k, .public = crypto.publicKey(k) };
    }

    pub fn wipe(self: *Local) void {
        crypto.wipe(self);
    }
};

/// Session key material, handed to `session.Peer.initiatorSession` /
/// `responderSession`: {send, recv, local_index, remote_index, is_initiator},
/// already oriented for this side. The responder must not send transport
/// data until it has received some from the initiator (whitepaper 5.4.6).
/// Wipe after use.
pub const Keys = @import("../session/root.zig").Seed;

pub const State = enum { zeroed, created_initiation, consumed_initiation, created_response, consumed_response };

// ------------------------------------------------------------ symmetric ops

fn mixHash(h: *[32]u8, data: []const u8) void {
    h.* = crypto.hash(&.{ h, data });
}

/// ck = KDF1(ck, e); h = HASH(h || e)   (protocol: "message_ephemeral")
fn mixEphemeral(ck: *[32]u8, h: *[32]u8, e: *const PublicKey) void {
    mixHash(h, e);
    ck.* = crypto.kdf1(ck, e);
}

/// (ck, key) = KDF2(ck, shared)
fn mixKey(ck: *[32]u8, key: ?*SymKey, shared: *const [32]u8) void {
    var out = crypto.kdf2(ck, shared);
    defer crypto.wipe(&out);
    ck.* = out[0];
    if (key) |k| k.* = out[1];
}

fn mixDh(ck: *[32]u8, key: ?*SymKey, private: *const PrivateKey, public: *const PublicKey) Error!void {
    var shared = crypto.dh(private.*, public.*) catch return error.InvalidPublicKey;
    defer crypto.wipe(&shared);
    mixKey(ck, key, &shared);
}

/// (ck, t, key) = KDF3(ck, psk); h = HASH(h || t)
fn mixPsk(ck: *[32]u8, h: *[32]u8, key: *SymKey, psk: *const crypto.PresharedKey) void {
    var out = crypto.kdf3(ck, psk);
    defer crypto.wipe(&out);
    ck.* = out[0];
    mixHash(h, &out[1]);
    key.* = out[2];
}

fn whitenedTimestamp(wall_ns: i96) crypto.Tai64n {
    var t = crypto.tai64n(wall_ns);
    const ns = std.mem.readInt(u32, t[8..12], .big) & ~timestamp_whitener_mask;
    std.mem.writeInt(u32, t[8..12], ns, .big);
    return t;
}

fn newEphemeral(rng: std.Random) PrivateKey {
    var e: PrivateKey = undefined;
    rng.bytes(&e);
    crypto.clampPrivateKey(&e);
    return e;
}

// ------------------------------------------------- responder, first phase

/// Result of decrypting an initiation's static key, before the peer is known.
/// Contains secrets: pass it to `Handshake.consumeInitiation` (which wipes it)
/// or `wipe` it.
pub const InitiationStart = struct {
    /// The initiator's static public key: look the peer up by it.
    remote_static: PublicKey,
    remote_ephemeral: PublicKey,
    sender_index: u32,
    hash: [32]u8,
    chaining_key: [32]u8,
    encrypted_timestamp: [crypto.tai64n_len + crypto.tag_len]u8,

    pub fn wipe(self: *InitiationStart) void {
        crypto.wipe(self);
    }
};

/// Responder step 1: authenticate the initiation's ephemeral/static part with
/// our static key and reveal the initiator's static public key. The mac1
/// check (CookieChecker.check) must have passed before this.
pub fn consumeInitiationStatic(local: *const Local, msg: *const Initiation) Error!InitiationStart {
    var h = initial_hash;
    var ck = initial_chaining_key;
    var key: SymKey = undefined;
    defer crypto.wipe(&key);
    defer crypto.wipe(&h);
    defer crypto.wipe(&ck);

    mixHash(&h, &local.public);
    mixEphemeral(&ck, &h, &msg.ephemeral);
    try mixDh(&ck, &key, &local.private, &msg.ephemeral);
    var s: PublicKey = undefined;
    try crypto.aeadDecrypt(&s, &key, 0, &msg.encrypted_static, &h);
    mixHash(&h, &msg.encrypted_static);
    return .{
        .remote_static = s,
        .remote_ephemeral = msg.ephemeral,
        .sender_index = msg.senderIndex(),
        .hash = h,
        .chaining_key = ck,
        .encrypted_timestamp = msg.encrypted_timestamp,
    };
}

// ------------------------------------------------------------ per peer

/// The handshake state for one peer (both roles). Not thread-safe.
pub const Handshake = struct {
    remote_static: PublicKey,
    psk: crypto.PresharedKey,
    /// DH(local static, remote static); zero if that is the identity element.
    precomputed_static_static: [32]u8,
    /// mac1/mac2 for messages we send to this peer; cookie replies from it.
    cookie: cookie.CookieGenerator,

    state: State = .zeroed,
    hash: [32]u8 = @splat(0),
    chaining_key: [32]u8 = @splat(0),
    ephemeral_private: PrivateKey = @splat(0),
    remote_ephemeral: PublicKey = @splat(0),
    local_index: u32 = 0,
    remote_index: u32 = 0,

    /// Greatest initiation timestamp accepted from this peer (survives
    /// session changes; all zero = none yet).
    latest_timestamp: crypto.Tai64n = @splat(0),
    /// Monotonic time of the last accepted initiation from this peer.
    last_initiation_consumption: ?i64 = null,

    /// `psk` all zero = no preshared key.
    pub fn init(local: *const Local, remote_static: PublicKey, psk: crypto.PresharedKey) Handshake {
        return .{
            .remote_static = remote_static,
            .psk = psk,
            .precomputed_static_static = precompute(local, &remote_static),
            .cookie = cookie.CookieGenerator.init(&remote_static),
        };
    }

    fn precompute(local: *const Local, remote_static: *const PublicKey) [32]u8 {
        return crypto.dh(local.private, remote_static.*) catch @splat(0);
    }

    /// The local static key changed: recompute and drop any handshake in
    /// progress (kernel wg_noise_set_static_identity_private_key).
    pub fn setLocal(self: *Handshake, local: *const Local) void {
        self.precomputed_static_static = precompute(local, &self.remote_static);
        self.clear();
    }

    pub fn setPresharedKey(self: *Handshake, psk: crypto.PresharedKey) void {
        self.psk = psk;
    }

    /// Forget the in-progress handshake (ephemeral, hash, chaining key,
    /// indices); keeps peer config, cookie and replay/flood history.
    pub fn clear(self: *Handshake) void {
        crypto.wipe(&self.hash);
        crypto.wipe(&self.chaining_key);
        crypto.wipe(&self.ephemeral_private);
        crypto.wipe(&self.remote_ephemeral);
        self.local_index = 0;
        self.remote_index = 0;
        self.state = .zeroed;
    }

    /// Wipe everything, including keys and cookie state (peer removed).
    pub fn wipe(self: *Handshake) void {
        crypto.wipe(self);
    }

    fn hasUsableStatic(self: *const Handshake) bool {
        return !crypto.isZero(32, &self.precomputed_static_static);
    }

    /// Initiator: build message 1. Replaces any handshake in progress.
    /// `wall_ns`: wall clock (ns since Unix epoch) for the TAI64N timestamp;
    /// `now`: monotonic ns (cookie age); `sender_index`: a fresh local index
    /// chosen by the device; draws 32 bytes from `rng` for the ephemeral key.
    pub fn createInitiation(self: *Handshake, local: *const Local, wall_ns: i96, now: i64, sender_index: u32, rng: std.Random) Error!Initiation {
        if (!self.hasUsableStatic()) return error.InvalidPublicKey;

        var h = initial_hash;
        var ck = initial_chaining_key;
        var key: SymKey = undefined;
        var e = newEphemeral(rng);
        defer crypto.wipe(&key);
        defer crypto.wipe(&h);
        defer crypto.wipe(&ck);
        defer crypto.wipe(&e);

        var msg: Initiation = .{ .sender = undefined, .ephemeral = undefined, .encrypted_static = undefined, .encrypted_timestamp = undefined, .mac1 = undefined, .mac2 = undefined };
        messages.writeIndex(&msg.sender, sender_index);

        mixHash(&h, &self.remote_static);
        msg.ephemeral = crypto.publicKey(e);
        mixEphemeral(&ck, &h, &msg.ephemeral);
        try mixDh(&ck, &key, &e, &self.remote_static);
        crypto.aeadEncrypt(&msg.encrypted_static, &key, 0, &local.public, &h);
        mixHash(&h, &msg.encrypted_static);
        mixKey(&ck, &key, &self.precomputed_static_static);
        const ts = whitenedTimestamp(wall_ns);
        crypto.aeadEncrypt(&msg.encrypted_timestamp, &key, 0, &ts, &h);
        mixHash(&h, &msg.encrypted_timestamp);

        self.cookie.addMacs(@as(*[Initiation.size]u8, @ptrCast(&msg)), now);

        self.clear();
        self.hash = h;
        self.chaining_key = ck;
        self.ephemeral_private = e;
        self.local_index = sender_index;
        self.state = .created_initiation;
        return msg;
    }

    /// Responder step 2: finish consuming an initiation whose static key
    /// identified this peer. Checks the timestamp (must be strictly newer than
    /// any accepted before) and the per-peer flood limit. `now`: monotonic
    /// ns. Always wipes `start`.
    pub fn consumeInitiation(self: *Handshake, start: *InitiationStart, now: i64) Error!void {
        defer start.wipe();
        if (!crypto.eql(32, &start.remote_static, &self.remote_static)) return error.PeerMismatch;
        if (!self.hasUsableStatic()) return error.InvalidPublicKey;

        var h = start.hash;
        var ck = start.chaining_key;
        var key: SymKey = undefined;
        defer crypto.wipe(&key);
        defer crypto.wipe(&h);
        defer crypto.wipe(&ck);

        mixKey(&ck, &key, &self.precomputed_static_static);
        var t: crypto.Tai64n = undefined;
        try crypto.aeadDecrypt(&t, &key, 0, &start.encrypted_timestamp, &h);
        mixHash(&h, &start.encrypted_timestamp);

        const replay = !crypto.tai64nAfter(&t, &self.latest_timestamp);
        const flood = if (self.last_initiation_consumption) |last|
            last +| min_initiation_interval_ns > now
        else
            false;
        if (replay) return error.ReplayedTimestamp;
        if (flood) return error.InitiationFlood;

        self.clear();
        self.remote_ephemeral = start.remote_ephemeral;
        self.latest_timestamp = t;
        self.hash = h;
        self.chaining_key = ck;
        self.remote_index = start.sender_index;
        if (self.last_initiation_consumption == null or self.last_initiation_consumption.? < now)
            self.last_initiation_consumption = now;
        self.state = .consumed_initiation;
    }

    /// Responder: build message 2 after `consumeInitiation`. `sender_index`:
    /// a fresh local index; draws 32 bytes from `rng`; `now`: monotonic ns.
    pub fn createResponse(self: *Handshake, now: i64, sender_index: u32, rng: std.Random) Error!Response {
        if (self.state != .consumed_initiation) return error.InvalidState;

        var h = self.hash;
        var ck = self.chaining_key;
        var key: SymKey = undefined;
        var e = newEphemeral(rng);
        defer crypto.wipe(&key);
        defer crypto.wipe(&h);
        defer crypto.wipe(&ck);
        defer crypto.wipe(&e);

        var msg: Response = .{ .sender = undefined, .receiver = undefined, .ephemeral = undefined, .encrypted_nothing = undefined, .mac1 = undefined, .mac2 = undefined };
        messages.writeIndex(&msg.sender, sender_index);
        messages.writeIndex(&msg.receiver, self.remote_index);

        msg.ephemeral = crypto.publicKey(e);
        mixEphemeral(&ck, &h, &msg.ephemeral);
        try mixDh(&ck, null, &e, &self.remote_ephemeral);
        try mixDh(&ck, null, &e, &self.remote_static);
        mixPsk(&ck, &h, &key, &self.psk);
        crypto.aeadEncrypt(&msg.encrypted_nothing, &key, 0, "", &h);
        mixHash(&h, &msg.encrypted_nothing);

        self.cookie.addMacs(@as(*[Response.size]u8, @ptrCast(&msg)), now);

        self.hash = h;
        self.chaining_key = ck;
        self.ephemeral_private = e;
        self.local_index = sender_index;
        self.state = .created_response;
        return msg;
    }

    /// Initiator: consume message 2 (mac1 already checked; the device found
    /// this handshake by `msg.receiverIndex()`).
    pub fn consumeResponse(self: *Handshake, local: *const Local, msg: *const Response) Error!void {
        if (self.state != .created_initiation) return error.InvalidState;
        if (msg.receiverIndex() != self.local_index) return error.IndexMismatch;

        var h = self.hash;
        var ck = self.chaining_key;
        var key: SymKey = undefined;
        defer crypto.wipe(&key);
        defer crypto.wipe(&h);
        defer crypto.wipe(&ck);

        mixEphemeral(&ck, &h, &msg.ephemeral);
        try mixDh(&ck, null, &self.ephemeral_private, &msg.ephemeral);
        try mixDh(&ck, null, &local.private, &msg.ephemeral);
        mixPsk(&ck, &h, &key, &self.psk);
        var nothing: [0]u8 = .{};
        try crypto.aeadDecrypt(&nothing, &key, 0, &msg.encrypted_nothing, &h);
        mixHash(&h, &msg.encrypted_nothing);

        self.remote_ephemeral = msg.ephemeral;
        self.hash = h;
        self.chaining_key = ck;
        self.remote_index = msg.senderIndex();
        self.state = .consumed_response;
    }

    /// Both roles, once the handshake is complete (initiator after
    /// `consumeResponse`, responder after `createResponse`):
    /// (T_send, T_recv) from KDF2(chaining_key, ""), oriented for this side.
    /// Clears the handshake (ephemeral, hash, chaining key).
    pub fn deriveKeys(self: *Handshake) Error!Keys {
        const is_initiator = switch (self.state) {
            .consumed_response => true,
            .created_response => false,
            else => return error.InvalidState,
        };
        var t = crypto.kdf2(&self.chaining_key, "");
        defer crypto.wipe(&t);
        const keys: Keys = .{
            .send = if (is_initiator) t[0] else t[1],
            .recv = if (is_initiator) t[1] else t[0],
            .local_index = self.local_index,
            .remote_index = self.remote_index,
            .is_initiator = is_initiator,
        };
        self.clear();
        return keys;
    }
};
