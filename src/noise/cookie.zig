//! MAC1 / MAC2 and the cookie mechanism (whitepaper 5.4.7, protocol page
//! "Cookie MACs" / "Cookie Reply"), structured like the kernel's cookie.c:
//!
//!   * `CookieChecker` (one per device, keyed by OUR static public key):
//!     verifies mac1 on every incoming handshake message, verifies mac2 when
//!     under load, and builds cookie replies. Its cookie secret is random and
//!     regenerated lazily once it is older than 120 s (by the caller's clock).
//!   * `CookieGenerator` (one per peer, keyed by the PEER's static public key):
//!     adds mac1/mac2 to messages we send to that peer and stores the cookie
//!     from a cookie reply.
//!
//! Times are monotonic nanoseconds supplied by the caller (`now: i64`); no
//! clock is read here. Randomness comes from a caller-supplied `std.Random`
//! (use a CSPRNG, e.g. `std.Random.IoSource`). Neither type locks: the
//! device serialises access.
const std = @import("std");
const crypto = @import("../crypto.zig");
const messages = @import("messages.zig");

pub const label_mac1 = "mac1----";
pub const label_cookie = "cookie--";
pub const cookie_len = 16;

const ns_per_s = std.time.ns_per_s;
/// Cookie secrets are regenerated after this age (kernel COOKIE_SECRET_MAX_AGE).
pub const cookie_secret_max_age_ns: i64 = 120 * ns_per_s;
/// A stored cookie is used for mac2 only while younger than max age minus
/// this latency (kernel COOKIE_SECRET_LATENCY), so it is not used right as
/// the responder's secret rotates.
pub const cookie_secret_latency_ns: i64 = 5 * ns_per_s;

/// `birth + age <= now` means expired (kernel wg_birthdate_has_expired).
fn expired(birth: ?i64, age: i64, now: i64) bool {
    const b = birth orelse return true;
    return b +| age <= now;
}

fn labelKey(comptime label: []const u8, public: *const crypto.PublicKey) [32]u8 {
    return crypto.hash(&.{ label, public });
}

/// What to do with an incoming initiation/response after the MAC checks.
pub const Verdict = enum {
    /// mac1 wrong (or wrong message shape): drop silently.
    invalid,
    /// Process the message. Under load this means mac2 was valid too; the
    /// device should still apply its per-source-IP handshake rate limiter
    /// (kernel ratelimiter.c) before doing the Diffie-Hellman work.
    ok,
    /// Under load and mac2 missing/wrong: send `createReply` and drop.
    need_cookie,
};

pub const CookieChecker = struct {
    mac1_key: [32]u8,
    encryption_key: [32]u8,
    secret: [32]u8 = @splat(0),
    secret_birth: ?i64 = null,

    pub fn init(local_public: *const crypto.PublicKey) CookieChecker {
        return .{
            .mac1_key = labelKey(label_mac1, local_public),
            .encryption_key = labelKey(label_cookie, local_public),
        };
    }

    /// Re-key after the local static key changed (keeps nothing).
    pub fn reset(self: *CookieChecker, local_public: *const crypto.PublicKey) void {
        self.wipe();
        self.* = init(local_public);
    }

    pub fn wipe(self: *CookieChecker) void {
        crypto.wipe(self);
    }

    /// `msg`: a whole initiation (148 B) or response (92 B). `src`: the
    /// sender's address as bytes; must be the same encoding for `check` and
    /// `createReply` (recommended, as the kernel: IP address bytes || BE16 port).
    /// Same as `checkMac1` followed (if under load) by `checkMac2`. A device
    /// that measures load should call the two halves itself and count a
    /// message only after `checkMac1` passed, so that unauthenticated junk
    /// cannot put it under load.
    pub fn check(self: *CookieChecker, msg: []const u8, src: []const u8, now: i64, under_load: bool, rng: std.Random) Verdict {
        if (!self.checkMac1(msg)) return .invalid;
        if (!under_load) return .ok;
        return self.checkMac2(msg, src, now, rng);
    }

    /// True when `msg` has the size of an initiation or response and a
    /// correct mac1 (proof the sender knows our public key). Stateless.
    pub fn checkMac1(self: *const CookieChecker, msg: []const u8) bool {
        if (msg.len != messages.Initiation.size and msg.len != messages.Response.size) return false;
        const m1 = messages.mac1Offset(msg.len);
        const want1 = crypto.mac(&self.mac1_key, &.{msg[0..m1]});
        return crypto.eql(16, &want1, msg[m1..][0..16]);
    }

    /// mac2 check for a message that already passed `checkMac1`: `.ok` when
    /// mac2 is the cookie for `src`, else `.need_cookie`.
    pub fn checkMac2(self: *CookieChecker, msg: []const u8, src: []const u8, now: i64, rng: std.Random) Verdict {
        std.debug.assert(msg.len == messages.Initiation.size or msg.len == messages.Response.size);
        const m2 = messages.mac2Offset(msg.len);
        var cookie = self.makeCookie(src, now, rng);
        defer crypto.wipe(&cookie);
        const want2 = crypto.mac(&cookie, &.{msg[0..m2]});
        return if (crypto.eql(16, &want2, msg[m2..][0..16])) .ok else .need_cookie;
    }

    /// Cookie reply to `msg` (an initiation/response that `check` answered
    /// with `.need_cookie`), addressed to its sender index. Draws 24 nonce
    /// bytes from `rng` (and 32 more if the secret must be regenerated).
    pub fn createReply(self: *CookieChecker, msg: []const u8, src: []const u8, now: i64, rng: std.Random) messages.CookieReply {
        std.debug.assert(msg.len == messages.Initiation.size or msg.len == messages.Response.size);
        var reply: messages.CookieReply = .{ .receiver = undefined, .nonce = undefined, .encrypted_cookie = undefined };
        messages.writeIndex(&reply.receiver, messages.handshakeSenderIndex(msg));
        rng.bytes(&reply.nonce);
        var cookie = self.makeCookie(src, now, rng);
        defer crypto.wipe(&cookie);
        const mac1 = msg[messages.mac1Offset(msg.len)..][0..16];
        crypto.xaeadEncrypt(&reply.encrypted_cookie, &self.encryption_key, &reply.nonce, &cookie, mac1);
        return reply;
    }

    /// cookie = MAC(secret, src), regenerating the secret when stale.
    fn makeCookie(self: *CookieChecker, src: []const u8, now: i64, rng: std.Random) [cookie_len]u8 {
        if (expired(self.secret_birth, cookie_secret_max_age_ns, now)) {
            rng.bytes(&self.secret);
            self.secret_birth = now;
        }
        return crypto.mac(&self.secret, &.{src});
    }
};

pub const CookieGenerator = struct {
    mac1_key: [32]u8,
    decryption_key: [32]u8,
    cookie: [cookie_len]u8 = @splat(0),
    /// When the stored cookie was received; null = none.
    cookie_birth: ?i64 = null,
    /// mac1 of the last handshake message we sent: the AD a cookie reply is
    /// bound to. Only one reply per sent message is accepted.
    last_mac1: [16]u8 = @splat(0),
    have_sent_mac1: bool = false,

    pub fn init(remote_public: *const crypto.PublicKey) CookieGenerator {
        return .{
            .mac1_key = labelKey(label_mac1, remote_public),
            .decryption_key = labelKey(label_cookie, remote_public),
        };
    }

    pub fn wipe(self: *CookieGenerator) void {
        crypto.wipe(self);
    }

    /// Fill mac1 and mac2 of an outgoing initiation/response (`msg` is the
    /// whole 148/92-byte message with everything before mac1 final). mac2 is
    /// zero unless we hold a cookie younger than 115 s.
    pub fn addMacs(self: *CookieGenerator, msg: []u8, now: i64) void {
        std.debug.assert(msg.len == messages.Initiation.size or msg.len == messages.Response.size);
        const m1 = messages.mac1Offset(msg.len);
        const m2 = messages.mac2Offset(msg.len);
        const mac1 = crypto.mac(&self.mac1_key, &.{msg[0..m1]});
        msg[m1..][0..16].* = mac1;
        self.last_mac1 = mac1;
        self.have_sent_mac1 = true;
        if (!expired(self.cookie_birth, cookie_secret_max_age_ns - cookie_secret_latency_ns, now)) {
            msg[m2..][0..16].* = crypto.mac(&self.cookie, &.{msg[0..m2]});
        } else {
            @memset(msg[m2..][0..16], 0);
        }
    }

    pub const ConsumeError = error{ NoMac1Sent, AuthenticationFailed };

    /// Store the cookie from a cookie reply addressed to this peer (the
    /// device matched `reply.receiverIndex()` to one of our indices).
    pub fn consumeReply(self: *CookieGenerator, reply: *const messages.CookieReply, now: i64) ConsumeError!void {
        if (!self.have_sent_mac1) return error.NoMac1Sent;
        var cookie: [cookie_len]u8 = undefined;
        try crypto.xaeadDecrypt(&cookie, &self.decryption_key, &reply.nonce, &reply.encrypted_cookie, &self.last_mac1);
        self.cookie = cookie;
        crypto.wipe(&cookie);
        self.cookie_birth = now;
        self.have_sent_mac1 = false;
    }
};
