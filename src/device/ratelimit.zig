//! Handshake flood protection, as in the kernel (ratelimiter.c, cookie.c)
//! and wireguard-go (ratelimiter.go, device.go):
//!
//! * `LoadMeter`: decides "under load". The kernel and wireguard-go call a
//!   device under load when its queue of pending handshake messages is at
//!   least 1/8 full (4096/8 resp. 1024/8), and keep the state for one second
//!   after it was last true. This device handles each handshake inline on
//!   one thread, so it measures the same thing as a rate: more than
//!   `threshold` handshake messages within the last second means under load,
//!   sticky for one second. The result is what noise's `under_load` takes.
//! * `Ratelimiter`: once under load, a handshake message with a valid MAC2
//!   (the sender proved its address with a cookie) is still limited per
//!   source address: 20 per second with a burst of 5 (kernel constants);
//!   IPv6 sources are grouped by /64. The table is fixed-size and keyed with
//!   a random SipHash key, so a flood of spoofed sources cannot grow memory
//!   or aim at one bucket; when a bucket is full of active sources the
//!   packet is refused.

const std = @import("std");
const ip = @import("ip.zig");

const ns_per_s: i64 = std.time.ns_per_s;

pub const LoadMeter = struct {
    /// Handshake messages per second at which the device counts as loaded.
    threshold: u32 = 128,
    window_start: i64 = 0,
    count_this: u32 = 0,
    count_prev: u32 = 0,
    under_load_until: i64 = std.math.minInt(i64),

    /// Records one received handshake message (types 1 and 2) at `now`
    /// and returns whether the device is under load.
    pub fn record(m: *LoadMeter, now: i64) bool {
        m.roll(now);
        m.count_this +|= 1;
        // Sliding estimate over the last second: the current partial window
        // plus the overlapping share of the previous one.
        const elapsed = now - m.window_start;
        const prev_share: u64 = @intCast(@divTrunc(@as(i128, m.count_prev) * (ns_per_s - elapsed), ns_per_s));
        if (prev_share + m.count_this >= m.threshold) m.under_load_until = now + ns_per_s;
        return m.underLoad(now);
    }

    pub fn underLoad(m: *const LoadMeter, now: i64) bool {
        return now < m.under_load_until;
    }

    fn roll(m: *LoadMeter, now: i64) void {
        if (now - m.window_start < ns_per_s) return;
        if (now - m.window_start < 2 * ns_per_s) {
            m.count_prev = m.count_this;
            m.window_start += ns_per_s;
        } else {
            m.count_prev = 0;
            m.window_start = now;
        }
        m.count_this = 0;
    }
};

pub const Ratelimiter = struct {
    pub const packets_per_second = 20;
    pub const packets_burstable = 5;
    const packet_cost: i64 = ns_per_s / packets_per_second;
    const tokens_max: i64 = packet_cost * packets_burstable;
    /// Idle entries are reusable after this long (kernel: 1 s gc period).
    const idle_ns: i64 = ns_per_s;

    pub const buckets = 2048;
    pub const ways = 4;

    const Slot = struct {
        key: [8]u8 = @splat(0),
        family: u8 = 0, // 0 = empty
        last: i64 = 0,
        tokens: i64 = 0,
    };

    sip_key: [16]u8,
    table: [buckets][ways]Slot = @splat(@splat(.{})),

    pub fn init(rand: std.Random) Ratelimiter {
        var k: [16]u8 = undefined;
        rand.bytes(&k);
        return .{ .sip_key = k };
    }

    /// Whether a packet from `src` may be processed now.
    pub fn allow(r: *Ratelimiter, src: ip.Addr, now: i64) bool {
        var key: [8]u8 = @splat(0);
        const fam: u8 = switch (src) {
            .v4 => |b| blk: {
                @memcpy(key[0..4], &b);
                break :blk 4;
            },
            .v6 => |b| blk: {
                @memcpy(&key, b[0..8]); // /64
                break :blk 6;
            },
        };
        var h = std.hash.SipHash64(1, 3).init(&r.sip_key);
        h.update(&.{fam});
        h.update(&key);
        const bucket = &r.table[h.finalInt() % buckets];

        var free: ?*Slot = null;
        for (bucket) |*s| {
            if (s.family == fam and std.mem.eql(u8, &s.key, &key)) {
                s.tokens = @min(tokens_max, s.tokens + (now - s.last));
                s.last = now;
                if (s.tokens >= packet_cost) {
                    s.tokens -= packet_cost;
                    return true;
                }
                return false;
            }
            if (free == null and (s.family == 0 or now - s.last >= idle_ns)) free = s;
        }
        const s = free orelse return false;
        s.* = .{ .key = key, .family = fam, .last = now, .tokens = tokens_max - packet_cost };
        return true;
    }
};

test "load meter: threshold, sticky for one second, decays" {
    var m: LoadMeter = .{ .threshold = 10 };
    const t0: i64 = 1000 * ns_per_s;
    m.window_start = t0;
    for (0..9) |i| try std.testing.expect(!m.record(t0 + @as(i64, @intCast(i)) * std.time.ns_per_ms));
    try std.testing.expect(m.record(t0 + 10 * std.time.ns_per_ms));
    try std.testing.expect(m.underLoad(t0 + 900 * std.time.ns_per_ms));
    try std.testing.expect(!m.underLoad(t0 + 1100 * std.time.ns_per_ms));
    // A trickle never trips it.
    var m2: LoadMeter = .{ .threshold = 10 };
    var t: i64 = t0;
    for (0..100) |_| {
        try std.testing.expect(!m2.record(t));
        t += 200 * std.time.ns_per_ms; // 5 per second
    }
}

test "ratelimiter: burst then 20/s per source, v6 grouped by /64" {
    var prng = std.Random.DefaultPrng.init(7);
    const r = try std.testing.allocator.create(Ratelimiter);
    defer std.testing.allocator.destroy(r);
    r.* = .init(prng.random());
    const a: ip.Addr = .{ .v4 = .{ 192, 0, 2, 1 } };
    const b: ip.Addr = .{ .v4 = .{ 192, 0, 2, 2 } };
    const t0: i64 = 50 * ns_per_s;
    var allowed: usize = 0;
    for (0..20) |_| {
        if (r.allow(a, t0)) allowed += 1;
    }
    try std.testing.expectEqual(@as(usize, Ratelimiter.packets_burstable), allowed);
    try std.testing.expect(r.allow(b, t0)); // other sources unaffected
    try std.testing.expect(!r.allow(a, t0 + 10 * std.time.ns_per_ms));
    try std.testing.expect(r.allow(a, t0 + 50 * std.time.ns_per_ms)); // one token per 50 ms
    // Over one second at a steady flood, about 20 get through.
    allowed = 0;
    var t = t0 + ns_per_s;
    for (0..1000) |_| {
        if (r.allow(a, t)) allowed += 1;
        t += std.time.ns_per_ms;
    }
    try std.testing.expect(allowed >= 20 and allowed <= 26);

    const v6a = try ip.Addr.parse("2001:db8:1:2::1");
    const v6b = try ip.Addr.parse("2001:db8:1:2:ffff::9");
    for (0..Ratelimiter.packets_burstable) |_| try std.testing.expect(r.allow(v6a, t));
    try std.testing.expect(!r.allow(v6b, t)); // same /64
}

test "ratelimiter: spoofed flood stays bounded and refuses when buckets fill" {
    var prng = std.Random.DefaultPrng.init(9);
    const r = try std.testing.allocator.create(Ratelimiter);
    defer std.testing.allocator.destroy(r);
    r.* = .init(prng.random());
    const t: i64 = 5 * ns_per_s;
    var refused: usize = 0;
    for (0..Ratelimiter.buckets * Ratelimiter.ways * 2) |i| {
        const n: u32 = @intCast(i);
        const src: ip.Addr = .{ .v4 = @bitCast(n +% 0x0a000000) };
        if (!r.allow(src, t)) refused += 1;
    }
    try std.testing.expect(refused > 0);
    // After the idle period, slots are reusable.
    try std.testing.expect(r.allow(.{ .v4 = .{ 203, 0, 113, 7 } }, t + 2 * ns_per_s));
}
