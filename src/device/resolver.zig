//! Endpoint names (`Endpoint = home.example.org:51820`): resolved again
//! while they do not work, so a dynamic-DNS change of the far end's address,
//! or a name that could not be resolved at start (no network yet at boot),
//! heals by itself instead of leaving the tunnel dead until it is restarted.
//!
//! When: a peer whose configured endpoint is a DNS name is looked up again
//!   * when a handshake initiation goes unanswered (the session timers'
//!     retransmission, every REKEY_TIMEOUT while the far end is silent), at
//!     most once per `min_interval`;
//!   * after a failed lookup, on its own deadline: backoff 1 s, 2 s, 4 s, ...
//!     up to `max_backoff` until one succeeds.
//! A peer that is working is never looked up. Nothing ticks: the device
//! folds `Schedule.next` into its timer deadline and asks `Schedule` what to
//! do when a deadline or a retransmission arrives.
//!
//! How: each lookup runs on a short-lived detached thread (a DNS lookup
//! blocks; the device loop must not), which writes the answer into its
//! peer's slot and signals a Waker the device waits on. The slots and the
//! Waker live in a reference-counted `Shared`, so a device torn down while
//! a lookup is still in flight never waits for it: the last one out frees.
//! A slot is handed over by its atomic state (idle -> busy by the device,
//! busy -> done by the worker, done -> idle by the device): one writer at a
//! time, no lock.
//!
//! The answer replaces the peer's endpoint only if nothing authenticated
//! came from the peer since the lookup started (roaming knows better).

const std = @import("std");
const net = std.Io.net;
const Waker = @import("../tun/root.zig").queue.Waker;

const ns_per_s = std.time.ns_per_s;

/// Unanswered handshakes look the name up again at most this often.
pub const min_interval: i64 = 15 * ns_per_s;
/// Failed lookups back off up to this.
pub const max_backoff: i64 = 120 * ns_per_s;
/// Longest host name kept (RFC 1035: 253 characters).
pub const max_host = 253;

/// DNS name -> one address (IP literals never get here:
/// `config.Endpoint.literal`). IPv4 is preferred (the device always has an
/// IPv4 socket; IPv6 only when the host supports it).
pub fn systemLookup(ctx: ?*anyopaque, io: std.Io, host: []const u8, port: u16) anyerror!net.IpAddress {
    _ = ctx;
    const h = try net.HostName.init(host);
    var buf: [32]net.HostName.LookupResult = undefined;
    var q: std.Io.Queue(net.HostName.LookupResult) = .init(&buf);
    try h.lookup(io, &q, .{ .port = port });
    var got: [32]net.HostName.LookupResult = undefined;
    const n = q.get(io, &got, 0) catch 0;
    var v6: ?net.IpAddress = null;
    for (got[0..n]) |r| switch (r) {
        .address => |a| switch (a) {
            .ip4 => return a,
            .ip6 => if (v6 == null) {
                v6 = a;
            },
        },
        else => {},
    };
    return v6 orelse error.UnknownHostName;
}

/// How names are looked up (tests substitute a fake).
pub const Lookup = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, io: std.Io, host: []const u8, port: u16) anyerror!net.IpAddress = systemLookup,

    pub const system: Lookup = .{};
};

/// When to look one peer's name up (pure; the device's clock, ns).
pub const Schedule = struct {
    busy: bool = false,
    /// When the last lookup started.
    last_start: ?i64 = null,
    /// Consecutive failed lookups.
    failures: u8 = 0,
    /// A lookup is due at this time (after a failure, or a request that
    /// came too soon after the previous lookup).
    due_at: ?i64 = null,

    pub fn backoff(failures: u8) i64 {
        if (failures == 0) return 0;
        const shift: u6 = @intCast(@min(failures - 1, 7));
        return @min(@as(i64, ns_per_s) << shift, max_backoff);
    }

    /// The far end is silent: should a lookup start now? If it is too soon
    /// after the last one, it is deferred to the earliest allowed time.
    pub fn request(s: *Schedule, now: i64) bool {
        if (s.busy) return false;
        if (s.last_start) |t| {
            const allowed = t + @max(min_interval, backoff(s.failures));
            if (now < allowed) {
                s.due_at = if (s.due_at) |d| @min(d, allowed) else allowed;
                return false;
            }
        }
        s.begin(now);
        return true;
    }

    /// A deadline passed: should a lookup start now?
    pub fn fire(s: *Schedule, now: i64) bool {
        const d = s.due_at orelse return false;
        if (s.busy or d > now) return false;
        s.begin(now);
        return true;
    }

    /// The lookup ended (or could not be started).
    pub fn finished(s: *Schedule, now: i64, ok: bool) void {
        s.busy = false;
        if (ok) {
            s.failures = 0;
            return;
        }
        s.failures +|= 1;
        const retry = now + backoff(s.failures);
        s.due_at = if (s.due_at) |d| @max(d, retry) else retry;
    }

    /// The earliest deadline (null: nothing to do until a request).
    pub fn next(s: *const Schedule) ?i64 {
        return if (s.busy) null else s.due_at;
    }

    fn begin(s: *Schedule, now: i64) void {
        s.busy = true;
        s.last_start = now;
        s.due_at = null;
    }
};

pub const SlotState = enum(u8) { idle, busy, done };

pub const Slot = struct {
    state: std.atomic.Value(SlotState) = .init(.idle),
    host: []const u8,
    port: u16,
    /// Written by the worker before `state` becomes done.
    result: ?net.IpAddress = null,
};

/// Slots + the Waker, shared by the device and its lookup threads. Its
/// memory is the page allocator's, not the device's: the last lookup thread
/// may free it after the device and its allocator are gone.
pub const Shared = struct {
    io: std.Io,
    lookup: Lookup,
    refs: std.atomic.Value(u32) = .init(1),
    waker: Waker,
    slots: []Slot,
    host_bytes: []u8,

    const gpa = std.heap.page_allocator;

    /// One slot per entry of `hosts` (copied).
    pub fn create(io: std.Io, lookup: Lookup, hosts: []const []const u8, ports: []const u16) !*Shared {
        std.debug.assert(hosts.len == ports.len);
        var total: usize = 0;
        for (hosts) |h| {
            if (h.len == 0 or h.len > max_host) return error.InvalidHost;
            total += h.len;
        }
        const s = try gpa.create(Shared);
        errdefer gpa.destroy(s);
        const slots = try gpa.alloc(Slot, hosts.len);
        errdefer gpa.free(slots);
        const bytes = try gpa.alloc(u8, total);
        errdefer gpa.free(bytes);
        var waker = Waker.init() catch return error.SystemResources;
        errdefer waker.deinit();
        var off: usize = 0;
        for (hosts, ports, slots) |h, p, *slot| {
            @memcpy(bytes[off..][0..h.len], h);
            slot.* = .{ .host = bytes[off..][0..h.len], .port = p };
            off += h.len;
        }
        s.* = .{ .io = io, .lookup = lookup, .waker = waker, .slots = slots, .host_bytes = bytes };
        return s;
    }

    pub fn release(s: *Shared) void {
        if (s.refs.fetchSub(1, .acq_rel) != 1) return;
        s.waker.deinit();
        gpa.free(s.slots);
        gpa.free(s.host_bytes);
        gpa.destroy(s);
    }

    /// Start a lookup for `slot` on its own thread. false: it could not be
    /// started (the slot is idle again; treat it as a failed lookup).
    pub fn start(s: *Shared, slot: usize) bool {
        const sl = &s.slots[slot];
        std.debug.assert(sl.state.load(.acquire) == .idle);
        sl.result = null;
        sl.state.store(.busy, .release);
        _ = s.refs.fetchAdd(1, .acq_rel);
        const t = std.Thread.spawn(.{ .stack_size = @import("../thread_stack.zig").threadStack(256 << 10) }, work, .{ s, slot }) catch {
            _ = s.refs.fetchSub(1, .acq_rel);
            sl.state.store(.idle, .release);
            return false;
        };
        t.detach();
        return true;
    }

    fn work(s: *Shared, slot: usize) void {
        const sl = &s.slots[slot];
        sl.result = s.lookup.func(s.lookup.ctx, s.io, sl.host, sl.port) catch null;
        sl.state.store(.done, .release);
        s.waker.signal();
        s.release();
    }

    /// The finished lookup of `slot`, if there is one (the slot is idle
    /// again). `.{ .done = false }` while none is finished.
    pub fn take(s: *Shared, slot: usize) struct { done: bool, result: ?net.IpAddress = null } {
        const sl = &s.slots[slot];
        if (sl.state.load(.acquire) != .done) return .{ .done = false };
        const r = sl.result;
        sl.state.store(.idle, .release);
        return .{ .done = true, .result = r };
    }
};

// ---- tests ---------------------------------------------------------------

const testing = std.testing;

test "schedule: unanswered handshakes look up at most every min_interval" {
    var s: Schedule = .{};
    try testing.expect(s.request(0));
    try testing.expect(!s.request(1)); // busy
    s.finished(2, true);
    try testing.expectEqual(@as(?i64, null), s.next());
    // Retransmissions every 5 s: deferred to 15 s after the last start.
    try testing.expect(!s.request(5 * ns_per_s));
    try testing.expect(!s.request(10 * ns_per_s));
    try testing.expectEqual(@as(?i64, min_interval), s.next());
    try testing.expect(!s.fire(min_interval - 1));
    try testing.expect(s.fire(min_interval));
    try testing.expectEqual(@as(?i64, null), s.next());
    s.finished(min_interval + 1, true);
    // Working again: nothing pending.
    try testing.expectEqual(@as(?i64, null), s.next());
    try testing.expect(!s.fire(1000 * ns_per_s));
}

test "schedule: failures back off 1, 2, 4 ... 120 s and retry on their own" {
    var s: Schedule = .{};
    var now: i64 = 0;
    try testing.expect(s.request(now));
    const want = [_]i64{ 1, 2, 4, 8, 16, 32, 64, 120, 120, 120 };
    for (want) |w| {
        s.finished(now, false);
        try testing.expectEqual(@as(?i64, now + w * ns_per_s), s.next());
        try testing.expect(!s.fire(now + w * ns_per_s - 1));
        now += w * ns_per_s;
        try testing.expect(s.fire(now));
    }
    // A request while failing honours the backoff, not just min_interval.
    s.finished(now, false);
    try testing.expect(!s.request(now + 20 * ns_per_s));
    try testing.expectEqual(@as(?i64, now + 120 * ns_per_s), s.next());
    try testing.expect(s.fire(now + 120 * ns_per_s));
    s.finished(now + 121 * ns_per_s, true);
    try testing.expectEqual(@as(u8, 0), s.failures);
    try testing.expectEqual(@as(?i64, null), s.next());
    try testing.expectEqual(@as(i64, 0), Schedule.backoff(0));
    try testing.expectEqual(max_backoff, Schedule.backoff(255));
}

const Fake = struct {
    calls: std.atomic.Value(u32) = .init(0),
    port: std.atomic.Value(u16) = .init(0),

    fn lookup(ctx: ?*anyopaque, io: std.Io, host: []const u8, port: u16) anyerror!net.IpAddress {
        _ = io;
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        _ = f.calls.fetchAdd(1, .monotonic);
        if (std.mem.eql(u8, host, "fails.invalid")) return error.UnknownHostName;
        const p = f.port.load(.monotonic);
        return .{ .ip4 = .loopback(if (p != 0) p else port) };
    }
};

test "shared slots: a lookup thread hands its answer over and wakes the device" {
    var fake: Fake = .{};
    const s = try Shared.create(testing.io, .{ .ctx = &fake, .func = Fake.lookup }, &.{ "home.example.org", "fails.invalid" }, &.{ 51820, 1 });
    defer s.release();
    try testing.expect(!s.take(0).done);
    try testing.expect(s.start(0));
    try testing.expect(s.start(1));
    var seen: [2]bool = .{ false, false };
    while (!(seen[0] and seen[1])) {
        _ = try @import("os.zig").wait(&.{s.waker.handle}, 5 * ns_per_s);
        s.waker.clear();
        for (0..2) |i| {
            const r = s.take(i);
            if (!r.done) continue;
            seen[i] = true;
            if (i == 0) {
                try testing.expectEqual(@as(u16, 51820), r.result.?.getPort());
            } else try testing.expectEqual(@as(?net.IpAddress, null), r.result);
        }
    }
    try testing.expectEqual(@as(u32, 2), fake.calls.load(.monotonic));
    try testing.expect(!s.take(0).done);
}

var detached_fake: Fake = .{}; // outlives the test: the worker may run after it

test "shared slots: released while a lookup is in flight, the thread frees it" {
    const s = try Shared.create(testing.io, .{ .ctx = &detached_fake, .func = Fake.lookup }, &.{"x.example"}, &.{1});
    try testing.expect(s.start(0));
    s.release(); // the device is gone; the worker frees on its way out
}

test "shared slots: host names are bounded" {
    const long: [max_host + 1]u8 = @splat('a');
    try testing.expectError(error.InvalidHost, Shared.create(testing.io, .{}, &.{&long}, &.{1}));
    try testing.expectError(error.InvalidHost, Shared.create(testing.io, .{}, &.{""}, &.{1}));
}
