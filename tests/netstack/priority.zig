//! Interactive-vs-bulk stress (Stream.setPriority / Stack.dialWith): bulk
//! transfers saturate the tunnel while an interactive stream sends 1-byte
//! writes; the write -> peer-read latency of those bytes is measured
//! (both nodes share one clock) at 0% / 1% / 5% loss on all traffic.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const pair = @import("pair.zig");
const Pair = pair.Pair;

const gpa = t.allocator;
const mib: u64 = hz.options.e2e_mib;

fn needPriority() !void {
    if (!hz.has_priority) return hz.skip("Stream.setPriority not on feat/netstack yet");
}

/// Ping-pong of single bytes: the device side writes one byte, the hub
/// reads it (latency = hub read time - device write time), echoes it, and
/// the device waits for the echo before the next keystroke.
const Keys = struct {
    p: *Pair,
    dev: ns.Stream,
    hub: ns.Stream,
    stop: *std.atomic.Value(bool),
    sent_at: std.atomic.Value(i64) = .init(0),
    lat: std.ArrayList(u64) = .empty,
    err: ?anyerror = null,
    echo_err: ?anyerror = null,
    max_samples: usize = 20_000,

    fn typist(k: *Keys) void {
        var b: [1]u8 = undefined;
        var i: usize = 0;
        while (!k.stop.load(.acquire) and i < k.max_samples) : (i += 1) {
            k.sent_at.store(k.p.now(), .release);
            k.dev.writeAll(&.{@truncate(i)}, 30 * hz.sec) catch |e| {
                k.err = e;
                break;
            };
            const n = k.dev.readWait(&b, 30 * hz.sec) catch |e| {
                k.err = e;
                break;
            };
            if (n != 1 or b[0] != @as(u8, @truncate(i))) {
                k.err = error.BadEcho;
                break;
            }
        }
        k.dev.shutdown();
    }

    fn echo(k: *Keys) void {
        var b: [1]u8 = undefined;
        while (true) {
            const n = k.hub.readWait(&b, 60 * hz.sec) catch |e| {
                k.echo_err = e;
                return;
            };
            if (n == 0) return;
            const lat = k.p.now() - k.sent_at.load(.acquire);
            k.lat.append(gpa, @intCast(@max(lat, 0))) catch {};
            k.hub.writeAll(&b, 30 * hz.sec) catch |e| {
                k.echo_err = e;
                return;
            };
        }
    }
};

const Bulk = struct {
    sent: pair.Sent = .{},
    recv: pair.Received = .{},
    threads: [2]std.Thread = undefined,
    c: @typeInfo(@typeInfo(@TypeOf(Pair.connect)).@"fn".return_type.?).error_union.payload = undefined,
};

const Result = struct { p50: u64, p99: u64, max: u64, samples: usize, secs: f64 };

/// `bulk_n` bulk streams of `bytes` each (device -> hub) plus one
/// interactive ping-pong stream for as long as the bulk transfers run.
fn run(o: pair.Options, bulk_n: usize, bytes: u64, label: []const u8) !Result {
    const p = try Pair.create(gpa, o);
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    const bulks = try gpa.alloc(Bulk, bulk_n);
    defer gpa.free(bulks);
    for (bulks) |*b| {
        b.* = .{};
        b.c = try p.connect(l, .bulk);
    }
    const ic = try p.connect(l, .interactive);
    var stop: std.atomic.Value(bool) = .init(false);
    var keys: Keys = .{ .p = p, .dev = ic.dev, .hub = ic.hub, .stop = &stop };
    defer keys.lat.deinit(gpa);
    const t0 = p.now();
    const kt = try std.Thread.spawn(.{}, Keys.typist, .{&keys});
    const et = try std.Thread.spawn(.{}, Keys.echo, .{&keys});
    for (bulks, 0..) |*b, i| {
        b.threads = .{
            try std.Thread.spawn(.{}, pair.sendAll, .{ b.c.dev, 100 + i, bytes, &b.sent }),
            try std.Thread.spawn(.{}, pair.recvAll, .{ b.c.hub, &b.recv }),
        };
    }
    for (bulks) |*b| for (b.threads) |x| x.join();
    const secs = @as(f64, @floatFromInt(p.now() - t0)) / 1e9;
    stop.store(true, .release);
    kt.join();
    et.join();
    for (bulks) |*b| {
        b.c.dev.close();
        b.c.hub.close();
    }
    ic.dev.close();
    ic.hub.close();
    for (bulks) |*b| {
        if (firstErr(b.sent.err, b.recv.err)) |e| {
            std.debug.print("{s}: bulk transfer failed: {s} after {d}/{d} bytes\n", .{ label, @errorName(e), b.recv.bytes, bytes });
            return e;
        }
        try t.expectEqual(bytes, b.recv.bytes);
        try t.expectEqualSlices(u8, &b.sent.digest, &b.recv.digest);
    }
    if (firstErr(keys.err, keys.echo_err)) |e| {
        std.debug.print("{s}: interactive stream failed: {s} after {d} keystrokes\n", .{ label, @errorName(e), keys.lat.items.len });
        return e;
    }
    std.mem.sort(u64, keys.lat.items, {}, std.sort.asc(u64));
    const items = keys.lat.items;
    const r: Result = .{
        .p50 = pair.percentile(items, 50),
        .p99 = pair.percentile(items, 99),
        .max = if (items.len != 0) items[items.len - 1] else 0,
        .samples = items.len,
        .secs = secs,
    };
    const ds = p.stack.stats();
    std.debug.print("{s}: {d} bulk x {d} MiB in {d:.2} s ({d:.1} MiB/s); keystroke latency p50 {d:.2} ms, p99 {d:.2} ms, max {d:.2} ms over {d} keys; dev retransmits {d} fast {d}, ring drops {d}\n", .{
        label,                        bulk_n,                         bytes / (1024 * 1024),     secs,
        @as(f64, @floatFromInt(bytes * bulk_n)) / (1024.0 * 1024.0) / secs,
        ms(r.p50),                    ms(r.p99),                      ms(r.max),                 r.samples,
        ds.retransmits,               ds.fast_retransmits,            ds.dropped_ring_full,
    });
    // Small -Dnetstack-e2e-mib runs end before many keystrokes; 50 MiB gives thousands.
    try t.expect(r.samples >= @min(@as(usize, 10), @as(usize, @intCast(mib / 8 + 1))));
    return r;
}

fn firstErr(a: ?anyerror, b: ?anyerror) ?anyerror {
    return a orelse b;
}

/// Bytes per bulk stream when `n` share the e2e size (at least 1 MiB).
fn perStream(n: u64) u64 {
    const m: u64 = @max(mib / n, 1);
    return m * 1024 * 1024;
}

fn ms(ns_: u64) f64 {
    return @as(f64, @floatFromInt(ns_)) / 1e6;
}

test "priority: 1 bulk stream + interactive 1-byte writes, 0% loss" {
    try needPriority();
    const r = try run(.{}, 1, mib * 1024 * 1024, "priority 0% loss");
    try t.expect(r.p99 <= 100 * hz.ms);
    try t.expect(r.max <= 1 * hz.sec);
}

test "priority: 1 bulk stream + interactive, 1% loss on all traffic" {
    try needPriority();
    const r = try run(.{ .impairment = .{ .loss_ppm = 10_000 }, .seed = 21 }, 1, mib * 1024 * 1024, "priority 1% loss");
    try t.expect(r.p50 <= 50 * hz.ms);
    try t.expect(r.p99 <= 1500 * hz.ms);
}

test "priority: 1 bulk stream + interactive, 5% loss on all traffic" {
    try needPriority();
    const r = try run(.{ .impairment = .{ .loss_ppm = 50_000 }, .seed = 23 }, 1, mib * 1024 * 1024, "priority 5% loss");
    try t.expect(r.p50 <= 100 * hz.ms);
    try t.expect(r.p99 <= 3 * hz.sec);
}

test "priority: 4 bulk streams at once + interactive, 0% loss" {
    try needPriority();
    const r = try run(.{}, 4, perStream(4), "priority 4 bulk");
    try t.expect(r.p99 <= 100 * hz.ms);
}

test "priority: bulk on max_connections - 1 streams + interactive, 0% loss" {
    try needPriority();
    var limits: ns.Limits = .{};
    limits.max_connections = 8;
    const r = try run(.{ .limits = limits }, limits.max_connections - 1, perStream(8), "priority 7 bulk (max_connections 8)");
    try t.expect(r.p99 <= 150 * hz.ms);
}