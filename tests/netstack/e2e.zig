//! End to end over the real stack: two zwg devices over UDP on 127.0.0.1,
//! each with a netstack as its Tun. Full-duplex transfers with SHA-256
//! checks at 0% / 1% / 5% loss (plus reordering and duplication), and the
//! std.Io reader / writer adapters.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const pair = @import("pair.zig");
const Pair = pair.Pair;

const gpa = t.allocator;
const mib: u64 = hz.options.e2e_mib;

test "e2e: Node pair: dial, echo both ways, half close, EOF; std.Io reader / writer" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    const c = try p.connect(l, .interactive);
    defer c.dev.close();
    defer c.hub.close();
    try t.expectEqual(ns.State.established, c.dev.status().state);
    try t.expectEqual(@as(u16, 8420), c.dev.remote().port);
    try t.expectEqualSlices(u8, &pair.dev_addr.v4, &c.hub.remote().addr.v4);

    var wbuf: [256]u8 = undefined;
    var w = c.dev.writer(&wbuf, 10 * hz.sec);
    try w.interface.print("hello over the tunnel {d}\n", .{42});
    try w.interface.flush();
    var rbuf: [256]u8 = undefined;
    var r = c.hub.reader(&rbuf, 10 * hz.sec);
    const line = try r.interface.takeDelimiterInclusive('\n');
    try t.expectEqualStrings("hello over the tunnel 42\n", line);

    try c.hub.writeAll("reply", 10 * hz.sec);
    c.hub.shutdown();
    var got: [16]u8 = undefined;
    var n: usize = 0;
    while (true) {
        const k = try c.dev.readWait(got[n..], 10 * hz.sec);
        if (k == 0) break;
        n += k;
    }
    try t.expectEqualStrings("reply", got[0..n]);
    // Reader at EOF: EndOfStream, no error recorded.
    c.dev.shutdown();
    try t.expectError(error.EndOfStream, r.interface.takeByte());
    try t.expectEqual(@as(?ns.ReadError, null), r.err);
}

pub const Report = struct {
    elapsed_ns: u64,
    dev: ns.Stats,
    hub: ns.Stats,
};

/// `total` bytes each way at once on one connection; checks SHA-256 and
/// byte counts on both sides.
pub fn duplex(p: *Pair, total: u64, prio: ns.Priority) !Report {
    const l = try p.hubStack().listen(8420);
    defer l.close();
    const c = try p.connect(l, prio);
    defer c.dev.close();
    defer c.hub.close();
    var s_dev: pair.Sent = .{};
    var s_hub: pair.Sent = .{};
    var r_dev: pair.Received = .{};
    var r_hub: pair.Received = .{};
    const t0 = p.now();
    const th = [_]std.Thread{
        try std.Thread.spawn(.{}, pair.sendAll, .{ c.dev, 1, total, &s_dev }),
        try std.Thread.spawn(.{}, pair.recvAll, .{ c.hub, &r_hub }),
        try std.Thread.spawn(.{}, pair.sendAll, .{ c.hub, 2, total, &s_hub }),
        try std.Thread.spawn(.{}, pair.recvAll, .{ c.dev, &r_dev }),
    };
    for (th) |x| x.join();
    const elapsed: u64 = @intCast(p.now() - t0);
    inline for (.{ s_dev.err, s_hub.err, r_dev.err, r_hub.err }) |e| if (e) |err| {
        std.debug.print("transfer failed after {d} ms: {s} (dev sent {d}, hub got {d}, hub sent {d}, dev got {d}); dev {any}; hub {any}\n", .{ elapsed / hz.ms, @errorName(err), s_dev.bytes, r_hub.bytes, s_hub.bytes, r_dev.bytes, p.stack.stats(), p.hubStack().stats() });
        return err;
    };
    try t.expectEqual(total, r_hub.bytes);
    try t.expectEqual(total, r_dev.bytes);
    try t.expectEqualSlices(u8, &s_dev.digest, &r_hub.digest);
    try t.expectEqualSlices(u8, &s_hub.digest, &r_dev.digest);
    return .{ .elapsed_ns = elapsed, .dev = p.stack.stats(), .hub = p.hubStack().stats() };
}

pub fn printReport(label: []const u8, p: *Pair, total: u64, r: Report) void {
    const secs = @as(f64, @floatFromInt(r.elapsed_ns)) / 1e9;
    const mbps = @as(f64, @floatFromInt(2 * total)) / (1024.0 * 1024.0) / secs;
    std.debug.print("e2e {s}: {d} MiB each way in {d:.2} s = {d:.1} MiB/s total; retransmits dev {d} hub {d}, fast dev {d} hub {d}, timeouts {d}/{d}, ring drops {d}/{d}", .{
        label,             total / (1024 * 1024), secs,                    mbps,
        r.dev.retransmits, r.hub.retransmits,     r.dev.fast_retransmits,  r.hub.fast_retransmits,
        r.dev.timeouts,    r.hub.timeouts,        r.dev.dropped_ring_full, r.hub.dropped_ring_full,
    });
    if (p.impaired) |it| std.debug.print("; impaired: dropped {d}, reordered {d}, duplicated {d}, passed {d}", .{ it.counts.dropped, it.counts.reordered, it.counts.duplicated, it.counts.passed });
    std.debug.print("\n", .{});
}

test "e2e: 0% loss (two ns.Node): full duplex, SHA-256 both ways" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const total = mib * 1024 * 1024;
    const r = try duplex(p, total, .interactive);
    printReport("0% loss", p, total, r);
}

test "e2e: ImpairedTun 0% (pass-through): full duplex, SHA-256 both ways" {
    const p = try Pair.create(gpa, .{ .impairment = .{}, .seed = 7 });
    defer p.destroy();
    const total = mib * 1024 * 1024;
    const r = try duplex(p, total, .interactive);
    printReport("ImpairedTun 0%", p, total, r);
}

test "e2e: 1% loss + 1% reorder + 0.1% duplication: full duplex, SHA-256 both ways" {
    const p = try Pair.create(gpa, .{ .impairment = .{ .loss_ppm = 10_000, .reorder_ppm = 10_000, .duplicate_ppm = 1_000 }, .seed = 11 });
    defer p.destroy();
    const total = mib * 1024 * 1024;
    const r = try duplex(p, total, .interactive);
    printReport("1% loss", p, total, r);
    try t.expect(r.dev.retransmits + r.hub.retransmits + r.dev.fast_retransmits + r.hub.fast_retransmits > 0);
}

test "e2e: 5% loss + 2% reorder + 0.5% duplication: full duplex, SHA-256 both ways" {
    const p = try Pair.create(gpa, .{ .impairment = .{ .loss_ppm = 50_000, .reorder_ppm = 20_000, .duplicate_ppm = 5_000 }, .seed = 13 });
    defer p.destroy();
    const total = mib * 1024 * 1024;
    const r = try duplex(p, total, .interactive);
    printReport("5% loss", p, total, r);
}

test "e2e: IPv6 inside the tunnel, 0% and 1% loss: full duplex, SHA-256 both ways" {
    {
        const p = try Pair.create(gpa, .{ .v6 = true });
        defer p.destroy();
        const total = mib * 1024 * 1024;
        const r = try duplex(p, total, .interactive);
        printReport("IPv6 0% loss", p, total, r);
    }
    {
        const p = try Pair.create(gpa, .{ .v6 = true, .impairment = .{ .loss_ppm = 10_000, .reorder_ppm = 10_000 }, .seed = 17 });
        defer p.destroy();
        const total = mib * 1024 * 1024;
        const r = try duplex(p, total, .interactive);
        printReport("IPv6 1% loss", p, total, r);
    }
}

test "e2e: TLS smoke test through Stream.reader / writer" {
    // std.crypto.tls has only a Client in this Zig, and the repo has no
    // TLS server to test against.
    return hz.skip("no TLS server in Zig std (std.crypto.tls has only Client) or in the repo");
}
