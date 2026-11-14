//! Two stacks back to back in manual mode on one virtual clock, with a
//! seeded lossy link between them: the deterministic, single-threaded
//! counterpart of the e2e tests (a failure here replays exactly).
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const H = hz.H;

const gpa = t.allocator;

pub const Link = struct {
    a: *H,
    b: *H,
    prng: std.Random.DefaultPrng,
    loss_ppm: u32,
    moved: u64 = 0,
    dropped: u64 = 0,

    fn lose(l: *Link) bool {
        return l.loss_ppm != 0 and l.prng.random().uintLessThan(u32, 1_000_000) < l.loss_ppm;
    }

    /// Moves every queued packet across (both ways); returns how many.
    pub fn pump(l: *Link) usize {
        var n: usize = 0;
        while (true) {
            var any = false;
            if (l.a.out()) |p| {
                any = true;
                if (l.lose()) l.dropped += 1 else l.b.sendRaw(p);
            }
            if (l.b.out()) |p| {
                any = true;
                if (l.lose()) l.dropped += 1 else l.a.sendRaw(p);
            }
            if (!any) break;
            n += 1;
        }
        l.moved += n;
        return n;
    }

    /// Advances the shared virtual clock to the earliest deadline of either
    /// stack (both stacks' clocks move together). Returns false if none.
    pub fn nextTimer(l: *Link) bool {
        const da = l.a.nextDeadline();
        const db = l.b.nextDeadline();
        // Timers that fired may have queued output and armed nothing yet.
        if (l.pump() != 0) return true;
        const d = if (da) |x| (if (db) |y| @min(x, y) else x) else (db orelse return false);
        l.a.clock.advance(@intCast(@max(d, 1)));
        l.b.clock.advance(@intCast(@max(d, 1)));
        return true;
    }
};

/// One direction, `total` bytes from a's stream to b's, at `loss_ppm` on
/// both directions of the link; returns virtual seconds taken.
fn transfer(loss_ppm: u32, seed: u64, total: usize) !f64 {
    return transferOpts(loss_ppm, seed, total, false);
}

/// `duplex`: b sends `total` bytes back at the same time.
fn transferOpts(loss_ppm: u32, seed: u64, total: usize, duplex: bool) !f64 {
    const a = try H.create(gpa, .{ .address = hz.peer_addr });
    defer a.destroy();
    const b = try H.create(gpa, .{});
    defer b.destroy();
    var link: Link = .{ .a = a, .b = b, .prng = .init(seed), .loss_ppm = loss_ppm };
    const l = try b.stack.listen(8420);
    const sa = try a.stack.dial(.{ .addr = hz.stack_addr, .port = 8420 });
    defer sa.close();
    var sb: ?ns.Stream = null;
    defer if (sb) |s| s.close();
    var sent: usize = 0;
    var got: usize = 0;
    var back_sent: usize = if (duplex) 0 else total;
    var back_got: usize = if (duplex) 0 else total;
    var buf: [16384]u8 = undefined;
    const t0 = a.now();
    var last_progress = t0;
    while (got < total or back_got < total) {
        if (sb == null) sb = l.accept() catch null;
        if (sent < total) {
            const n = @min(buf.len, total - sent);
            hz.fillPattern(99, sent, buf[0..n]);
            sent += sa.write(buf[0..n]) catch |e| switch (e) {
                error.WouldBlock => 0,
                else => return e,
            };
        }
        if (sb) |s| if (back_sent < total) {
            const n = @min(buf.len, total - back_sent);
            hz.fillPattern(77, back_sent, buf[0..n]);
            back_sent += s.write(buf[0..n]) catch |e| switch (e) {
                error.WouldBlock => 0,
                else => return e,
            };
        };
        while (back_got < total) {
            const n = sa.read(&buf) catch |e| switch (e) {
                error.WouldBlock => break,
                else => return e,
            };
            if (n == 0) break;
            for (buf[0..n], 0..) |x, i| if (x != hz.patternByte(77, back_got + i)) return error.CorruptData;
            back_got += n;
            last_progress = a.now();
        }
        if (sb) |s| while (true) {
            const n = s.read(&buf) catch |e| switch (e) {
                error.WouldBlock => break,
                else => return e,
            };
            if (n == 0) break;
            for (buf[0..n], 0..) |x, i| if (x != hz.patternByte(99, got + i)) return error.CorruptData;
            got += n;
            last_progress = a.now();
        };
        if (got >= total and back_got >= total) break;
        if (link.pump() == 0) {
            if (a.now() - last_progress > 70 * @as(i64, hz.sec)) {
                std.debug.print("vlink stalled at {d}/{d} bytes, sent {d}; a: {any} {any}\nb: {any}\n", .{ got, total, sent, sa.status(), a.stats(), b.stats() });
                return error.Stalled;
            }
            if (!link.nextTimer()) {
                std.debug.print("vlink deadlock: no packet and no timer at {d}/{d} bytes (sent {d}); a: {any}; b: {any}\n", .{ got, total, sent, sa.status(), if (sb) |x| x.status() else null });
                return error.NoTimerWhileIncomplete;
            }
        }
    }
    const secs = @as(f64, @floatFromInt(a.now() - t0)) / 1e9;
    std.debug.print("vlink {d} ppm loss: {d} bytes in {d:.2} virtual s; packets {d}, dropped {d}; retransmits a {d} b {d}, fast a {d} b {d}\n", .{ loss_ppm, total, secs, link.moved, link.dropped, a.stats().retransmits, b.stats().retransmits, a.stats().fast_retransmits, b.stats().fast_retransmits });
    return secs;
}

test "vlink: manual stacks back to back, 0% / 1% / 5% / 10% loss, 4 MiB intact, no stall" {
    for ([_]u32{ 0, 10_000, 50_000, 100_000 }, 0..) |loss, i| {
        _ = try transfer(loss, 1000 + i, 4 * 1024 * 1024);
    }
}

test "vlink: 5% loss over many seeds (1 MiB each)" {
    for (0..20) |seed| {
        _ = transfer(50_000, seed, 1024 * 1024) catch |e| {
            std.debug.print("vlink 5% failed with seed {d}\n", .{seed});
            return e;
        };
    }
}
test "vlink: full duplex at 5% loss over many seeds (1 MiB each way)" {
    for (0..20) |seed| {
        _ = transferOpts(50_000, 100 + seed, 1024 * 1024, true) catch |e| {
            std.debug.print("vlink duplex 5% failed with seed {d}\n", .{100 + seed});
            return e;
        };
    }
}