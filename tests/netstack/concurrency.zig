//! Concurrency: one reader and one writer thread per stream while the
//! stack threads run, and close / abort / listener close / abortAll racing
//! blocked calls. Every blocking call has a timeout, so a lost wakeup
//! fails as error.Timeout instead of hanging. Windows has no thread
//! sanitizer in this Zig; elsewhere `-Dnetstack-tsan=true` builds with it.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const pair = @import("pair.zig");
const Pair = pair.Pair;

const gpa = t.allocator;
const wait_ns: u64 = 10 * hz.sec;

test "concurrency: 40 connections in a row, a reader and a writer thread per stream on both sides" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    for (0..40) |i| {
        const c = try p.connect(l, if (i % 2 == 0) .interactive else .bulk);
        var s1: pair.Sent = .{};
        var s2: pair.Sent = .{};
        var r1: pair.Received = .{};
        var r2: pair.Received = .{};
        const size: u64 = 256 * 1024 + i * 4099;
        const th = [_]std.Thread{
            try std.Thread.spawn(.{}, pair.sendAll, .{ c.dev, i, size, &s1 }),
            try std.Thread.spawn(.{}, pair.recvAll, .{ c.hub, &r1 }),
            try std.Thread.spawn(.{}, pair.sendAll, .{ c.hub, i + 1000, size, &s2 }),
            try std.Thread.spawn(.{}, pair.recvAll, .{ c.dev, &r2 }),
        };
        for (th) |x| x.join();
        inline for (.{ s1.err, s2.err, r1.err, r2.err }) |e| if (e) |err| return err;
        try t.expectEqualSlices(u8, &s1.digest, &r1.digest);
        try t.expectEqualSlices(u8, &s2.digest, &r2.digest);
        c.dev.close();
        c.hub.close();
    }
}

const Outcome = struct {
    err: ?anyerror = null,
    returned: bool = false,
};

fn blockedRead(st: ns.Stream, out: *Outcome) void {
    var b: [64]u8 = undefined;
    while (true) {
        const n = st.readWait(&b, wait_ns) catch |e| {
            out.err = e;
            break;
        };
        if (n == 0) break;
    }
    out.returned = true;
}

fn blockedWrite(st: ns.Stream, out: *Outcome) void {
    var b: [64 * 1024]u8 = @splat(0x42);
    while (true) {
        st.writeAll(&b, wait_ns) catch |e| {
            out.err = e;
            break;
        };
    }
    out.returned = true;
}

fn blockedAccept(l: ns.Listener, out: *Outcome) void {
    if (l.acceptWait(wait_ns)) |st| {
        st.abort();
    } else |e| out.err = e;
    out.returned = true;
}

test "concurrency: close() wakes a reader blocked in readWait (Closed, not Timeout)" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    for (0..20) |_| {
        const c = try p.connect(l, .interactive);
        var o: Outcome = .{};
        const th = try std.Thread.spawn(.{}, blockedRead, .{ c.hub, &o });
        // Let it block (event-driven: wait for the dev side's write to be
        // read would race the close; a short write round trip does it).
        try c.dev.writeAll("x", wait_ns);
        c.hub.close();
        th.join();
        try t.expect(o.returned);
        if (o.err) |e| try t.expect(e == error.Closed) else return error.ReaderSawEofInsteadOfClosed;
        c.dev.close();
    }
}

test "concurrency: abort() wakes a writer blocked on a full send buffer" {
    var limits: ns.Limits = .{};
    limits.send_buffer = 64 * 1024;
    limits.recv_buffer = 64 * 1024;
    const p = try Pair.create(gpa, .{ .limits = limits });
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    for (0..10) |_| {
        const c = try p.connect(l, .interactive);
        var o: Outcome = .{};
        const th = try std.Thread.spawn(.{}, blockedWrite, .{ c.dev, &o });
        // The hub reads one byte (so the writer is under way), then never
        // again: the writer fills both buffers and blocks in writeAll.
        var b: [1]u8 = undefined;
        _ = try c.hub.readWait(&b, wait_ns);
        c.dev.abort();
        th.join();
        try t.expect(o.returned);
        try t.expect(o.err != null);
        try t.expect(o.err.? == error.Closed or o.err.? == error.ConnectionReset);
        c.hub.close();
    }
}

test "concurrency: listener close wakes acceptWait (Closed)" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    for (0..20) |_| {
        const l = try p.hubStack().listen(8421);
        var o: Outcome = .{};
        const th = try std.Thread.spawn(.{}, blockedAccept, .{ l, &o });
        l.close();
        th.join();
        try t.expect(o.returned);
        try t.expectEqual(@as(?anyerror, error.Closed), o.err);
    }
}

test "concurrency: abortAll wakes every blocked reader, writer and acceptor" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    var cs: [4]@typeInfo(@typeInfo(@TypeOf(Pair.connect)).@"fn".return_type.?).error_union.payload = undefined;
    for (&cs) |*c| c.* = try p.connect(l, .interactive);
    var outs: [9]Outcome = @splat(.{});
    var th: [9]std.Thread = undefined;
    for (cs, 0..) |c, i| {
        th[2 * i] = try std.Thread.spawn(.{}, blockedRead, .{ c.hub, &outs[2 * i] });
        th[2 * i + 1] = try std.Thread.spawn(.{}, blockedRead, .{ c.dev, &outs[2 * i + 1] });
    }
    th[8] = try std.Thread.spawn(.{}, blockedAccept, .{ l, &outs[8] });
    p.hubStack().abortAll();
    p.stack.abortAll();
    for (th) |x| x.join();
    for (outs) |o| {
        try t.expect(o.returned);
        if (o.err) |e| try t.expect(e != error.Timeout) else return error.NotWoken;
    }
    for (cs) |c| {
        c.dev.close();
        c.hub.close();
    }
    l.close();
}

/// Stress: reader + writer threads on both ends while the main thread
/// closes or aborts at a random moment.
fn racer(st: ns.Stream, seed: u64, out: *Outcome) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    var b: [4096]u8 = undefined;
    while (true) {
        if (prng.random().boolean()) {
            st.writeAll(b[0..prng.random().uintLessThan(usize, b.len)], 2 * hz.sec) catch |e| {
                out.err = e;
                break;
            };
        } else {
            const n = st.readWait(&b, 2 * hz.sec) catch |e| {
                if (e == error.Timeout) continue;
                out.err = e;
                break;
            };
            if (n == 0) break;
        }
    }
    out.returned = true;
}

test "concurrency: close / abort racing reads and writes (200 rounds)" {
    const p = try Pair.create(gpa, .{});
    defer p.destroy();
    const l = try p.hubStack().listen(8420);
    defer l.close();
    var prng: std.Random.DefaultPrng = .init(77);
    for (0..200) |round| {
        const c = try p.connect(l, if (round % 3 == 0) .bulk else .interactive);
        var outs: [2]Outcome = @splat(.{});
        const a = try std.Thread.spawn(.{}, racer, .{ c.dev, round, &outs[0] });
        const b = try std.Thread.spawn(.{}, racer, .{ c.hub, round + 5000, &outs[1] });
        // A random number of status round trips before the axe falls.
        for (0..prng.random().uintLessThan(usize, 50)) |_| _ = c.dev.status();
        switch (prng.random().uintLessThan(u8, 4)) {
            0 => c.dev.close(),
            1 => c.dev.abort(),
            2 => c.hub.close(),
            else => c.hub.abort(),
        }
        // The other side ends by EOF / reset; close it once its thread is done
        // with it... except the closed handle: its racer gets Closed.
        a.join();
        b.join();
        c.dev.close();
        c.hub.close();
        for (outs) |o| {
            try t.expect(o.returned);
            if (o.err) |e| try t.expect(e != error.Timeout);
        }
    }
}