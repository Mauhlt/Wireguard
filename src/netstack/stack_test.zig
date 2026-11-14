//! State-machine tests: the stack driven by hand (input / output /
//! runTimers, no threads) against `testing.Peer`, a crafted TCP peer,
//! with the device clock advanced instead of waiting.
const std = @import("std");
const t = std.testing;
const root = @import("root.zig");
const wire = @import("wire.zig");
const tcp = @import("tcp.zig");
const Peer = root.testing.Peer;

var one: [1]u8 = undefined;
const stack_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 1 } };
const peer_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 2 } };

const Rig = struct {
    clock: root.Clock,
    stack: *root.Stack,
    peer: Peer,
    buf: [2048]u8 = undefined,
    out: [2048]u8 = undefined,

    fn init(r: *Rig, limits: root.Limits) !void {
        r.clock = .{ .io = t.io };
        r.stack = try root.Stack.create(t.allocator, &r.clock, .{ .address = stack_addr, .limits = limits });
        r.peer = .{ .peer = .{ .addr = peer_addr, .port = 40000 }, .stack = .{ .addr = stack_addr, .port = 8420 } };
    }

    fn deinit(r: *Rig) void {
        r.stack.destroy();
    }

    fn send(r: *Rig, s: Peer.Seg) void {
        r.stack.input(r.peer.packet(&r.buf, s));
    }

    /// Next segment the stack sends (must be one).
    fn recv(r: *Rig) !wire.Tcp {
        const p = r.stack.output(&r.out) orelse return error.NothingSent;
        return r.peer.expect(p);
    }

    fn expectSilent(r: *Rig) !void {
        try t.expectEqual(@as(?[]u8, null), r.stack.output(&r.out));
    }

    /// Advance the clock to the next deadline and fire it.
    fn fireNext(r: *Rig) !void {
        const d = r.stack.runTimers() orelse return error.NoTimer;
        const now = r.clock.now();
        if (d > now) r.clock.advance(d - now);
        _ = r.stack.runTimers();
    }

    /// Passive open on 8420: returns (accepted stream, stack ISS + 1, peer seq).
    fn established(r: *Rig, l: root.Listener) !struct { st: root.Stream, snd: u32, rcv: u32 } {
        const iss: u32 = 1000;
        r.send(.{ .seq = iss, .flags = .{ .syn = true }, .options = .{ .mss = 1380, .window_scale = 7 } });
        const sa = try r.recv();
        try t.expect(sa.flags.syn and sa.flags.ack);
        try t.expectEqual(iss + 1, sa.ack);
        try t.expectEqual(@as(?u16, 1380), sa.options.mss);
        try t.expect(sa.options.window_scale != null);
        try t.expectError(error.WouldBlock, l.accept());
        r.send(.{ .seq = iss + 1, .ack = sa.seq +% 1, .flags = .{ .ack = true }, .window = 2048 });
        const st = try l.accept();
        return .{ .st = st, .snd = sa.seq +% 1, .rcv = iss + 1 };
    }
};

test "passive open, data both ways, FIN from the peer, close" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    try t.expectEqual(root.State.established, e.st.status().state);

    // Peer -> stack.
    r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true, .psh = true }, .window = 2048, .payload = "hello" });
    var buf: [64]u8 = undefined;
    try t.expectEqual(@as(usize, 5), try e.st.read(&buf));
    try t.expectEqualStrings("hello", buf[0..5]);
    try t.expectError(error.WouldBlock, e.st.read(&buf));
    // A small segment is ACKed at once.
    const a = try r.recv();
    try t.expectEqual(e.rcv + 5, a.ack);

    // Stack -> peer (no Nagle: goes at once).
    try t.expectEqual(@as(usize, 5), try e.st.write("world"));
    const d = try r.recv();
    try t.expectEqualStrings("world", d.payload);
    try t.expectEqual(e.snd, d.seq);
    // window_scale 7 from the peer: 2048 << 7 bytes of window.
    r.send(.{ .seq = e.rcv + 5, .ack = e.snd + 5, .flags = .{ .ack = true, .fin = true }, .window = 2048 });
    const fa = try r.recv();
    try t.expectEqual(e.rcv + 6, fa.ack);
    try t.expectEqual(@as(usize, 0), try e.st.read(&buf)); // EOF
    try t.expectEqual(root.State.close_wait, e.st.status().state);

    e.st.close();
    const fin = try r.recv();
    try t.expect(fin.flags.fin);
    try t.expectEqual(e.snd + 5, fin.seq);
    r.send(.{ .seq = e.rcv + 6, .ack = e.snd + 6, .flags = .{ .ack = true }, .window = 2048 });
    try r.expectSilent();
    try t.expectEqual(@as(u16, 0), r.stack.stats().connections);
    try t.expectEqual(root.State.closed, e.st.status().state); // stale handle
    try t.expectError(error.Closed, e.st.read(&buf));
}

test "active open, our FIN first, TIME-WAIT then freed" {
    var r: Rig = undefined;
    try r.init(.{ .time_wait_ns = 50 * std.time.ns_per_ms });
    defer r.deinit();
    const st = try r.stack.dial(.{ .addr = peer_addr, .port = 9000 });
    r.peer.peer.port = 9000;
    const syn = (try wire.parseTcp4(r.stack.output(&r.out).?)).tcp;
    try t.expect(syn.flags.syn and !syn.flags.ack);
    r.peer.stack.port = syn.src_port;
    try t.expect(syn.src_port >= 49152);
    try t.expectEqual(root.State.syn_sent, st.status().state);
    try t.expectError(error.WouldBlock, st.read(&one));

    r.send(.{ .seq = 5000, .ack = syn.seq +% 1, .flags = .{ .syn = true, .ack = true }, .options = .{ .mss = 1000 } });
    const ack = try r.recv();
    try t.expectEqual(@as(u32, 5001), ack.ack);
    try st.waitConnected(0);
    try t.expectEqual(root.State.established, st.status().state);

    st.shutdown();
    const fin = try r.recv();
    try t.expect(fin.flags.fin);
    try t.expectEqual(root.State.fin_wait_1, st.status().state);
    r.send(.{ .seq = 5001, .ack = fin.seq +% 1, .flags = .{ .ack = true, .fin = true } });
    _ = try r.recv(); // ACK of their FIN
    try t.expectEqual(root.State.time_wait, st.status().state);
    try r.fireNext();
    try t.expectEqual(root.State.closed, st.status().state);
    var b: [4]u8 = undefined;
    try t.expectEqual(@as(usize, 0), try st.read(&b));
    st.close();
    try t.expectEqual(@as(u16, 0), r.stack.stats().connections);
}

test "SYN to a closed port gets RST, RST answers nothing, connect refused" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    r.send(.{ .seq = 77, .flags = .{ .syn = true } });
    const rst = try r.recv();
    try t.expect(rst.flags.rst and rst.flags.ack);
    try t.expectEqual(@as(u32, 78), rst.ack);
    r.send(.{ .seq = 77, .flags = .{ .rst = true } });
    try r.expectSilent();

    const st = try r.stack.dial(.{ .addr = peer_addr, .port = 9000 });
    r.peer.peer.port = 9000;
    const syn = (try wire.parseTcp4(r.stack.output(&r.out).?)).tcp;
    r.peer.stack.port = syn.src_port;
    r.send(.{ .seq = 0, .ack = syn.seq +% 1, .flags = .{ .rst = true, .ack = true } });
    try t.expectError(error.ConnectionRefused, st.waitConnected(0));
    try t.expectError(error.ConnectionRefused, st.read(&one));
    st.close();
}

test "retransmission after loss: RTO, backoff, Karn" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    const t0 = r.clock.now();
    _ = try e.st.write("lost");
    const first = try r.recv(); // dropped by the "network"
    try r.expectSilent();
    try r.fireNext();
    const again = try r.recv();
    try t.expectEqual(first.seq, again.seq);
    try t.expectEqualStrings("lost", again.payload);
    const rto1 = r.clock.now() - t0;
    try t.expect(rto1 >= tcp.min_rto_ns);
    // Second loss: the RTO doubles.
    const t1 = r.clock.now();
    try r.fireNext();
    _ = try r.recv();
    try t.expect(r.clock.now() - t1 >= 2 * rto1 - std.time.ns_per_ms);
    r.send(.{ .seq = e.rcv, .ack = e.snd + 4, .flags = .{ .ack = true }, .window = 2048 });
    try t.expectEqual(@as(?i64, null), r.stack.runTimers()); // RTO disarmed
    try t.expect(r.stack.stats().retransmits >= 2);
}

test "user timeout: an unanswered connection fails" {
    var r: Rig = undefined;
    try r.init(.{ .user_timeout_ns = 3 * std.time.ns_per_s });
    defer r.deinit();
    const st = try r.stack.dial(.{ .addr = peer_addr, .port = 9000 });
    var n: usize = 0;
    while (n < 20) : (n += 1) {
        while (r.stack.output(&r.out)) |_| {}
        r.fireNext() catch break;
    }
    try t.expectError(error.ConnectionTimedOut, st.waitConnected(0));
    st.close();
    try t.expectEqual(@as(u16, 0), r.stack.stats().connections);
}

test "out-of-order segments: dup ACK, then both delivered in order" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    r.send(.{ .seq = e.rcv + 3, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048, .payload = "def" });
    const dup = try r.recv();
    try t.expectEqual(e.rcv, dup.ack); // still waiting for byte 0
    var buf: [16]u8 = undefined;
    try t.expectError(error.WouldBlock, e.st.read(&buf));
    r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048, .payload = "abc" });
    const a = try r.recv();
    try t.expectEqual(e.rcv + 6, a.ack);
    try t.expectEqual(@as(usize, 6), try e.st.read(&buf));
    try t.expectEqualStrings("abcdef", buf[0..6]);
    // A duplicate of old data is just ACKed again.
    r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048, .payload = "abc" });
    try t.expectEqual(e.rcv + 6, (try r.recv()).ack);
    try t.expectError(error.WouldBlock, e.st.read(&buf));
}

test "fast retransmit on three duplicate ACKs" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    var data: [4 * 1380]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    try t.expectEqual(data.len, try e.st.write(&data));
    var segs: [4]wire.Tcp = undefined;
    for (&segs) |*sg| sg.* = try r.recv();
    try t.expectEqual(@as(usize, 1380), segs[0].payload.len);
    // Segment 0 lost; 1, 2, 3 arrive: three duplicate ACKs.
    for (0..3) |_| r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048 });
    const re = try r.recv();
    try t.expectEqual(segs[0].seq, re.seq);
    try t.expectEqual(@as(u64, 1), r.stack.stats().fast_retransmits);
    // Full ACK ends recovery.
    r.send(.{ .seq = e.rcv, .ack = e.snd +% @as(u32, data.len), .flags = .{ .ack = true }, .window = 2048 });
    try r.expectSilent();
}

test "zero window: no data, persist probe, resumes when the window opens" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true }, .window = 0 });
    _ = try e.st.write("blocked");
    try r.expectSilent();
    try r.fireNext(); // persist timer
    const probe = try r.recv();
    try t.expectEqual(e.snd -% 1, probe.seq); // out-of-window probe, no data
    try t.expectEqual(@as(usize, 0), probe.payload.len);
    r.send(.{ .seq = e.rcv, .ack = e.snd, .flags = .{ .ack = true }, .window = 100 });
    const d = try r.recv();
    try t.expectEqualStrings("blocked", d.payload);
}

test "receive window: we advertise what is free, never accept beyond it" {
    var r: Rig = undefined;
    try r.init(.{ .recv_buffer = 4096, .send_buffer = 4096 });
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    var big: [1380]u8 = @splat('x');
    var seq = e.rcv;
    var sent: usize = 0;
    while (sent + big.len <= 4096) : (sent += big.len) {
        r.send(.{ .seq = seq, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048, .payload = &big });
        seq +%= big.len;
    }
    var last: wire.Tcp = undefined;
    while (r.stack.output(&r.out)) |p| last = try r.peer.expect(p);
    try t.expectEqual(seq, last.ack);
    const free_left = 4096 - sent;
    // recv_buffer 4096 needs no scaling.
    try t.expectEqual(@as(u16, @intCast(free_left)), last.window);
    // Beyond the window: trimmed to what fits.
    r.send(.{ .seq = seq, .ack = e.snd, .flags = .{ .ack = true }, .window = 2048, .payload = &big });
    while (r.stack.output(&r.out)) |p| last = try r.peer.expect(p);
    try t.expectEqual(seq +% @as(u32, @intCast(free_left)), last.ack);
    try t.expectEqual(@as(u16, 0), last.window);
    // Reading opens it again, with a window update.
    var sink: [4096]u8 = undefined;
    try t.expectEqual(@as(usize, 4096), try e.st.read(&sink));
    const upd = try r.recv();
    try t.expectEqual(@as(u16, 4096), upd.window);
}

test "RST in window but not exact: challenge ACK; exact: reset" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const e = try r.established(l);
    r.send(.{ .seq = e.rcv + 10, .flags = .{ .rst = true } });
    const ch = try r.recv();
    try t.expectEqual(e.rcv, ch.ack);
    try t.expectEqual(root.State.established, e.st.status().state);
    r.send(.{ .seq = e.rcv, .flags = .{ .rst = true } });
    try t.expectError(error.ConnectionReset, e.st.read(&one));
    e.st.close();
    try t.expectEqual(@as(u16, 0), r.stack.stats().connections);
}

test "SYN backlog cap, half-open expiry" {
    var r: Rig = undefined;
    try r.init(.{ .syn_backlog = 2 });
    defer r.deinit();
    _ = try r.stack.listen(8420);
    for (0..5) |i| {
        r.peer.peer.port = @intCast(41000 + i);
        r.send(.{ .seq = 1, .flags = .{ .syn = true } });
    }
    var synacks: usize = 0;
    while (r.stack.output(&r.out)) |_| synacks += 1;
    try t.expectEqual(@as(usize, 2), synacks);
    try t.expectEqual(@as(u64, 3), r.stack.stats().dropped_syn_backlog);
    try t.expectEqual(@as(u16, 2), r.stack.stats().connections);
    // Unanswered SYN-ACKs: dropped after max_synack_retries.
    var n: usize = 0;
    while (r.stack.stats().connections != 0 and n < 20) : (n += 1) {
        try r.fireNext();
        while (r.stack.output(&r.out)) |_| {}
    }
    try t.expectEqual(@as(u16, 0), r.stack.stats().connections);
}

test "malformed and foreign packets are dropped silently" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    _ = try r.stack.listen(8420);
    var p = r.peer.packet(&r.buf, .{ .seq = 1, .flags = .{ .syn = true } });
    p[p.len - 1] ^= 0xff; // TCP checksum
    r.stack.input(p);
    r.stack.input(&.{ 0x45, 0, 0 });
    const zeros: [40]u8 = @splat(0);
    r.stack.input(&zeros);
    try r.expectSilent();
    try t.expectEqual(@as(u64, 3), r.stack.stats().dropped_malformed);
    // Not our address.
    r.peer.stack.addr = .{ .v4 = .{ 10, 8, 0, 9 } };
    r.send(.{ .seq = 1, .flags = .{ .syn = true } });
    try r.expectSilent();
    try t.expectEqual(@as(u64, 1), r.stack.stats().dropped_not_for_us);
}

test "ICMP echo request gets a reply" {
    var r: Rig = undefined;
    try r.init(.{});
    defer r.deinit();
    var msg = [_]u8{ wire.icmp_echo_request, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g' };
    std.mem.writeInt(u16, msg[2..4], wire.checksum(&msg), .big);
    try (wire.Ip4{ .protocol = wire.proto_icmp, .src = peer_addr.v4, .dst = stack_addr.v4 }).write(&r.buf, msg.len);
    @memcpy(r.buf[20..][0..msg.len], &msg);
    r.stack.input(r.buf[0 .. 20 + msg.len]);
    const reply = r.stack.output(&r.out).?;
    const ip = try wire.Ip4.parse(reply);
    try t.expectEqual(peer_addr.v4, ip.header.dst);
    try t.expectEqual(wire.icmp_echo_reply, try wire.icmp4Type(ip.payload));
    try t.expectEqualStrings("ping", ip.payload[8..]);
}

test "bulk stream: write stops at the unsent low-watermark; interactive goes first" {
    var r: Rig = undefined;
    try r.init(.{ .bulk_unsent_lowat = 8 * 1024 });
    defer r.deinit();
    const l = try r.stack.listen(8420);
    const bulk = try r.established(l);
    bulk.st.setPriority(.bulk);
    // Zero window from the peer: nothing leaves, so nothing is "sent".
    r.send(.{ .seq = bulk.rcv, .ack = bulk.snd, .flags = .{ .ack = true }, .window = 0 });
    var big: [32 * 1024]u8 = @splat('b');
    try t.expectEqual(@as(usize, 8 * 1024), try bulk.st.write(&big));
    try t.expectError(error.WouldBlock, bulk.st.write(&big));
    try t.expect(!bulk.st.status().writable);

    // Open the bulk window, then an interactive stream writes: its
    // segment is scheduled before the bulk backlog.
    r.send(.{ .seq = bulk.rcv, .ack = bulk.snd, .flags = .{ .ack = true }, .window = 0xffff });
    r.peer.peer.port = 40001;
    const inter = try r.established(l);
    _ = try inter.st.write("key");
    const first = try r.recv();
    try t.expectEqual(@as(u16, 40001), first.dst_port);
    try t.expectEqualStrings("key", first.payload);
}

/// Two manually driven stacks joined by an in-process link with seeded
/// loss and reordering. When the link is idle the shared clock jumps to
/// the earliest timer deadline, so a run is fast and deterministic.
const Link = struct {
    clock: root.Clock,
    a: *root.Stack,
    b: *root.Stack,
    prng: std.Random.DefaultPrng,
    loss_ppm: u32,
    reorder_ppm: u32,
    dup_ppm: u32 = 0,
    held: ?struct { to_b: bool, len: usize } = null,
    held_buf: [2048]u8 = undefined,
    buf: [2048]u8 = undefined,
    dropped: usize = 0,

    fn init(l: *Link, seed: u64, loss_ppm: u32, reorder_ppm: u32, limits: root.Limits) !void {
        l.* = .{ .clock = .{ .io = t.io }, .a = undefined, .b = undefined, .prng = .init(seed), .loss_ppm = loss_ppm, .reorder_ppm = reorder_ppm };
        l.a = try root.Stack.create(t.allocator, &l.clock, .{ .address = stack_addr, .limits = limits });
        l.b = try root.Stack.create(t.allocator, &l.clock, .{ .address = peer_addr, .limits = limits });
    }

    fn deinit(l: *Link) void {
        l.a.destroy();
        l.b.destroy();
    }

    fn hit(l: *Link, ppm: u32) bool {
        return ppm != 0 and l.prng.random().uintLessThan(u32, 1_000_000) < ppm;
    }

    /// Moves every pending packet once; returns how many moved.
    fn pump(l: *Link) usize {
        var moved: usize = 0;
        for ([_]bool{ true, false }) |to_b| {
            const from = if (to_b) l.a else l.b;
            const to = if (to_b) l.b else l.a;
            while (from.output(&l.buf)) |p| {
                moved += 1;
                if (l.hit(l.loss_ppm)) {
                    l.dropped += 1;
                    continue;
                }
                if (l.held == null and l.hit(l.reorder_ppm)) {
                    @memcpy(l.held_buf[0..p.len], p);
                    l.held = .{ .to_b = to_b, .len = p.len };
                    continue;
                }
                to.input(p);
                if (l.hit(l.dup_ppm)) to.input(p);
                if (l.held) |h| {
                    l.held = null;
                    (if (h.to_b) l.b else l.a).input(l.held_buf[0..h.len]);
                }
            }
        }
        return moved;
    }

    /// Runs until `done` or no packet and no timer is left.
    fn run(l: *Link, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool) !void {
        var idle_rounds: usize = 0;
        while (true) {
            ctx.step();
            if (done(ctx)) return;
            if (l.pump() > 0) {
                idle_rounds = 0;
                continue;
            }
            if (l.held) |h| {
                l.held = null;
                (if (h.to_b) l.b else l.a).input(l.held_buf[0..h.len]);
                continue;
            }
            const da = l.a.runTimers();
            const db = l.b.runTimers();
            if (l.pump() > 0) continue; // a timer that was already due fired
            const d = if (da != null and db != null) @min(da.?, db.?) else da orelse db orelse return error.Stalled;
            const now = l.clock.now();
            if (d > now) l.clock.advance(d - now);
            _ = l.a.runTimers();
            _ = l.b.runTimers();
            idle_rounds += 1;
            if (idle_rounds > 10_000) return error.Stalled;
        }
    }
};

const Both = struct {
    ab: Transfer,
    ba: Transfer,
    fn step(x: *Both) void {
        x.ab.step();
        x.ba.step();
    }
    fn done(x: *Both) bool {
        return x.ab.eof and x.ba.eof;
    }
};

fn bothWays(seed: u64, loss_ppm: u32, reorder_ppm: u32, dup_ppm: u32, size: usize) !void {
    var l: Link = undefined;
    try l.init(seed, loss_ppm, reorder_ppm, .{});
    defer l.deinit();
    l.dup_ppm = dup_ppm;
    const lis = try l.b.listen(8420);
    const c = try l.a.dial(.{ .addr = peer_addr, .port = 8420 });
    var srv: ?root.Stream = null;
    var guard: usize = 0;
    while (srv == null) : (guard += 1) {
        if (guard > 1000) return error.NoAccept;
        if (l.pump() == 0) {
            const d = l.a.runTimers() orelse l.b.runTimers() orelse return error.Stalled;
            const now = l.clock.now();
            if (d > now) l.clock.advance(d - now);
            _ = l.a.runTimers();
            _ = l.b.runTimers();
        }
        srv = lis.accept() catch null;
    }
    const d1 = try t.allocator.alloc(u8, size);
    defer t.allocator.free(d1);
    const d2 = try t.allocator.alloc(u8, size);
    defer t.allocator.free(d2);
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(d1);
    prng.random().bytes(d2);
    var x: Both = .{ .ab = .{ .tx = c, .rx = srv.?, .data = d1 }, .ba = .{ .tx = srv.?, .rx = c, .data = d2 } };
    defer x.ab.got.deinit(t.allocator);
    defer x.ba.got.deinit(t.allocator);
    l.run(&x, Both.done) catch |e| {
        var pr: [1]u8 = undefined;
        std.debug.print("errors: a={any} b={any}\n", .{ c.read(&pr), srv.?.read(&pr) });
        for ([_]root.Stream{ c, srv.? }) |s| if (s.debugConn()) |k| std.debug.print("  {t} una={d} nxt={d} max={d} base={d} wnd={d} cwnd={d} ssth={d} rec={} rcv_nxt={d} rcvlen={d} ooo={d} unsent={d} sndlen={d} rto_at={?d} persist={?d} rto={d} backoff={d} fin_q={} eof={} err={?}\n", .{ k.state, k.snd_una, k.snd_nxt, k.snd_max, k.snd_base, k.snd_wnd, k.cwnd, k.ssthresh, k.in_recovery, k.rcv_nxt, k.rcv.len, k.ooo_len, k.unsent(), k.snd.len, k.rto_at, k.persist_at, k.rto, k.backoff, k.fin_queued, k.eof, k.err }) else std.debug.print("  (stale)\n", .{});
        if (l.a.output(&l.buf)) |p| std.debug.print("a would send {any}\n", .{(try wire.parseTcp4(p)).tcp}) else std.debug.print("a sends nothing\n", .{});
        std.debug.print("stalled both ways (seed {d}): ab sent {d} got {d}, ba sent {d} got {d}, dropped {d}\n  a={any}\n  b={any}\n", .{ seed, x.ab.sent, x.ab.got.items.len, x.ba.sent, x.ba.got.items.len, l.dropped, c.status(), srv.?.status() });
        return e;
    };
    try t.expectEqualSlices(u8, d1, x.ab.got.items);
    try t.expectEqualSlices(u8, d2, x.ba.got.items);
}

test "both ends in go-back-N after a blackout still recover (pure ACKs at snd_max)" {
    var l: Link = undefined;
    try l.init(99, 0, 0, .{});
    defer l.deinit();
    const lis = try l.b.listen(8420);
    const c = try l.a.dial(.{ .addr = peer_addr, .port = 8420 });
    _ = l.pump();
    _ = l.pump();
    const s = try lis.accept();
    var data: [8 * 1380]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7);
    _ = try c.write(&data);
    _ = try s.write(&data);
    // Both send their whole window before hearing from the other (so no
    // segment acknowledges the other's data), the data crosses, and every
    // ACK after that is lost: both time out and go back to snd_una while
    // the peer already holds everything.
    var buf: [2048]u8 = undefined;
    var from_a: std.ArrayList([]u8) = .empty;
    var from_b: std.ArrayList([]u8) = .empty;
    defer {
        for (from_a.items) |p| t.allocator.free(p);
        for (from_b.items) |p| t.allocator.free(p);
        from_a.deinit(t.allocator);
        from_b.deinit(t.allocator);
    }
    while (l.a.output(&buf)) |p| try from_a.append(t.allocator, try t.allocator.dupe(u8, p));
    while (l.b.output(&buf)) |p| try from_b.append(t.allocator, try t.allocator.dupe(u8, p));
    try t.expect(from_a.items.len >= 8 and from_b.items.len >= 8);
    for (from_a.items) |p| l.b.input(p);
    for (from_b.items) |p| l.a.input(p);
    while (l.a.output(&buf)) |_| {} // ACKs: lost
    while (l.b.output(&buf)) |_| {}
    const rto_at = l.a.runTimers() orelse return error.NoTimer;
    const t_now = l.clock.now();
    if (rto_at > t_now) l.clock.advance(rto_at - t_now + std.time.ns_per_ms);
    _ = l.a.runTimers();
    _ = l.b.runTimers();
    try t.expect(c.debugConn().?.snd_nxt != c.debugConn().?.snd_max);
    try t.expect(s.debugConn().?.snd_nxt != s.debugConn().?.snd_max);
    // Now the link is clean: both must drain completely.
    var guard: usize = 0;
    while (guard < 1000) : (guard += 1) {
        if (l.pump() == 0) {
            const ka = c.debugConn().?;
            const kb = s.debugConn().?;
            if (ka.snd_una == ka.snd_max and kb.snd_una == kb.snd_max) break;
            const d = l.a.runTimers() orelse l.b.runTimers() orelse return error.Stalled;
            const now = l.clock.now();
            if (d > now) l.clock.advance(d - now);
            _ = l.a.runTimers();
            _ = l.b.runTimers();
        }
    }
    try t.expectEqual(c.debugConn().?.snd_max, c.debugConn().?.snd_una);
    try t.expectEqual(s.debugConn().?.snd_max, s.debugConn().?.snd_una);
    var got: [data.len]u8 = undefined;
    try t.expectEqual(data.len, try c.read(&got));
    try t.expectEqualSlices(u8, &data, &got);
}

test "two stacks, both directions at once, loss + reordering + duplication" {
    for (0..40) |seed| try bothWays(seed + 10, 10_000, 10_000, 2_000, 1 << 20);
}

const Transfer = struct {
    tx: root.Stream,
    rx: root.Stream,
    data: []const u8,
    sent: usize = 0,
    got: std.ArrayList(u8) = .empty,
    eof: bool = false,

    fn step(x: *Transfer) void {
        while (x.sent < x.data.len) {
            const n = x.tx.write(x.data[x.sent..]) catch break;
            x.sent += n;
            if (x.sent == x.data.len) x.tx.shutdown();
        }
        var buf: [16 * 1024]u8 = undefined;
        while (true) {
            const n = x.rx.read(&buf) catch break;
            if (n == 0) {
                x.eof = true;
                break;
            }
            x.got.appendSlice(t.allocator, buf[0..n]) catch @panic("oom");
        }
    }

    fn done(x: *Transfer) bool {
        return x.eof;
    }
};

fn lossyTransfer(seed: u64, loss_ppm: u32, reorder_ppm: u32, size: usize) !void {
    var l: Link = undefined;
    try l.init(seed, loss_ppm, reorder_ppm, .{ .recv_buffer = 64 * 1024, .send_buffer = 64 * 1024 });
    defer l.deinit();
    const lis = try l.b.listen(8420);
    const c = try l.a.dial(.{ .addr = peer_addr, .port = 8420 });
    var srv: ?root.Stream = null;
    var guard: usize = 0;
    while (srv == null) : (guard += 1) {
        if (guard > 1000) return error.NoAccept;
        if (l.pump() == 0) {
            const d = l.a.runTimers() orelse l.b.runTimers() orelse return error.Stalled;
            const now = l.clock.now();
            if (d > now) l.clock.advance(d - now);
            _ = l.a.runTimers();
            _ = l.b.runTimers();
        }
        srv = lis.accept() catch null;
    }
    const data = try t.allocator.alloc(u8, size);
    defer t.allocator.free(data);
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(data);
    var x: Transfer = .{ .tx = c, .rx = srv.?, .data = data };
    defer x.got.deinit(t.allocator);
    l.run(&x, Transfer.done) catch |e| {
        std.debug.print("stalled: sent {d} got {d} dropped {d} a={any} b={any}\n", .{ x.sent, x.got.items.len, l.dropped, c.status(), srv.?.status() });
        return e;
    };
    try t.expectEqualSlices(u8, data, x.got.items);
    const st = l.a.stats();
    std.debug.print("lossy link seed {d} loss {d} reorder {d}: {d} KiB in {d} ms simulated, rto {d} fast {d} retrans {d} dropped {d}\n", .{ seed, loss_ppm, reorder_ppm, size / 1024, @divTrunc(l.clock.offset_ns.load(.monotonic), std.time.ns_per_ms), st.rto_expirations, st.fast_retransmits, st.retransmits, l.dropped });
}

test "two stacks over a lossy, reordering link: data intact" {
    try lossyTransfer(1, 0, 0, 1 << 20);
    try lossyTransfer(2, 10_000, 0, 1 << 20);
    try lossyTransfer(3, 10_000, 10_000, 1 << 20);
    try lossyTransfer(4, 50_000, 20_000, 256 << 10);
}
