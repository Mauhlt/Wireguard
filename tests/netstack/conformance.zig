//! Conformance: RFC 9293 (state machine), RFC 6298 (RTO, Karn), RFC 5681
//! (fast retransmit, ACK rules), RFC 6528 (ISNs), RFC 7323 (window scale
//! negotiation), driven in manual mode on a virtual clock.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const wire = hz.wire;
const H = hz.H;
const Peer = hz.Peer;
const ms = hz.ms;
const sec = hz.sec;

const gpa = t.allocator;

// ---------------------------------------------------------------- handshakes

test "conformance: passive open: SYN-ACK has MSS 1380, window scale only when offered" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    try t.expectEqual(@as(u16, 8420), l.port());

    var c = try hz.openPassive(h, l, .{});
    try t.expectEqual(@as(?u16, 1380), c.syn_options.mss);
    try t.expectEqual(@as(?u8, null), c.syn_options.window_scale); // RFC 7323 1.3
    try t.expectEqual(ns.State.established, c.state());
    try t.expectEqual(@as(u16, 40000), c.stream.remote().port);
    try t.expectEqual(@as(u16, 8420), c.stream.local().port);
    try t.expectEqualSlices(u8, &hz.peer_ip, &c.stream.remote().addr.v4);

    var c2 = try hz.openPassive(h, l, .{ .peer_port = 40001, .syn_options = .{ .mss = 1380, .window_scale = 7 } });
    try t.expect(c2.syn_options.window_scale != null);
    try t.expect(c2.syn_options.window_scale.? <= wire.max_window_scale);
    c.stream.abort();
    c2.stream.abort();
}

test "conformance: active open: SYN has MSS 1380 + window scale, SYN-ACK -> ACK -> ESTABLISHED" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    var c = try hz.openActive(h, .{});
    try t.expectEqual(@as(?u16, 1380), c.syn_options.mss);
    try t.expect(c.syn_options.window_scale != null);
    try t.expectEqual(ns.State.established, c.state());
    try t.expect(c.peer.stack.port != 0);
    try t.expectEqual(@as(u16, 443), c.stream.remote().port);
    c.stream.abort();
}

test "conformance: SYN-SENT: RST without ACK and RST with a bad ACK are ignored; RST+ACK refuses" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 81 });
    defer st.close();
    const syn = (try wire.parseTcp4(h.out() orelse return error.NoSyn)).tcp;
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 81 }, .stack = .{ .addr = hz.stack_addr, .port = syn.src_port } };

    h.send(&p, .{ .seq = 0, .flags = .{ .rst = true } });
    try t.expectEqual(ns.State.syn_sent, st.status().state);
    h.send(&p, .{ .seq = 0, .ack = syn.seq +% 1000, .flags = .{ .rst = true, .ack = true } });
    try t.expectEqual(ns.State.syn_sent, st.status().state);
    try h.expectSilent(); // never answer a RST
    h.send(&p, .{ .seq = 0, .ack = syn.seq +% 1, .flags = .{ .rst = true, .ack = true } });
    var buf: [8]u8 = undefined;
    try t.expectError(error.ConnectionRefused, st.read(&buf));
}

test "conformance: SYN-SENT: a SYN-ACK acking the wrong sequence gets a RST, connection stays" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 82 });
    defer st.abort();
    const syn = (try wire.parseTcp4(h.out() orelse return error.NoSyn)).tcp;
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 82 }, .stack = .{ .addr = hz.stack_addr, .port = syn.src_port } };
    h.send(&p, .{ .seq = 5000, .ack = syn.seq +% 77, .flags = .{ .syn = true, .ack = true } });
    const r = (try h.seg(&p)) orelse return error.NoReset; // RFC 9293 3.10.7.3: <SEQ=SEG.ACK><CTL=RST>
    try t.expect(r.flags.rst);
    try t.expectEqual(syn.seq +% 77, r.seq);
    try t.expectEqual(ns.State.syn_sent, st.status().state);
}

test "conformance: simultaneous open (SYN crosses SYN) reaches ESTABLISHED" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 5000 });
    defer st.abort();
    const syn = (try wire.parseTcp4(h.out() orelse return error.NoSyn)).tcp;
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 5000 }, .stack = .{ .addr = hz.stack_addr, .port = syn.src_port } };
    const peer_isn: u32 = 0x1234_0000;
    h.send(&p, .{ .seq = peer_isn, .flags = .{ .syn = true }, .options = .{ .mss = 1380 } });
    const sa = (try h.waitSeg(&p, 1 * sec)) orelse return error.NoSynAck;
    try t.expect(sa.flags.syn and sa.flags.ack);
    try t.expectEqual(syn.seq, sa.seq);
    try t.expectEqual(peer_isn +% 1, sa.ack);
    try t.expectEqual(ns.State.syn_received, st.status().state);
    // The peer's own SYN-ACK (its SYN again, now acking ours): either it
    // completes the handshake or it is answered with an ACK; then a plain
    // ACK must complete it.
    h.send(&p, .{ .seq = peer_isn, .ack = syn.seq +% 1, .flags = .{ .syn = true, .ack = true } });
    _ = h.drain();
    if (st.status().state != .established) {
        h.send(&p, .{ .seq = peer_isn +% 1, .ack = syn.seq +% 1, .flags = .{ .ack = true } });
    }
    try t.expectEqual(ns.State.established, st.status().state);
    h.send(&p, .{ .seq = peer_isn +% 1, .ack = syn.seq +% 1, .flags = .{ .ack = true, .psh = true }, .payload = "sim" });
    var buf: [8]u8 = undefined;
    try t.expectEqual(@as(usize, 3), try st.read(&buf));
    try t.expectEqualStrings("sim", buf[0..3]);
}

// ---------------------------------------------------------------- closing

test "conformance: simultaneous close: FIN-WAIT-1 -> CLOSING -> TIME-WAIT" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    c.stream.shutdown();
    const f = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoFin;
    try t.expect(f.flags.fin);
    try t.expectEqual(c.rcv_nxt, f.seq);
    try t.expectEqual(ns.State.fin_wait_1, c.state());
    c.fin(h); // crosses: does not ack the stack's FIN
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAckOfFin;
    try t.expectEqual(c.snd_nxt, a.ack);
    try t.expectEqual(ns.State.closing, c.state());
    h.send(&c.peer, .{ .seq = c.snd_nxt -% 1, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true } });
    const a2 = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoReAck;
    try t.expectEqual(c.snd_nxt, a2.ack);
    c.rcv_nxt +%= 1;
    c.ack(h);
    try t.expectEqual(ns.State.time_wait, c.state());
}

test "conformance: FIN in SYN-SENT (no SYN bit) is dropped" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 83 });
    defer st.abort();
    const syn = (try wire.parseTcp4(h.out() orelse return error.NoSyn)).tcp;
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 83 }, .stack = .{ .addr = hz.stack_addr, .port = syn.src_port } };
    h.send(&p, .{ .seq = 99, .ack = syn.seq +% 1, .flags = .{ .ack = true, .fin = true } });
    try t.expectEqual(ns.State.syn_sent, st.status().state);
    try h.expectSilent();
}

test "conformance: FIN in SYN-RECEIVED completes the handshake, then CLOSE-WAIT and EOF" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 40000 }, .stack = .{ .addr = hz.stack_addr, .port = 8420 } };
    h.send(&p, .{ .seq = 10, .flags = .{ .syn = true }, .options = .{ .mss = 1380 } });
    const sa = (try h.seg(&p)) orelse return error.NoSynAck;
    h.send(&p, .{ .seq = 11, .ack = sa.seq +% 1, .flags = .{ .ack = true, .fin = true }, .payload = "bye" });
    const a = (try h.waitSeg(&p, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(@as(u32, 15), a.ack);
    const st = try l.accept();
    defer st.close();
    try t.expectEqual(ns.State.close_wait, st.status().state);
    var buf: [8]u8 = undefined;
    try t.expectEqual(@as(usize, 3), try st.read(&buf));
    try t.expectEqual(@as(usize, 0), try st.read(&buf));
}

test "conformance: FIN in ESTABLISHED -> CLOSE-WAIT, repeated FIN re-ACKed, LAST-ACK -> CLOSED" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true, .psh = true }, .payload = "hello" });
    c.snd_nxt +%= 6;
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, a.ack);
    try t.expectEqual(ns.State.close_wait, c.state());
    var buf: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 5), try c.stream.read(&buf));
    try t.expectEqual(@as(usize, 0), try c.stream.read(&buf));
    try t.expectEqual(@as(usize, 0), try c.stream.read(&buf)); // EOF is sticky
    h.send(&c.peer, .{ .seq = c.snd_nxt -% 1, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true } });
    const a2 = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoReAck;
    try t.expectEqual(c.snd_nxt, a2.ack);
    try t.expectEqual(ns.State.close_wait, c.state());
    try t.expectEqual(@as(usize, 2), try c.stream.write("ok")); // still writable
    c.stream.shutdown();
    var got_fin = false;
    while (try h.waitSeg(&c.peer, 1 * sec)) |s| {
        if (s.payload.len != 0) c.rcv_nxt +%= @intCast(s.payload.len);
        if (s.flags.fin) {
            got_fin = true;
            break;
        }
    }
    try t.expect(got_fin);
    try t.expectEqual(ns.State.last_ack, c.state());
    h.send(&c.peer, .{ .seq = c.snd_nxt -% 1, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true } });
    _ = h.drain();
    c.rcv_nxt +%= 1;
    c.ack(h);
    try t.expectEqual(ns.State.closed, c.state());
}

test "conformance: FIN-WAIT-1 + FIN acking our FIN -> TIME-WAIT directly" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    c.stream.shutdown();
    const f = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoFin;
    try t.expect(f.flags.fin);
    c.rcv_nxt +%= 1;
    c.fin(h);
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, a.ack);
    try t.expectEqual(ns.State.time_wait, c.state());
}

test "conformance: FIN-WAIT-2 receives data, FIN -> TIME-WAIT; a FIN repeated in TIME-WAIT is re-ACKed" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    c.stream.shutdown();
    _ = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoFin;
    c.rcv_nxt +%= 1;
    c.ack(h);
    try t.expectEqual(ns.State.fin_wait_2, c.state());
    c.data(h, "late data");
    var buf: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 9), try c.stream.read(&buf));
    _ = h.drain();
    c.fin(h);
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, a.ack);
    try t.expectEqual(ns.State.time_wait, c.state());
    h.send(&c.peer, .{ .seq = c.snd_nxt -% 1, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true } });
    const a2 = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoReAck;
    try t.expectEqual(c.snd_nxt, a2.ack);
    try t.expectEqual(ns.State.time_wait, c.state());
}

test "conformance: TIME-WAIT lasts time_wait_ns: not less, not more" {
    var limits: ns.Limits = .{};
    limits.time_wait_ns = 2 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    c.stream.shutdown();
    _ = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoFin;
    c.rcv_nxt +%= 1;
    c.fin(h);
    _ = h.drain();
    try t.expectEqual(ns.State.time_wait, c.state());
    c.stream.close(); // the connection finishes in the background
    try t.expectEqual(@as(u16, 1), h.stats().connections);
    const d = h.nextDeadline() orelse return error.NoTimeWaitTimer;
    try t.expect(d <= limits.time_wait_ns);
    h.advance(limits.time_wait_ns - 200 * ms);
    try t.expectEqual(@as(u16, 1), h.stats().connections);
    h.advance(200 * ms);
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    try t.expectEqual(@as(?i64, null), h.stack.runTimers());
}

// ---------------------------------------------------------------- RST

test "conformance: RST in SYN-RECEIVED: back to LISTEN, nothing to accept, slot freed" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 40000 }, .stack = .{ .addr = hz.stack_addr, .port = 8420 } };
    h.send(&p, .{ .seq = 10, .flags = .{ .syn = true } });
    _ = (try h.seg(&p)) orelse return error.NoSynAck;
    h.send(&p, .{ .seq = 11, .flags = .{ .rst = true } });
    try t.expectError(error.WouldBlock, l.accept());
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    try h.expectSilent();
    var c = try hz.openPassive(h, l, .{ .isn = 5000 });
    c.stream.abort();
}

test "conformance: RST at RCV.NXT resets ESTABLISHED: read and write fail with ConnectionReset" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    h.send(&c.peer, .{ .seq = c.snd_nxt, .flags = .{ .rst = true } });
    var buf: [8]u8 = undefined;
    try t.expectError(error.ConnectionReset, c.stream.read(&buf));
    try t.expectError(error.ConnectionReset, c.stream.write("x"));
    try h.expectSilent();
}

test "conformance: no listener: SYN gets RST+ACK, ACK gets RST, RST gets nothing" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 40000 }, .stack = .{ .addr = hz.stack_addr, .port = 9999 } };
    h.send(&p, .{ .seq = 100, .flags = .{ .syn = true } });
    const r = (try h.seg(&p)) orelse return error.NoReset;
    try t.expect(r.flags.rst and r.flags.ack);
    try t.expectEqual(@as(u32, 0), r.seq);
    try t.expectEqual(@as(u32, 101), r.ack);
    h.send(&p, .{ .seq = 100, .ack = 5555, .flags = .{ .ack = true } });
    const r2 = (try h.seg(&p)) orelse return error.NoReset;
    try t.expect(r2.flags.rst);
    try t.expectEqual(@as(u32, 5555), r2.seq);
    h.send(&p, .{ .seq = 100, .flags = .{ .rst = true } });
    h.send(&p, .{ .seq = 100, .ack = 1, .flags = .{ .rst = true, .ack = true } });
    try h.expectSilent();
    try t.expect(h.stats().rst_sent >= 2);
}

test "conformance: in-window RST not at RCV.NXT -> challenge ACK; exact RST resets (RFC 5961 3)" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    for ([_]u32{ 1, 100, 1000, 30000 }) |off| {
        h.send(&c.peer, .{ .seq = c.snd_nxt +% off, .flags = .{ .rst = true } });
        const a = (try h.seg(&c.peer)) orelse return error.NoChallengeAck;
        try t.expect(a.flags.ack and !a.flags.rst);
        try t.expectEqual(c.snd_nxt, a.ack);
        try t.expectEqual(ns.State.established, c.state());
    }
    // The peer, answering the challenge, sends the exact RST.
    h.send(&c.peer, .{ .seq = c.snd_nxt, .flags = .{ .rst = true } });
    var buf: [4]u8 = undefined;
    try t.expectError(error.ConnectionReset, c.stream.read(&buf));
}

test "conformance: SYN on a synchronized connection -> challenge ACK, connection kept (RFC 5961 4)" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    for ([_]u32{ 0, 5, 1 << 31 }) |off| {
        h.send(&c.peer, .{ .seq = c.snd_nxt +% off, .flags = .{ .syn = true } });
        const a = (try h.seg(&c.peer)) orelse return error.NoChallengeAck;
        try t.expect(a.flags.ack and !a.flags.rst and !a.flags.syn);
        try t.expectEqual(c.snd_nxt, a.ack);
        try t.expectEqual(ns.State.established, c.state());
    }
    c.data(h, "still here");
    var buf: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 10), try c.stream.read(&buf));
}
// ---------------------------------------------------------------- RTO (RFC 6298)

/// Retransmission intervals of one 100-byte segment the peer never ACKs.
fn retransmitIntervals(h: *H, c: *hz.Conn, out: []u64) !void {
    _ = try c.stream.write(&@as([100]u8, @splat('x')));
    const first = (try h.seg(&c.peer)) orelse return error.NoData;
    try t.expectEqual(c.rcv_nxt, first.seq);
    var last = h.now();
    for (out) |*iv| {
        const s = (try h.waitSeg(&c.peer, 300 * sec)) orelse return error.NoRetransmit;
        try t.expectEqual(c.rcv_nxt, s.seq);
        try t.expectEqual(@as(usize, 100), s.payload.len);
        const n = h.now();
        iv.* = @intCast(n - last);
        last = n;
    }
}

test "conformance: RTO: first retransmission within [200 ms, 3 s], then exponential backoff" {
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 600 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    c.stream.setPriority(.bulk); // interactive streams send a tail loss probe first
    var iv: [6]u64 = undefined;
    try retransmitIntervals(h, &c, &iv);
    std.debug.print("RTO intervals (ms): {d} {d} {d} {d} {d} {d}\n", .{ iv[0] / ms, iv[1] / ms, iv[2] / ms, iv[3] / ms, iv[4] / ms, iv[5] / ms });
    try t.expect(iv[0] >= 190 * ms and iv[0] <= 3 * sec); // 200 ms floor, minus clock jitter
    for (iv[0 .. iv.len - 1], iv[1..]) |a, b| {
        if (a >= 60 * sec) break; // RFC 6298 2.5: a cap of >= 60 s is allowed
        try t.expect(b * 10 >= a * 18 and b * 10 <= a * 22);
    }
    try t.expect(h.stats().retransmits >= iv.len);
}

test "conformance: Karn: an ACK after a retransmission gives no RTT sample, backed-off RTO kept" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    c.stream.setPriority(.bulk); // no tail loss probe: the RTO path

    // Clean round: sample ~0, RTO at its floor.
    _ = try c.stream.write(&@as([100]u8, @splat('a')));
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    const r0 = h.nextDeadline() orelse return error.NoTimer;
    c.rcv_nxt +%= 100;
    c.ack(h);

    // Ambiguous round: timeout, retransmission, then the ACK 1 ms later.
    _ = try c.stream.write(&@as([100]u8, @splat('b')));
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    const t0 = h.now();
    const re = (try h.waitSeg(&c.peer, 60 * sec)) orelse return error.NoRetransmit;
    try t.expectEqual(c.rcv_nxt, re.seq);
    const rto1: u64 = @intCast(h.now() - t0);
    h.advance(1 * ms);
    c.rcv_nxt +%= 100;
    c.ack(h);
    _ = h.drain();

    // Next segment: its timer must still be the backed-off RTO (RFC 6298
    // section 5: it only collapses after a new valid RTT measurement).
    _ = try c.stream.write(&@as([100]u8, @splat('c')));
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    const r2 = h.nextDeadline() orelse return error.NoTimer;
    std.debug.print("Karn: clean RTO {d} ms, first timeout {d} ms, after the ambiguous ACK {d} ms\n", .{ r0 / ms, rto1 / ms, r2 / ms });
    try t.expect(r2 * 10 >= rto1 * 18);
}

// ---------------------------------------------------------------- RFC 5681

const Sent = struct { seq: u32, len: u32 };

fn collectData(h: *H, c: *hz.Conn, list: *std.ArrayList(Sent)) !void {
    while (try h.seg(&c.peer)) |s| if (s.payload.len != 0) try list.append(gpa, .{ .seq = s.seq, .len = @intCast(s.payload.len) });
}

test "conformance: fast retransmit on the third duplicate ACK, no timer needed" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();

    var data: [40 * 1380]u8 = undefined;
    hz.fillPattern(1, 0, &data);
    _ = try hz.writeSome(c.stream, &data);

    var sent: std.ArrayList(Sent) = .empty;
    defer sent.deinit(gpa);
    var una = c.rcv_nxt;
    try collectData(h, &c, &sent);
    // ACK one segment at a time until at least 5 segments are beyond SND.UNA.
    var i: usize = 0;
    while (true) : (i += 1) {
        var beyond: usize = 0;
        for (sent.items) |s| {
            if (hz.seqLe(una, s.seq)) beyond += 1;
        }
        if (i > 0 and beyond >= 5) break;
        if (i >= sent.items.len or i > 30) return error.NotEnoughInFlight;
        una = sent.items[i].seq +% sent.items[i].len;
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = una, .flags = .{ .ack = true } });
        try collectData(h, &c, &sent);
    }
    // The segment at `una` is "lost": three duplicate ACKs.
    const before = sent.items.len;
    for (0..2) |_| {
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = una, .flags = .{ .ack = true } });
        try collectData(h, &c, &sent);
    }
    for (sent.items[before..]) |s| try t.expect(s.seq != una); // not before the third
    const before3 = sent.items.len;
    h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = una, .flags = .{ .ack = true } });
    try collectData(h, &c, &sent);
    var found = false;
    for (sent.items[before3..]) |s| found = found or s.seq == una;
    try t.expect(found);
    try t.expect(h.stats().fast_retransmits >= 1);
}

test "conformance: initial window is at most 10 segments (RFC 6928 / 5681)" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    var data: [64 * 1024]u8 = @splat(7);
    _ = try hz.writeSome(c.stream, &data);
    var bytes: usize = 0;
    while (try h.seg(&c.peer)) |s| bytes += s.payload.len;
    try t.expect(bytes > 0);
    try t.expect(bytes <= 10 * 1380);
}

test "conformance: delayed ACK within 500 ms; data past a hole is ACKed at once" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    const t0 = h.now();
    c.data(h, "one");
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, a.ack);
    try t.expect(h.now() - t0 <= 500 * ms);
    h.send(&c.peer, .{ .seq = c.snd_nxt +% 100, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "later" });
    const d = (try h.seg(&c.peer)) orelse return error.NoImmediateDupAck; // RFC 5681 4.2
    try t.expectEqual(c.snd_nxt, d.ack);
}

// ---------------------------------------------------------------- windows

test "conformance: receive window closes at recv_buffer, excess dropped, SWS-safe reopening" {
    var limits: ns.Limits = .{};
    limits.recv_buffer = 16384;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    try t.expect(c.syn_window <= 16384);

    var data: [16384 + 1000]u8 = undefined;
    hz.fillPattern(2, 0, &data);
    var off: usize = 0;
    while (off < 16384) {
        const n = @min(1380, 16384 - off);
        c.data(h, data[off..][0..n]);
        off += n;
    }
    var last: ?wire.Tcp = null;
    while (try h.waitSeg(&c.peer, 1 * sec)) |s| {
        last = s;
        if (s.ack == c.snd_nxt) break;
    }
    const full = last orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, full.ack);
    try t.expectEqual(@as(u16, 0), full.window);
    // Beyond the window: not accepted (ACKed, RCV.NXT unchanged).
    h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[16384..][0..1000] });
    const na = (try h.seg(&c.peer)) orelse return error.NoAckForOutOfWindow;
    try t.expectEqual(c.snd_nxt, na.ack);
    try t.expectEqual(@as(u16, 0), na.window);
    // Reading a little must not open a silly window (RFC 9293 3.8.6.2.2).
    var small: [100]u8 = undefined;
    try t.expectEqual(@as(usize, 100), try c.stream.read(&small));
    while (try h.waitSeg(&c.peer, 1 * sec)) |s| try t.expect(s.window == 0 or s.window >= @min(1380, 16384 / 2));
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    try got.appendSlice(gpa, &small);
    _ = try hz.readAvailable(c.stream, gpa, &got);
    try t.expectEqualSlices(u8, data[0..16384], got.items);
    // An unprompted window update after the reads.
    const upd = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoWindowUpdate;
    try t.expectEqual(c.snd_nxt, upd.ack);
    try t.expect(upd.window >= 1380);
}

test "conformance: zero window: probes back off, keep the connection past user_timeout, data flows on reopen" {
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 10 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .window = 0 });
    defer c.stream.abort();
    var data: [1000]u8 = undefined;
    hz.fillPattern(3, 0, &data);
    try t.expectEqual(@as(usize, 1000), try c.stream.write(&data));
    while (try h.seg(&c.peer)) |s| try t.expect(s.payload.len <= 1);
    var prev: u64 = 0;
    var last = h.now();
    const start = last;
    for (0..6) |_| {
        const p = (try h.waitSeg(&c.peer, 120 * sec)) orelse return error.NoProbe;
        try t.expect(p.payload.len <= 1);
        const n = h.now();
        const iv: u64 = @intCast(n - last);
        last = n;
        try t.expect(iv + 50 * ms >= prev); // never faster than the previous probe
        prev = iv;
        c.ack(h); // window still 0
    }
    try t.expect(@as(u64, @intCast(h.now() - start)) > limits.user_timeout_ns);
    try t.expectEqual(ns.State.established, c.state());
    c.window = 65535;
    c.ack(h);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var rounds: usize = 0;
    while (got.items.len < 1000 and rounds < 20) : (rounds += 1) {
        _ = try c.pullWait(h, &got, gpa, 2 * sec);
    }
    try t.expectEqualSlices(u8, &data, got.items);
}
// ---------------------------------------------------------------- MSS

/// Largest payload the stack sends to a peer that offered `peer_mss`,
/// checking the 20000 bytes arrive intact.
fn maxSegmentSent(peer_mss: ?u16) !usize {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = peer_mss } });
    defer c.stream.abort();
    var data: [20000]u8 = undefined;
    hz.fillPattern(4, 0, &data);
    _ = try hz.writeSome(c.stream, &data);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var largest: usize = 0;
    var rounds: usize = 0;
    while (got.items.len < data.len and rounds < 400) : (rounds += 1) {
        const first = h.waitOut(5 * sec) orelse break;
        var pkt: ?[]u8 = first;
        while (pkt) |raw| : (pkt = h.out()) {
            const s = try c.peer.expect(raw);
            largest = @max(largest, s.payload.len);
            if (s.payload.len != 0 and s.seq == c.rcv_nxt) {
                try got.appendSlice(gpa, s.payload);
                c.rcv_nxt +%= @intCast(s.payload.len);
            }
        }
        c.ack(h);
    }
    try t.expectEqualSlices(u8, &data, got.items);
    return largest;
}

test "conformance: MSS: clamped to 1380 at MTU 1420 even if the peer offers 1460" {
    try t.expectEqual(@as(usize, 1380), try maxSegmentSent(1460));
}

test "conformance: MSS: the peer's smaller MSS (536) is honored" {
    try t.expectEqual(@as(usize, 536), try maxSegmentSent(536));
}

test "conformance: MSS: no MSS option means 536 (RFC 9293 3.7.1)" {
    try t.expect(try maxSegmentSent(null) <= 536);
}

test "conformance: MSS follows the MTU (1280 -> 1240)" {
    const h = try H.create(gpa, .{ .mtu = 1280 });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    try t.expectEqual(@as(?u16, 1240), c.syn_options.mss);
}

// ---------------------------------------------------------------- reassembly

test "conformance: out-of-order segments are reassembled in order" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    var data: [3000]u8 = undefined;
    hz.fillPattern(5, 0, &data);
    const base = c.snd_nxt;
    for ([_]usize{ 2, 1, 0 }) |k| {
        h.send(&c.peer, .{ .seq = base +% @as(u32, @intCast(k * 1000)), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[k * 1000 ..][0..1000] });
        if (k != 0) {
            const d = (try h.seg(&c.peer)) orelse return error.NoDupAck;
            try t.expectEqual(base, d.ack);
        }
    }
    c.snd_nxt = base +% 3000;
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(c.snd_nxt, a.ack);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try hz.readAvailable(c.stream, gpa, &got);
    try t.expectEqualSlices(u8, &data, got.items);
}

test "conformance: duplicate and overlapping (consistent) segments deliver each byte once" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    var data: [400]u8 = undefined;
    hz.fillPattern(6, 0, &data);
    const base = c.snd_nxt;
    const ranges = [_][2]usize{ .{ 100, 300 }, .{ 100, 300 }, .{ 250, 400 }, .{ 0, 150 }, .{ 0, 150 }, .{ 50, 120 }, .{ 0, 400 }, .{ 390, 400 } };
    for (ranges) |r| {
        h.send(&c.peer, .{ .seq = base +% @as(u32, @intCast(r[0])), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[r[0]..r[1]] });
    }
    _ = h.drain();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try hz.readAvailable(c.stream, gpa, &got);
    try t.expectEqualSlices(u8, &data, got.items);
}

test "conformance: out-of-order queue capped at max_ooo_segments; data correct after the gaps fill" {
    var limits: ns.Limits = .{};
    limits.max_ooo_segments = 4;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    var data: [1600]u8 = undefined;
    hz.fillPattern(7, 0, &data);
    const base = c.snd_nxt;
    var k: usize = 100;
    while (k < 1600) : (k += 200) {
        h.send(&c.peer, .{ .seq = base +% @as(u32, @intCast(k)), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[k..][0..100] });
    }
    _ = h.drain();
    try t.expect(h.stats().dropped_ooo >= 4);
    try t.expectEqual(@as(usize, 0), c.stream.status().read_available);
    k = 0;
    while (k < 1600) : (k += 100) {
        h.send(&c.peer, .{ .seq = base +% @as(u32, @intCast(k)), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[k..][0..100] });
    }
    _ = h.drain();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try hz.readAvailable(c.stream, gpa, &got);
    try t.expectEqualSlices(u8, &data, got.items);
}

test "conformance: sequence numbers wrap around 2^32 (in order, out of order, FIN after the wrap)" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .isn = 0xFFFF_FFFF - 1500 });
    defer c.stream.close();
    var data: [6000]u8 = undefined;
    hz.fillPattern(8, 0, &data);
    const base = c.snd_nxt;
    const order = [_]usize{ 0, 3, 1, 2, 5, 4 };
    for (order) |k| {
        h.send(&c.peer, .{ .seq = base +% @as(u32, @intCast(k * 1000)), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = data[k * 1000 ..][0..1000] });
    }
    c.snd_nxt = base +% 6000;
    c.fin(h);
    var final_ack: u32 = 0;
    while (try h.waitSeg(&c.peer, 1 * sec)) |s| {
        final_ack = s.ack;
        if (s.ack == c.snd_nxt) break;
    }
    try t.expectEqual(c.snd_nxt, final_ack);
    try t.expect(c.snd_nxt < 10000); // it did wrap
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    try t.expect(try hz.readAvailable(c.stream, gpa, &got));
    try t.expectEqualSlices(u8, &data, got.items);
}

// ---------------------------------------------------------------- ISNs (RFC 6528)

test "conformance: ISNs: distinct per 4-tuple, spread over the space, keyed per stack" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const h2 = try H.create(gpa, .{});
    defer h2.destroy();
    _ = try h.stack.listen(8420);
    _ = try h2.stack.listen(8420);
    var isns: [64]u32 = undefined;
    var top: std.StaticBitSet(256) = .empty;
    var same_as_other: usize = 0;
    for (&isns, 0..) |*isn, i| {
        const port: u16 = @intCast(41000 + i);
        var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = port }, .stack = .{ .addr = hz.stack_addr, .port = 8420 } };
        h.send(&p, .{ .seq = 77, .flags = .{ .syn = true } });
        const sa = (try h.seg(&p)) orelse return error.NoSynAck;
        isn.* = sa.seq;
        h.send(&p, .{ .seq = 78, .flags = .{ .rst = true } });
        top.set(sa.seq >> 24);
        h2.send(&p, .{ .seq = 77, .flags = .{ .syn = true } });
        const sb = (try h2.seg(&p)) orelse return error.NoSynAck;
        if (sb.seq == sa.seq) same_as_other += 1;
        h2.send(&p, .{ .seq = 78, .flags = .{ .rst = true } });
    }
    for (isns, 0..) |a, i| for (isns[i + 1 ..]) |b| try t.expect(a != b);
    var equal_steps: usize = 0;
    for (1..isns.len - 1) |i| {
        if (isns[i + 1] -% isns[i] == isns[i] -% isns[i - 1]) equal_steps += 1;
    }
    try t.expect(equal_steps < 4);
    try t.expect(top.count() >= 24); // 64 random top bytes: ~57 distinct expected
    try t.expectEqual(@as(usize, 0), same_as_other);
}

test "conformance: ISNs of dials are unpredictable; the same tuple later gets a new ISN" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    var isns: [32]u32 = undefined;
    for (&isns, 0..) |*isn, i| {
        const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = @intCast(2000 + i) });
        const syn = (try wire.parseTcp4(h.out() orelse return error.NoSyn)).tcp;
        isn.* = syn.seq;
        st.abort();
        _ = h.drain();
    }
    for (isns, 0..) |a, i| for (isns[i + 1 ..]) |b| try t.expect(a != b);
    var equal_steps: usize = 0;
    for (1..isns.len - 1) |i| {
        if (isns[i + 1] -% isns[i] == isns[i] -% isns[i - 1]) equal_steps += 1;
    }
    try t.expect(equal_steps < 4);

    const l = try h.stack.listen(8420);
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 45000 }, .stack = .{ .addr = hz.stack_addr, .port = l.port() } };
    h.send(&p, .{ .seq = 1, .flags = .{ .syn = true } });
    const a = (try h.seg(&p)) orelse return error.NoSynAck;
    h.send(&p, .{ .seq = 2, .flags = .{ .rst = true } });
    h.advance(1 * sec);
    h.send(&p, .{ .seq = 1, .flags = .{ .syn = true } });
    const b = (try h.seg(&p)) orelse return error.NoSynAck;
    h.send(&p, .{ .seq = 2, .flags = .{ .rst = true } });
    try t.expect(a.seq != b.seq);
}

// ---------------------------------------------------------------- ICMP

/// An ICMP echo request peer -> `dst` (wire.Ip4 + wire.checksum).
pub fn echoRequest(buf: []u8, dst: [4]u8, id: u16, seqn: u16, payload: []const u8) ![]u8 {
    const icmp = buf[wire.ip4_header_len..][0 .. 8 + payload.len];
    icmp[0] = wire.icmp_echo_request;
    icmp[1] = 0;
    @memset(icmp[2..4], 0);
    std.mem.writeInt(u16, icmp[4..6], id, .big);
    std.mem.writeInt(u16, icmp[6..8], seqn, .big);
    @memcpy(icmp[8..], payload);
    std.mem.writeInt(u16, icmp[2..4], wire.checksum(icmp), .big);
    try (wire.Ip4{ .protocol = wire.proto_icmp, .src = hz.peer_ip, .dst = dst }).write(buf, icmp.len);
    return buf[0 .. wire.ip4_header_len + icmp.len];
}

test "conformance: ICMP echo to the stack address is answered, not when disabled or for others" {
    {
        const h = try H.create(gpa, .{});
        defer h.destroy();
        var buf: [256]u8 = undefined;
        h.sendRaw(try echoRequest(&buf, hz.stack_ip, 0x4242, 7, "ping payload"));
        const rep = h.out() orelse return error.NoEchoReply;
        const ip = try wire.Ip4.parse(rep);
        try t.expectEqual(wire.proto_icmp, ip.header.protocol);
        try t.expectEqualSlices(u8, &hz.stack_ip, &ip.header.src);
        try t.expectEqualSlices(u8, &hz.peer_ip, &ip.header.dst);
        try t.expectEqual(wire.icmp_echo_reply, try wire.icmp4Type(ip.payload));
        try t.expectEqual(@as(u16, 0x4242), std.mem.readInt(u16, ip.payload[4..6], .big));
        try t.expectEqual(@as(u16, 7), std.mem.readInt(u16, ip.payload[6..8], .big));
        try t.expectEqualStrings("ping payload", ip.payload[8..]);
        try t.expectEqual(@as(u64, 1), h.stats().icmp_echo_replies);
        h.sendRaw(try echoRequest(&buf, .{ 10, 8, 0, 9 }, 1, 1, "x"));
        try h.expectSilent();
    }
    {
        const h = try H.create(gpa, .{ .icmp_echo = false });
        defer h.destroy();
        var buf: [256]u8 = undefined;
        h.sendRaw(try echoRequest(&buf, hz.stack_ip, 1, 1, "x"));
        try h.expectSilent();
    }
}