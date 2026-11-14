//! Loss recovery beyond RFC 6675: tail loss probes (RFC 8985 7, interactive
//! streams), RACK time-based loss detection (RFC 8985 6) and D-SACK
//! (RFC 2883, with RFC 3708-style spurious-retransmission undo). RACK and
//! D-SACK tests skip until tcp.zig cites them (harness.has_rack /
//! has_dsack).
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const wire = hz.wire;
const H = hz.H;
const ms = hz.ms;
const sec = hz.sec;
const sack = @import("sack.zig");

const gpa = t.allocator;
const has_tlp = @hasField(ns.Stats, "tail_loss_probes");

fn needTlp() !void {
    if (comptime !has_tlp) return hz.skip("tail loss probe not on feat/netstack yet");
}
fn needRack() !void {
    if (comptime !(hz.has_rack and sack.has_sack)) return hz.skip("RACK (RFC 8985 6) not on feat/netstack yet");
}
fn needDsack() !void {
    if (comptime !(hz.has_dsack and sack.has_sack)) return hz.skip("D-SACK (RFC 2883) not on feat/netstack yet");
}

/// Establishes, then gives the stack `rounds` RTT samples of `rtt` (on a
/// bulk stream, so no tail loss probe fires while the peer "waits");
/// the stream is interactive again afterwards.
fn withRtt(h: *H, l: ns.Listener, rtt: u64, rounds: usize, o: hz.PassiveOpts) !hz.Conn {
    var c = try hz.openPassive(h, l, o);
    c.stream.setPriority(.bulk);
    defer c.stream.setPriority(.interactive);
    for (0..rounds) |_| {
        _ = try c.stream.write("w");
        const s = (try h.seg(&c.peer)) orelse return error.NoData;
        h.advance(rtt);
        c.rcv_nxt = s.seq +% 1;
        c.ack(h);
        _ = h.drain();
    }
    return c;
}

// ---------------------------------------------------------------- TLP

test "tlp: a lost last segment is probed at max(2 SRTT, 10 ms), once, before the RTO" {
    try needTlp();
    if (comptime !has_tlp) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try withRtt(h, l, 30 * ms, 40, .{}); // SRTT converges to ~30 ms
    defer c.stream.abort();
    const p0 = h.stats().tail_loss_probes;
    _ = try c.stream.write("keystroke");
    const orig = (try h.seg(&c.peer)) orelse return error.NoData;
    const t0 = h.now();
    const probe = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoProbe;
    const dt: u64 = @intCast(h.now() - t0);
    std.debug.print("TLP after {d} ms (SRTT ~30 ms)\n", .{dt / ms});
    try t.expectEqual(orig.seq, probe.seq);
    try t.expectEqualStrings("keystroke", probe.payload);
    try t.expect(dt >= 50 * ms and dt <= 90 * ms);
    try t.expectEqual(p0 + 1, h.stats().tail_loss_probes);
    // No second probe: the next transmission is the RTO's.
    const re = (try h.waitSeg(&c.peer, 5 * sec)) orelse return error.NoRetransmit;
    try t.expect(@as(u64, @intCast(h.now() - t0)) >= 190 * ms);
    try t.expectEqual(orig.seq, re.seq);
    try t.expectEqual(p0 + 1, h.stats().tail_loss_probes);
}

test "tlp: 10 ms floor when SRTT is ~0" {
    try needTlp();
    if (comptime !has_tlp) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try withRtt(h, l, 0, 3, .{});
    defer c.stream.abort();
    _ = try c.stream.write("k");
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    const t0 = h.now();
    _ = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoProbe;
    const dt: u64 = @intCast(h.now() - t0);
    try t.expect(dt >= 9 * ms and dt <= 20 * ms);
}

test "tlp: bulk streams never probe" {
    try needTlp();
    if (comptime !has_tlp) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try withRtt(h, l, 30 * ms, 4, .{});
    defer c.stream.abort();
    c.stream.setPriority(.bulk);
    _ = try c.stream.write("bulk");
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    const t0 = h.now();
    _ = (try h.waitSeg(&c.peer, 5 * sec)) orelse return error.NoRetransmit;
    try t.expect(@as(u64, @intCast(h.now() - t0)) >= 190 * ms);
    try t.expectEqual(@as(u64, 0), h.stats().tail_loss_probes);
}

test "tlp: duplicate ACKs without progress cannot trigger a probe storm" {
    try needTlp();
    if (comptime !has_tlp) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try withRtt(h, l, 20 * ms, 4, .{});
    defer c.stream.abort();
    const p0 = h.stats().tail_loss_probes;
    _ = try c.stream.write("tail");
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    _ = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoProbe;
    for (0..500) |_| {
        c.ack(h); // ACK = snd_una: no progress
        h.advance(1 * ms);
        _ = h.drain();
    }
    try t.expectEqual(p0 + 1, h.stats().tail_loss_probes);
    // Progress re-arms: a new tail may be probed once more.
    c.rcv_nxt +%= 4;
    c.ack(h);
    _ = try c.stream.write("next");
    _ = (try h.seg(&c.peer)) orelse return error.NoData;
    _ = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoProbe;
    try t.expectEqual(p0 + 2, h.stats().tail_loss_probes);
}

// ---------------------------------------------------------------- RACK

fn delayEvery7th(i: usize, nth: u32) sack.Fate {
    return if (nth == 1 and i % 7 == 3) .delay else .deliver;
}

test "rack: reordering within reo_wnd causes no spurious retransmissions" {
    try needRack();
    if (comptime !(hz.has_rack and sack.has_sack)) return;
    const r = try sack.runSender(.{
        .strategy = .honest,
        .loss_ppm = 0,
        .rtt_ns = 40 * ms,
        .delay_ns = 2 * ms, // < min_rtt / 4
        .fate = delayEvery7th,
        .bulk = true,
        .total = 256 * 1024,
        .label = " [reordered, no loss]",
    });
    // Nothing was lost: at most the first reordering (before reordering is
    // seen) may cost a spurious retransmission.
    try t.expect(r.stats.retransmits <= 1);
    try t.expectEqual(@as(u64, 0), r.stats.rto_expirations);
}

fn loseFifthTwice(i: usize, nth: u32) sack.Fate {
    return if (i == 5 and nth <= 2) .drop else .deliver;
}

test "rack: a lost retransmission is recovered without an RTO" {
    try needRack();
    if (comptime !(hz.has_rack and sack.has_sack)) return;
    const r = try sack.runSender(.{
        .strategy = .honest,
        .loss_ppm = 0,
        .rtt_ns = 40 * ms,
        .fate = loseFifthTwice,
        .bulk = true,
        .total = 256 * 1024,
        .label = " [retransmission lost]",
    });
    try t.expectEqual(@as(u64, 0), r.stats.rto_expirations);
    try t.expect(r.stats.retransmits >= 2);
}

// ---------------------------------------------------------------- D-SACK

test "dsack: a duplicate segment is reported with a D-SACK block (RFC 2883 4)" {
    try needDsack();
    if (comptime !(hz.has_dsack and sack.has_sack)) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = 1380, .sack_permitted = true } });
    defer c.stream.abort();
    const base = c.snd_nxt;
    var p: [100]u8 = @splat('d');
    c.data(h, &p);
    _ = h.drain();
    // The same segment again (already ACKed): D-SACK = the duplicate range.
    h.send(&c.peer, .{ .seq = base, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &p });
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    const s = a.options.sack orelse return error.NoDsack;
    try t.expectEqual(base, s.slice()[0].start);
    try t.expectEqual(base +% 100, s.slice()[0].end);
    try t.expectEqual(base +% 100, a.ack);
    // A duplicate of out-of-order data: first block the duplicate, second
    // the island containing it (RFC 2883 4.2).
    h.send(&c.peer, .{ .seq = base +% 300, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &p });
    _ = h.drain();
    h.send(&c.peer, .{ .seq = base +% 300, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &p });
    const b = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    const s2 = b.options.sack orelse return error.NoDsack;
    try t.expect(s2.slice().len >= 2);
    try t.expectEqual(base +% 300, s2.slice()[0].start);
    try t.expectEqual(base +% 400, s2.slice()[0].end);
    try t.expect(hz.seqLe(s2.slice()[1].start, base +% 300) and hz.seqLe(base +% 400, s2.slice()[1].end));
}

test "dsack: a hostile D-SACK flood cannot grow reo_wnd past its cap or undo cwnd repeatedly" {
    try needDsack();
    if (comptime !(hz.has_dsack and sack.has_sack)) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try withRtt(h, l, 40 * ms, 8, .{ .syn_options = .{ .mss = 1380, .sack_permitted = true } });
    defer c.stream.abort();
    c.stream.setPriority(.bulk);
    // Build cwnd up, then cause one real recovery (3 SACKed above a hole).
    var data: [64 * 1024]u8 = undefined;
    hz.fillPattern(71, 0, &data);
    _ = try hz.writeSome(c.stream, &data);
    var segs: [64]struct { seq: u32, len: u32 } = undefined;
    var n: usize = 0;
    while (try h.seg(&c.peer)) |s| if (s.payload.len != 0 and n < segs.len) {
        segs[n] = .{ .seq = s.seq, .len = @intCast(s.payload.len) };
        n += 1;
    };
    if (n < 5) return error.FlightTooSmall;
    const before = (c.stream.debugConn() orelse return error.Gone).cwnd;
    h.advance(40 * ms);
    var sk: wire.Sack = .{ .len = 1 };
    sk.blocks[0] = .{ .start = segs[1].seq, .end = segs[4].seq +% segs[4].len };
    for (0..3) |_| h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .options = .{ .sack = sk } });
    _ = h.drain();
    // Flood: D-SACK blocks (below and at snd_una, overlapping the
    // retransmission and anything else), thousands of them.
    var prng: std.Random.DefaultPrng = .init(5);
    const r = prng.random();
    var max_cwnd: u32 = 0;
    for (0..5000) |i| {
        var d: wire.Sack = .{ .len = 2 };
        const back = r.uintLessThan(u32, 1 << 20);
        d.blocks[0] = .{ .start = c.rcv_nxt -% back -% 1380, .end = c.rcv_nxt -% back };
        d.blocks[1] = .{ .start = segs[0].seq, .end = segs[0].seq +% segs[0].len };
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .options = .{ .sack = d } });
        if (i % 50 == 0) h.advance(1 * ms);
        _ = h.drain();
        const k = c.stream.debugConn() orelse return error.Gone;
        max_cwnd = @max(max_cwnd, k.cwnd);
        if (comptime @hasField(@TypeOf(k), "reo_wnd")) {
            // RFC 8985 6.2: reo_wnd never exceeds SRTT.
            try t.expect(k.reo_wnd <= @max(k.srtt, 0) + 1 * @as(i64, @intCast(ms)));
        }
    }
    std.debug.print("D-SACK flood: cwnd before loss {d}, max during flood {d}\n", .{ before, max_cwnd });
    // An undo restores at most the pre-loss window, once.
    try t.expect(max_cwnd <= before + 2 * 1380);
}
