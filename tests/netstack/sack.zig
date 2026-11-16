//! SACK (RFC 2018, RFC 6675 recovery): negotiation, the stack's own SACK
//! blocks as a receiver, and a sender facing honest, lossy and hostile
//! SACK peers: blocks outside [snd_una, snd_max], inverted, wrapping,
//! overlapping, rapidly changing, lying (reneging), more holes than the
//! scoreboard holds, and a tiny MSS with per-byte blocks ("SACK Panic"
//! style). Every transfer must finish with the bytes intact, without new
//! allocations and with bounded work per ACK.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const wire = hz.wire;
const H = hz.H;
const ms = hz.ms;
const sec = hz.sec;

const gpa = t.allocator;

pub const has_sack = @hasField(wire.TcpOptions, "sack") and @hasField(ns.Stats, "sack_blocks_ignored");

fn needSack() !void {
    if (comptime !has_sack) return hz.skip("SACK not on feat/netstack yet");
}

test "sack: SACK-permitted is echoed only when offered" {
    try needSack();
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var a = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = 1380, .sack_permitted = true } });
    defer a.stream.abort();
    try t.expect(a.syn_options.sack_permitted);
    var b = try hz.openPassive(h, l, .{ .peer_port = 40001 });
    defer b.stream.abort();
    try t.expect(!b.syn_options.sack_permitted);
    // Our own SYN offers it.
    var c = try hz.openActive(h, .{});
    defer c.stream.abort();
    try t.expect(c.syn_options.sack_permitted);
}

test "sack: as receiver, duplicate ACKs carry correct SACK blocks (most recent first, at most 4)" {
    try needSack();
    if (comptime !has_sack) return;
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = 1380, .sack_permitted = true } });
    defer c.stream.abort();
    const base = c.snd_nxt;
    var payload: [100]u8 = @splat('s');
    // Holes at 0..100; islands at 100k..100k+100 for k = 2, 4, 6, 8, 10.
    var k: u32 = 2;
    while (k <= 10) : (k += 2) {
        h.send(&c.peer, .{ .seq = base +% k * 100, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &payload });
        const d = (try h.seg(&c.peer)) orelse return error.NoDupAck;
        try t.expectEqual(base, d.ack);
        const s = d.options.sack orelse return error.NoSackBlocks;
        const blocks = s.slice();
        try t.expect(blocks.len >= 1 and blocks.len <= wire.max_sack_blocks);
        // RFC 2018 4: the first block covers the segment that triggered it.
        try t.expectEqual(base +% k * 100, blocks[0].start);
        try t.expectEqual(base +% k * 100 +% 100, blocks[0].end);
        for (blocks) |b| {
            try t.expect(hz.seqLt(base, b.start) and hz.seqLt(b.start, b.end));
            try t.expect((b.start -% base) % 200 == 0 and b.end -% b.start == 100);
        }
        try t.expectEqual(@as(usize, @min(k / 2, wire.max_sack_blocks)), blocks.len);
    }
    // Filling the first hole: ACK moves to the first island's end, blocks shrink.
    h.send(&c.peer, .{ .seq = base, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &payload });
    h.send(&c.peer, .{ .seq = base +% 100, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = &payload });
    var last: ?wire.Tcp = null;
    while (try h.seg(&c.peer)) |s| last = s;
    const a = last orelse (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoAck;
    try t.expectEqual(base +% 300, a.ack);
    if (a.options.sack) |s| for (s.slice()) |b| try t.expect(hz.seqLt(a.ack, b.start));
}

// ---------------------------------------------------------------- sender vs SACK peers

pub const Strategy = enum {
    /// Real blocks for what arrived past the cumulative ACK.
    honest,
    /// Blocks beyond SND.MAX or below SND.UNA.
    outside,
    /// start >= end, and zero-length blocks.
    inverted,
    /// [ack, ack - 1]: a block covering almost the whole sequence space.
    wrap_huge,
    /// Honest blocks, each also sent overlapping and duplicated.
    overlapping,
    /// 4 random in-flight blocks, different on every ACK (lies).
    churn,
    /// Claims everything after the first hole (reneging when it ACKs).
    lying,
    /// Honest; in the second half (cwnd grown by then) every other first
    /// transmission is lost: more holes in flight than the scoreboard holds.
    many_holes,
};

pub const RunOpts = struct {
    strategy: Strategy,
    total: usize = 256 * 1024,
    loss_ppm: u32 = 30_000,
    peer_mss: u16 = 1380,
    seed: u64 = 1,
    budget_ns: u64 = 900 * sec,
    /// false: the peer does not offer SACK (NewReno baseline).
    offer_sack: bool = true,
    /// Virtual time between the stack's burst and the peer's ACKs.
    rtt_ns: u64 = 0,
    /// Per-segment fate by (segment index, transmission number from 1);
    /// overrides `loss_ppm` / many_holes when set.
    fate: ?*const fn (index: usize, nth: u32) Fate = null,
    /// Delayed segments arrive this long after the rest of their burst.
    delay_ns: u64 = 2 * ms,
    /// Use a bulk stream (no tail loss probes).
    bulk: bool = false,
    /// Label for the report line.
    label: []const u8 = "",
};

pub const Fate = enum { deliver, drop, delay };

pub const RunResult = struct { virtual_ns: u64, max_out_per_ack: usize, stats: ns.Stats };

pub fn runSender(o: RunOpts) !RunResult {
    if (comptime !has_sack) unreachable;
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 600 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = o.peer_mss, .sack_permitted = o.offer_sack } });
    defer c.stream.abort();
    try t.expectEqual(o.offer_sack, c.syn_options.sack_permitted);
    if (o.bulk) c.stream.setPriority(.bulk);
    const base = c.rcv_nxt; // stack's first data byte
    var prng: std.Random.DefaultPrng = .init(o.seed);
    const rnd = prng.random();

    var got = try std.DynamicBitSetUnmanaged.initEmpty(gpa, o.total);
    defer got.deinit(gpa);
    const sends = try gpa.alloc(u8, o.total / o.peer_mss + 1);
    defer gpa.free(sends);
    @memset(sends, 0);
    var held: std.ArrayList([2]usize) = .empty; // delayed (offset, length)
    defer held.deinit(gpa);
    var cum: usize = 0;
    var highest: usize = 0;
    var written: usize = 0;
    var wbuf: [16 * 1024]u8 = undefined;

    // Allocation baseline once the connection exists (buffers allocated).
    const allocs0 = h.fa.allocations;
    var max_out: usize = 0;
    const t0 = h.now();
    var acks: std.ArrayList(struct { ack: u32, sack: ?wire.Sack }) = .empty;
    defer acks.deinit(gpa);

    while (cum < o.total) {
        while (written < o.total) {
            const n = @min(wbuf.len, o.total - written);
            hz.fillPattern(55, written, wbuf[0..n]);
            const k = c.stream.write(wbuf[0..n]) catch |e| switch (e) {
                error.WouldBlock => break,
                else => return e,
            };
            written += k;
        }
        const elapsed: u64 = @intCast(h.now() - t0);
        if (elapsed > o.budget_ns) {
            std.debug.print("sack {t}: stalled at {d}/{d} after {d} s\n", .{ o.strategy, cum, o.total, elapsed / sec });
            ns.testing.dumpStream("sender", c.stream);
            return error.Stalled;
        }
        var pkt_opt: ?[]u8 = h.waitOut(o.budget_ns - elapsed);
        if (pkt_opt == null) {
            std.debug.print("sack {t}: no packet and no timer at {d}/{d}\n", .{ o.strategy, cum, o.total });
            ns.testing.dumpStream("sender", c.stream);
            return error.NoTimerWhileIncomplete;
        }
        // The peer takes the whole burst first, then ACKs each segment (a
        // link with an RTT, so the flight can grow past a few segments).
        acks.clearRetainingCapacity();
        held.clearRetainingCapacity();
        var burst: usize = 0;
        while (pkt_opt) |raw| : (pkt_opt = h.out()) {
            burst += 1;
            const s = try c.peer.expect(raw);
            if (s.payload.len == 0) continue;
            try t.expect(s.payload.len <= o.peer_mss);
            const off: usize = s.seq -% base;
            if (off >= o.total or off + s.payload.len > o.total) return error.DataBeyondWritten;
            for (s.payload, 0..) |b, i| if (b != hz.patternByte(55, off + i)) return error.CorruptData;
            const idx = off / o.peer_mss;
            sends[idx] +|= 1;
            const first = sends[idx] == 1;
            const fate: Fate = if (o.fate) |f| f(idx, sends[idx]) else if (o.strategy == .many_holes)
                (if (first and off >= o.total / 2 and idx % 2 == 1) .drop else .deliver)
            else if (o.loss_ppm != 0 and rnd.uintLessThan(u32, 1_000_000) < o.loss_ppm) .drop else .deliver;
            switch (fate) {
                .drop => continue,
                .delay => {
                    try held.append(gpa, .{ off, s.payload.len });
                    continue;
                },
                .deliver => {},
            }
            for (0..s.payload.len) |i| got.set(off + i);
            highest = @max(highest, off + s.payload.len);
            while (cum < o.total and got.isSet(cum)) cum += 1;
            c.rcv_nxt = base +% @as(u32, @intCast(cum));
            const sack = if (o.offer_sack) blocksFor(o.strategy, rnd, &got, base, cum, highest, o.total) else null;
            try acks.append(gpa, .{ .ack = c.rcv_nxt, .sack = sack });
        }
        max_out = @max(max_out, burst / @max(acks.items.len, 1));
        if (o.rtt_ns != 0) h.advance(o.rtt_ns);
        for (acks.items) |a| h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = a.ack, .flags = .{ .ack = true }, .options = .{ .sack = a.sack } });
        if (held.items.len != 0) {
            h.advance(o.delay_ns);
            for (held.items) |hd| {
                for (0..hd[1]) |i| got.set(hd[0] + i);
                highest = @max(highest, hd[0] + hd[1]);
                while (cum < o.total and got.isSet(cum)) cum += 1;
                c.rcv_nxt = base +% @as(u32, @intCast(cum));
                const sack = if (o.offer_sack) blocksFor(o.strategy, rnd, &got, base, cum, highest, o.total) else null;
                h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .options = .{ .sack = sack } });
            }
        }
    }
    const virt: u64 = @intCast(h.now() - t0);
    const st = h.stats();
    std.debug.print("sack {t}{s}{s}: {d} KiB intact in {d:.2} virtual s; retransmits {d} (RTO {d}, fast {d}); SACK blocks ignored {d}; max {d} packets per ACK (burst average)\n", .{
        o.strategy, if (o.offer_sack) "" else " (no SACK)", o.label, o.total / 1024, @as(f64, @floatFromInt(virt)) / 1e9, st.retransmits, st.rto_expirations, st.fast_retransmits, st.sack_blocks_ignored, max_out,
    });
    // After establishment only the buffers resize (the send buffer grows
    // with the writes up to its cap, and goes back once drained): a few
    // allocations, however many blocks the peer sends.
    const lim = h.cfg.limits;
    const doublings = std.math.log2_int_ceil(u32, lim.send_buffer / @min(lim.initial_buffer, lim.send_buffer)) +
        std.math.log2_int_ceil(u32, lim.recv_buffer / @min(lim.initial_buffer, lim.recv_buffer));
    try t.expect(h.fa.allocations - allocs0 <= 2 * (@as(usize, doublings) + 1));
    // Work per ACK bounded by what cwnd / the send buffer allow, never by
    // what the peer's blocks claim.
    try t.expect(max_out <= 256);
    return .{ .virtual_ns = virt, .max_out_per_ack = max_out, .stats = st };
}

fn blocksFor(strategy: Strategy, rnd: std.Random, got: *const std.DynamicBitSetUnmanaged, base: u32, cum: usize, highest: usize, total: usize) ?wire.Sack {
    if (comptime !has_sack) unreachable;
    var s: wire.Sack = .{};
    const ack = base +% @as(u32, @intCast(cum));
    const top = base +% @as(u32, @intCast(highest));
    switch (strategy) {
        .honest, .many_holes, .overlapping => {
            // Islands past cum, highest first (most recent), at most 4.
            var end = highest;
            while (end > cum and s.len < wire.max_sack_blocks) {
                while (end > cum and !got.isSet(end - 1)) end -= 1;
                if (end <= cum) break;
                var start = end;
                while (start > cum and got.isSet(start - 1)) start -= 1;
                s.blocks[s.len] = .{ .start = base +% @as(u32, @intCast(start)), .end = base +% @as(u32, @intCast(end)) };
                s.len += 1;
                end = start;
            }
            if (strategy == .overlapping and s.len > 0 and s.len < wire.max_sack_blocks) {
                const b = s.blocks[0];
                s.blocks[s.len] = .{ .start = b.start -% 1, .end = b.end }; // overlaps and reaches into the hole
                s.len += 1;
                if (s.len < wire.max_sack_blocks) {
                    s.blocks[s.len] = b; // duplicate
                    s.len += 1;
                }
            }
        },
        .outside => {
            for (0..wire.max_sack_blocks) |i| {
                const far = rnd.intRangeAtMost(u32, 1, 1 << 30);
                s.blocks[i] = if (i % 2 == 0)
                    .{ .start = top +% far, .end = top +% far +% 1000 }
                else
                    .{ .start = ack -% far -% 1000, .end = ack -% far };
            }
            s.len = wire.max_sack_blocks;
        },
        .inverted => {
            s.blocks[0] = .{ .start = top, .end = ack };
            s.blocks[1] = .{ .start = ack +% 100, .end = ack +% 100 };
            s.blocks[2] = .{ .start = ack +% 500, .end = ack +% 200 };
            s.len = 3;
        },
        .wrap_huge => {
            s.blocks[0] = .{ .start = ack, .end = ack -% 1 };
            s.blocks[1] = .{ .start = ack +% 1, .end = ack };
            s.len = 2;
        },
        .churn => {
            const span: u32 = @intCast(@max(highest, cum + 1) - cum);
            for (0..wire.max_sack_blocks) |i| {
                const a = rnd.uintLessThan(u32, span);
                const b = rnd.uintLessThan(u32, span);
                s.blocks[i] = .{ .start = ack +% @min(a, b), .end = ack +% @max(a, b) +% 1 };
            }
            s.len = wire.max_sack_blocks;
        },
        .lying => {
            if (highest > cum + 1) {
                s.blocks[0] = .{ .start = ack +% 1, .end = base +% @as(u32, @intCast(@min(highest + 4096, total))) };
                s.len = 1;
            }
        },
    }
    return if (s.len == 0) null else s;
}

test "sack: honest peer at 3% loss, data intact" {
    try needSack();
    if (comptime !has_sack) return;
    _ = try runSender(.{ .strategy = .honest });
}

test "sack: blocks outside [snd_una, snd_max] are ignored and counted" {
    try needSack();
    if (comptime !has_sack) return;
    const r = try runSender(.{ .strategy = .outside });
    try t.expect(r.stats.sack_blocks_ignored > 0);
}

test "sack: inverted and zero-length blocks are ignored" {
    try needSack();
    if (comptime !has_sack) return;
    const r = try runSender(.{ .strategy = .inverted });
    try t.expect(r.stats.sack_blocks_ignored > 0);
}

test "sack: a block wrapping almost the whole sequence space is ignored" {
    try needSack();
    if (comptime !has_sack) return;
    const r = try runSender(.{ .strategy = .wrap_huge });
    try t.expect(r.stats.sack_blocks_ignored > 0);
}

test "sack: overlapping and duplicated blocks" {
    try needSack();
    if (comptime !has_sack) return;
    _ = try runSender(.{ .strategy = .overlapping });
}

test "sack: rapidly changing random blocks (lies) every ACK: no corruption, bounded work" {
    try needSack();
    if (comptime !has_sack) return;
    for (0..4) |seed| _ = try runSender(.{ .strategy = .churn, .seed = 100 + seed, .total = 128 * 1024 });
}

test "sack: reneging peer (SACKs data it never kept): data retransmitted after RTO, intact" {
    try needSack();
    if (comptime !has_sack) return;
    for (0..4) |seed| _ = try runSender(.{ .strategy = .lying, .seed = 200 + seed, .total = 128 * 1024 });
}

test "sack: more holes than the scoreboard holds: falls back, still completes, no worse than NewReno" {
    try needSack();
    if (comptime !has_sack) return;
    // A virtual RTT: with rtt_ns = 0 every RTT sample (and so RACK's
    // reo_wnd = min_RTT / 4) is microseconds of real time, which a busy
    // machine changes from run to run; the comparison then flaked.
    const with = try runSender(.{ .strategy = .many_holes, .loss_ppm = 0, .rtt_ns = 20 * ms });
    const without = try runSender(.{ .strategy = .many_holes, .loss_ppm = 0, .offer_sack = false, .rtt_ns = 20 * ms });
    // The scoreboard fallback must not make recovery slower than plain
    // NewReno on the same loss pattern (10% slack).
    try t.expect(with.virtual_ns * 10 <= without.virtual_ns * 11 + 10 * hz.ms);
}

test "sack: tiny MSS (64) with per-segment holes and 4 blocks per ACK (SACK Panic style)" {
    try needSack();
    if (comptime !has_sack) return;
    const r = try runSender(.{ .strategy = .many_holes, .loss_ppm = 0, .peer_mss = 64, .total = 64 * 1024 });
    try t.expect(r.stats.sack_blocks_ignored > 0); // more islands than max_sack_ranges: the cap held
    _ = try runSender(.{ .strategy = .churn, .peer_mss = 64, .total = 32 * 1024, .seed = 9 });
}

test "sack: honest SACK over many seeds at 5% loss (virtual link)" {
    try needSack();
    if (comptime !has_sack) return;
    for (0..10) |seed| _ = try runSender(.{ .strategy = .honest, .loss_ppm = 50_000, .seed = 300 + seed, .total = 128 * 1024 });
}
