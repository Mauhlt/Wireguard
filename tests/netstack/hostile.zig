//! Hostile input: malformed packets, floods, exhaustion, injection, peers
//! that stall. Every test checks the stack neither panics nor leaks (the
//! testing allocator) and stays within the documented Limits.
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

/// Recomputes the IPv4 header checksum after a test edited the header.
fn fixIpChecksum(pkt: []u8) void {
    const ihl: usize = @as(usize, pkt[0] & 0x0f) * 4;
    @memset(pkt[10..12], 0);
    std.mem.writeInt(u16, pkt[10..12], wire.checksum(pkt[0..@min(ihl, pkt.len)]), .big);
}

/// Recomputes the TCP checksum of a 20-byte-IP-header packet after a test
/// edited the segment.
fn fixTcpChecksum(pkt: []u8) void {
    const seg = pkt[20..];
    @memset(seg[16..18], 0);
    var c = wire.pseudoHeader(.{ .v4 = pkt[12..16].* }, .{ .v4 = pkt[16..20].* }, wire.proto_tcp, @intCast(seg.len));
    c.add(seg);
    std.mem.writeInt(u16, seg[16..18], c.final(), .big);
}

fn listenerPeer(port: u16) Peer {
    return .{ .peer = .{ .addr = hz.peer_addr, .port = port }, .stack = .{ .addr = hz.stack_addr, .port = 8420 } };
}

/// A valid SYN to the listener still gets its SYN-ACK (then RST it away).
fn expectStillServes(h: *H, port: u16) !void {
    var p = listenerPeer(port);
    h.send(&p, .{ .seq = 1, .flags = .{ .syn = true } });
    const sa = (try h.seg(&p)) orelse return error.ListenerStoppedServing;
    try t.expect(sa.flags.syn and sa.flags.ack);
    h.send(&p, .{ .seq = 2, .flags = .{ .rst = true } });
    try h.expectSilent();
}

// ---------------------------------------------------------------- malformed IPv4

test "hostile: malformed IPv4 (version, IHL, total length, checksum, fragments, truncation) dropped silently" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = listenerPeer(40000);
    var base_buf: [128]u8 = undefined;
    const good = p.packet(&base_buf, .{ .seq = 9, .flags = .{ .syn = true }, .options = .{ .mss = 1380 } });
    var b: [128]u8 = undefined;
    const Edit = struct { name: []const u8, at: usize, val: u8, fix: bool };
    const edits = [_]Edit{
        .{ .name = "version 6", .at = 0, .val = 0x65, .fix = true },
        .{ .name = "version 0", .at = 0, .val = 0x05, .fix = true },
        .{ .name = "IHL 4", .at = 0, .val = 0x44, .fix = true },
        .{ .name = "IHL 0", .at = 0, .val = 0x40, .fix = true },
        .{ .name = "IHL 15 (> packet)", .at = 0, .val = 0x4f, .fix = false },
        .{ .name = "total length high byte", .at = 2, .val = 0xff, .fix = true },
        .{ .name = "total length < IHL", .at = 3, .val = 4, .fix = true },
        .{ .name = "header checksum", .at = 10, .val = 0x00, .fix = false },
        .{ .name = "MF fragment", .at = 6, .val = 0x20, .fix = true },
        .{ .name = "fragment offset", .at = 7, .val = 0x01, .fix = true },
        .{ .name = "MF + DF", .at = 6, .val = 0x60, .fix = true },
    };
    var expected_drops: u64 = 0;
    for (edits) |e| {
        @memcpy(b[0..good.len], good);
        if (e.at == 10) b[11] ^= 0x5a else b[e.at] = e.val;
        if (e.at == 3) b[2] = 0;
        if (e.fix) fixIpChecksum(b[0..good.len]);
        h.sendRaw(b[0..good.len]);
        expected_drops += 1;
        h.expectSilent() catch |err| {
            std.debug.print("answered a packet with bad {s}\n", .{e.name});
            return err;
        };
    }
    for (0..good.len) |n| {
        h.sendRaw(good[0..n]);
        try h.expectSilent();
    }
    expected_drops += good.len;
    // (A version-6 nibble now goes to the IPv6 parser: it may count as not-for-us.)
    try t.expect(h.stats().dropped_malformed + h.stats().dropped_not_for_us >= expected_drops);
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    try expectStillServes(h, 40001);
}

test "hostile: IPv4 with options (IHL 6) is parsed past the options, never misread" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = listenerPeer(40000);
    var a: [128]u8 = undefined;
    const good = p.packet(&a, .{ .seq = 9, .flags = .{ .syn = true } });
    var b: [132]u8 = undefined;
    @memcpy(b[0..20], good[0..20]);
    b[0] = 0x46;
    @memcpy(b[20..24], &[_]u8{ 1, 1, 1, 0 }); // NOP NOP NOP EOL
    @memcpy(b[24 .. good.len + 4], good[20..]);
    std.mem.writeInt(u16, b[2..4], @intCast(good.len + 4), .big);
    fixIpChecksum(b[0 .. good.len + 4]);
    h.sendRaw(b[0 .. good.len + 4]);
    // Either dropped or answered correctly; never answered with garbage.
    if (h.out()) |pkt| {
        const sa = try p.expect(pkt);
        try t.expect(sa.flags.syn and sa.flags.ack);
        try t.expectEqual(@as(u32, 10), sa.ack);
    }
}

test "hostile: non-TCP/ICMP protocols and other destinations are dropped and counted" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var b: [64]u8 = undefined;
    for ([_]u8{ 17, 0, 2, 41, 47, 50, 255 }) |proto| {
        @memset(b[20..40], 0);
        try (wire.Ip4{ .protocol = proto, .src = hz.peer_ip, .dst = hz.stack_ip }).write(&b, 20);
        h.sendRaw(b[0..40]);
        try h.expectSilent();
    }
    const before = h.stats().dropped_not_for_us;
    var p: Peer = .{ .peer = .{ .addr = hz.peer_addr, .port = 40000 }, .stack = .{ .addr = .{ .v4 = .{ 10, 8, 0, 3 } }, .port = 8420 } };
    var buf: [128]u8 = undefined;
    for ([_][4]u8{ .{ 10, 8, 0, 3 }, .{ 255, 255, 255, 255 }, .{ 224, 0, 0, 1 }, .{ 0, 0, 0, 0 }, .{ 127, 0, 0, 1 } }) |dst| {
        p.stack.addr = .{ .v4 = dst };
        h.sendRaw(p.packet(&buf, .{ .seq = 1, .flags = .{ .syn = true } }));
        try h.expectSilent();
    }
    try t.expect(h.stats().dropped_not_for_us >= before + 5);
    try t.expectEqual(@as(u16, 0), h.stats().connections);
}

test "hostile: SYN from a broadcast, multicast or own source address gets no SYN-ACK" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var buf: [128]u8 = undefined;
    for ([_][4]u8{ .{ 255, 255, 255, 255 }, .{ 224, 0, 0, 5 }, hz.stack_ip, .{ 0, 0, 0, 0 } }) |src| {
        var p: Peer = .{ .peer = .{ .addr = .{ .v4 = src }, .port = 40000 }, .stack = .{ .addr = hz.stack_addr, .port = 8420 } };
        h.sendRaw(p.packet(&buf, .{ .seq = 1, .flags = .{ .syn = true } }));
        if (h.out()) |pkt| {
            const tp = try wire.parseTcp4(pkt);
            std.debug.print("SYN from {d}.{d}.{d}.{d} answered (flags {any})\n", .{ src[0], src[1], src[2], src[3], tp.tcp.flags });
            return error.AnsweredBogusSource; // RFC 9293 3.10.7.2 / RFC 1122 4.2.3.10
        }
    }
}

// ---------------------------------------------------------------- malformed TCP

test "hostile: malformed TCP (data offset, option lengths, option loops, checksum) dropped, no RST" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = listenerPeer(40000);
    var a: [128]u8 = undefined;
    // 20 option bytes: MSS(4) WS(3) SACKP(2) TS(10) + 1 pad.
    const good = p.packet(&a, .{ .seq = 9, .flags = .{ .syn = true }, .options = .{ .mss = 1380, .window_scale = 7, .sack_permitted = true, .timestamp = .{ 1, 2 } } });
    const opt_at = 40;
    var b: [128]u8 = undefined;
    const opt_cases = [_][]const u8{
        &.{ 2, 0 }, // MSS, length 0 (a zero-length loop)
        &.{ 9, 0 }, // unknown kind, length 0
        &.{ 2, 1 }, // length 1
        &.{ 2, 3, 5 }, // MSS with length 3
        &.{ 3, 2 }, // WS with length 2
        &.{ 8, 9 }, // TS with length 9
        &.{ 4, 3, 0 }, // SACK-permitted length 3
        &.{ 2, 40 }, // length past the option area
        &.{ 5, 255 }, // SACK block running off the end
        &.{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2 }, // NOPs then a kind with no length
    };
    for (opt_cases) |oc| {
        @memcpy(b[0..good.len], good);
        @memset(b[opt_at .. opt_at + 20], 1);
        @memcpy(b[opt_at .. opt_at + oc.len], oc);
        fixTcpChecksum(b[0..good.len]);
        h.sendRaw(b[0..good.len]);
        h.expectSilent() catch |err| {
            std.debug.print("answered TCP options {any}\n", .{oc});
            return err;
        };
    }
    // Data offset below 5, past the segment, and pointing into the payload.
    for ([_]u8{ 0x00, 0x40, 0xf0 }) |off| {
        @memcpy(b[0..good.len], good);
        b[32] = off;
        fixTcpChecksum(b[0..good.len]);
        h.sendRaw(b[0..good.len]);
        try h.expectSilent();
    }
    // Bad TCP checksum (every byte position flipped once).
    for (20..good.len) |i| {
        @memcpy(b[0..good.len], good);
        b[i] ^= 0x01;
        h.sendRaw(b[0..good.len]);
        try h.expectSilent();
    }
    try t.expectEqual(@as(u64, 0), h.stats().rst_sent);
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    try expectStillServes(h, 40001);
}

test "hostile: absurd MSS (0, 1, 65535) and window scale (200) in a SYN: no panic, sane segments" {
    for ([_]u16{ 0, 1, 7, 65535 }) |mss| {
        const h = try H.create(gpa, .{});
        defer h.destroy();
        const l = try h.stack.listen(8420);
        var p = listenerPeer(40000);
        h.send(&p, .{ .seq = 9, .flags = .{ .syn = true }, .options = .{ .mss = mss, .window_scale = 200 } });
        const sa = (try h.seg(&p)) orelse continue; // refusing it is fine
        if (sa.flags.rst) continue;
        h.send(&p, .{ .seq = 10, .ack = sa.seq +% 1, .flags = .{ .ack = true }, .window = 65535 });
        const st = l.accept() catch continue;
        defer st.abort();
        var data: [5000]u8 = undefined;
        hz.fillPattern(11, 0, &data);
        _ = try hz.writeSome(st, &data);
        var packets: usize = 0;
        var max_payload: usize = 0;
        while (h.out()) |pkt| {
            const s = try p.expect(pkt);
            max_payload = @max(max_payload, s.payload.len);
            packets += 1;
            if (packets > 10_000) return error.SegmentStorm;
        }
        try t.expect(max_payload <= 1380);
        if (mss >= 1) try t.expect(packets < 5000); // a 1-byte MSS must not become 5000 packets per burst
    }
}

// ---------------------------------------------------------------- floods / exhaustion

test "hostile: SYN flood past syn_backlog: extra SYNs dropped and counted, half-opens expire" {
    var limits: ns.Limits = .{};
    limits.syn_backlog = 4;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var answered: usize = 0;
    for (0..20) |i| {
        var p = listenerPeer(@intCast(30000 + i));
        h.send(&p, .{ .seq = 100, .flags = .{ .syn = true } });
        while (h.out()) |pkt| {
            const tp = try wire.parseTcp4(pkt);
            if (tp.tcp.flags.syn and tp.tcp.flags.ack) answered += 1;
        }
    }
    try t.expectEqual(@as(usize, 4), answered);
    try t.expectEqual(@as(u64, 16), h.stats().dropped_syn_backlog);
    try t.expect(h.stats().connections <= 4);
    try t.expectError(error.WouldBlock, l.accept());
    // Half-open connections give up (bounded SYN-ACK retries / user timeout).
    var waited: u64 = 0;
    while (h.stats().connections != 0 and waited < 2 * limits.user_timeout_ns) {
        const d = h.nextDeadline() orelse break;
        _ = h.drain();
        h.advance(@max(d, 1 * ms));
        waited += @max(d, 1 * ms);
    }
    _ = h.drain();
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    try t.expect(waited <= limits.user_timeout_ns + 5 * sec);
    try expectStillServes(h, 50000);
}

test "hostile: accept-backlog overflow: never more than accept_backlog queued" {
    var limits: ns.Limits = .{};
    limits.accept_backlog = 2;
    limits.syn_backlog = 16;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    for (0..6) |i| {
        _ = hz.openPassive(h, l, .{ .peer_port = @intCast(31000 + i), .accept = false }) catch {};
        _ = h.drain();
    }
    var accepted: usize = 0;
    while (l.accept()) |st| {
        accepted += 1;
        st.abort();
    } else |e| try t.expectEqual(error.WouldBlock, e);
    std.debug.print("accept backlog 2: {d} connections were queued for accept\n", .{accepted});
    try t.expect(accepted >= 1 and accepted <= 2);
    try t.expect(h.stats().connections <= limits.syn_backlog + limits.accept_backlog);
}

test "hostile: connection exhaustion at max_connections: SYNs and dials refused, slots come back" {
    var limits: ns.Limits = .{};
    limits.max_connections = 4;
    limits.syn_backlog = 16;
    limits.accept_backlog = 16;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var answered: usize = 0;
    for (0..10) |i| {
        var p = listenerPeer(@intCast(32000 + i));
        h.send(&p, .{ .seq = 100, .flags = .{ .syn = true } });
        while (h.out()) |pkt| {
            const tp = try wire.parseTcp4(pkt);
            if (tp.tcp.flags.syn and tp.tcp.flags.ack) answered += 1;
        }
    }
    try t.expectEqual(@as(usize, 4), answered);
    try t.expectEqual(@as(u16, 4), h.stats().connections);
    try t.expectError(error.TooManyConnections, h.stack.dial(.{ .addr = hz.peer_addr, .port = 1 }));
    // Reset the half-opens: room again.
    for (0..4) |i| {
        var p = listenerPeer(@intCast(32000 + i));
        h.send(&p, .{ .seq = 101, .flags = .{ .rst = true } });
    }
    _ = h.drain();
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 1 });
    st.abort();
    _ = l;
}

test "hostile: out-of-order flood (1000 one-byte holes): bookkeeping capped, no new memory" {
    var limits: ns.Limits = .{};
    limits.max_ooo_segments = 8;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    _ = h.drain();
    const live = h.liveBytes();
    const allocs = h.fa.allocations;
    for (0..1000) |i| {
        h.send(&c.peer, .{ .seq = c.snd_nxt +% @as(u32, @intCast(2 * i + 1)), .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "z" });
        _ = h.drain();
    }
    try t.expect(h.stats().dropped_ooo >= 1000 - 8);
    try t.expectEqual(live, h.liveBytes());
    try t.expectEqual(allocs, h.fa.allocations);
    // Fill from the start: in-order data still works.
    c.data(h, "abc");
    var buf: [8]u8 = undefined;
    const n = try c.stream.read(&buf);
    try t.expect(n >= 3);
    try t.expectEqualStrings("abc", buf[0..3]);
}

test "hostile: memory stays within the Limits formula with every connection busy" {
    var limits: ns.Limits = .{};
    limits.max_connections = 8;
    limits.send_buffer = 32 * 1024;
    limits.recv_buffer = 32 * 1024;
    limits.ring_packets = 64;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var conns: [8]hz.Conn = undefined;
    var peak: usize = h.liveBytes();
    var junk: [32 * 1024]u8 = @splat(0x55);
    for (&conns, 0..) |*c, i| {
        c.* = try hz.openPassive(h, l, .{ .peer_port = @intCast(33000 + i), .window = 0 });
        _ = try hz.writeSome(c.stream, &junk); // fill the send buffer (peer window 0)
        var off: usize = 0;
        while (off < junk.len) : (off += 1380) c.data(h, junk[off..@min(off + 1380, junk.len)]);
        _ = h.drain();
        peak = @max(peak, h.liveBytes());
    }
    // root.zig's Limits doc: buffers + the two rings + per-connection fixed
    // state. That state is the connection record (tcp.Conn, RACK's ring
    // included); its size comes from the type, not from slack. The doc's
    // "< 1 KiB" is checked separately (see the next test).
    const conn_state = @sizeOf(ConnType) + 64; // + the slot's bookkeeping
    const bound = @as(usize, limits.max_connections) * (limits.send_buffer + limits.recv_buffer) +
        2 * @as(usize, limits.ring_packets) * 1420 + @as(usize, limits.max_connections) * conn_state + 64 * 1024;
    std.debug.print("netstack memory: peak {d} bytes, bound {d} (fixed state {d} bytes per connection)\n", .{ peak, bound, conn_state });
    try t.expect(peak <= bound);
    for (&conns) |*c| c.stream.abort();
}

test "hostile: tiny-window slowloris: never exceeds the 1-byte window; writes back-pressure" {
    var limits: ns.Limits = .{};
    limits.send_buffer = 8 * 1024;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .window = 1 });
    defer c.stream.abort();
    var data: [64 * 1024]u8 = undefined;
    hz.fillPattern(12, 0, &data);
    const accepted = try hz.writeSome(c.stream, &data);
    try t.expect(accepted <= limits.send_buffer);
    try t.expectError(error.WouldBlock, c.stream.write("more"));
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    // The peer takes one byte per ACK for a while.
    var rounds: usize = 0;
    while (rounds < 300) : (rounds += 1) {
        const pkt = h.waitOut(70 * sec) orelse break;
        var pp: ?[]u8 = pkt;
        while (pp) |raw| : (pp = h.out()) {
            const s = try c.peer.expect(raw);
            // Beyond the window only a 1-byte probe is allowed.
            try t.expect(s.payload.len <= 1);
            if (s.payload.len == 1 and s.seq == c.rcv_nxt) {
                try got.append(gpa, s.payload[0]);
                c.rcv_nxt +%= 1;
            }
        }
        c.ack(h);
    }
    try t.expect(got.items.len > 0);
    try t.expectEqualSlices(u8, data[0..got.items.len], got.items);
    try t.expect(c.stream.status().write_available <= limits.send_buffer);
}

test "hostile: huge window claim (scale 14): flight bounded by cwnd and send_buffer" {
    var limits: ns.Limits = .{};
    limits.send_buffer = 64 * 1024;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .syn_options = .{ .mss = 1380, .window_scale = 14 } });
    defer c.stream.abort();
    var data: [256 * 1024]u8 = undefined;
    hz.fillPattern(13, 0, &data);
    const accepted = try hz.writeSome(c.stream, &data);
    try t.expect(accepted <= limits.send_buffer);
    var bytes: usize = 0;
    while (try h.seg(&c.peer)) |s| bytes += s.payload.len;
    try t.expect(bytes <= 10 * 1380); // initial window, not the peer's 1 GiB
}

// ---------------------------------------------------------------- injection

test "hostile: RST / ACK / SYN injection with out-of-window numbers changes nothing" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    _ = try c.stream.write("ping");
    const d = (try h.seg(&c.peer)) orelse return error.NoData;
    try t.expectEqualStrings("ping", d.payload);
    const offsets = [_]u32{ 1 << 20, 1 << 30, 1 << 31, 0xFFFF_0000, 0xFFFF_FF00, 70000 };
    for (offsets) |off| {
        h.send(&c.peer, .{ .seq = c.snd_nxt +% off, .flags = .{ .rst = true } });
        h.send(&c.peer, .{ .seq = c.snd_nxt +% off, .ack = c.rcv_nxt, .flags = .{ .rst = true, .ack = true } });
        try t.expectEqual(ns.State.established, c.state());
        // ACK of data never sent / far in the past: must not move SND.UNA.
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt +% 4 +% off, .flags = .{ .ack = true } });
        // (0xFFFF_FFFF would straddle RCV.NXT: legitimately in window for data.)
        if (off != 0xFFFF_FFFF) h.send(&c.peer, .{ .seq = c.snd_nxt +% off, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "evil" });
        _ = h.drain();
        try t.expectEqual(ns.State.established, c.state());
    }
    var buf: [16]u8 = undefined;
    try t.expectError(error.WouldBlock, c.stream.read(&buf)); // no injected data delivered
    // The unacked "ping" is still retransmitted intact.
    const re = (try h.waitSeg(&c.peer, 5 * sec)) orelse return error.NoRetransmit;
    try t.expectEqual(c.rcv_nxt, re.seq);
    try t.expectEqualStrings("ping", re.payload);
    c.rcv_nxt +%= 4;
    c.ack(h);
    c.data(h, "pong");
    try t.expectEqual(@as(usize, 4), try c.stream.read(&buf));
    try t.expectEqualStrings("pong", buf[0..4]);
}

test "hostile: conflicting retransmission cannot rewrite delivered or queued bytes" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.abort();
    const base = c.snd_nxt;
    h.send(&c.peer, .{ .seq = base, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "AAAAAAAAAA" });
    h.send(&c.peer, .{ .seq = base +% 5, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "BBBBBBBBBB" });
    // Out of order, then a conflicting overlap of the queued part.
    h.send(&c.peer, .{ .seq = base +% 30, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "CCCCCCCCCC" });
    h.send(&c.peer, .{ .seq = base +% 25, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "DDDDDDDDDD" });
    h.send(&c.peer, .{ .seq = base +% 15, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .payload = "EEEEEEEEEE" });
    _ = h.drain();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try hz.readAvailable(c.stream, gpa, &got);
    try t.expectEqual(@as(usize, 40), got.items.len);
    try t.expectEqualStrings("AAAAAAAAAA", got.items[0..10]); // delivered first: kept
    try t.expectEqualStrings("BBBBB", got.items[10..15]);
    try t.expectEqualStrings("EEEEEEEEEE", got.items[15..25]);
    for (got.items[25..30]) |x| try t.expect(x == 'D');
    for (got.items[30..40]) |x| try t.expect(x == 'C' or x == 'D');
}

test "hostile: data after FIN is never delivered" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    c.data(h, "real");
    c.fin(h);
    c.data(h, "after fin");
    h.send(&c.peer, .{ .seq = c.snd_nxt -% 10, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true }, .payload = "XXXXXXXXXXXX" });
    _ = h.drain();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    try t.expect(try hz.readAvailable(c.stream, gpa, &got));
    try t.expectEqualStrings("real", got.items);
}

// ---------------------------------------------------------------- stalls

test "hostile: a peer that never answers the SYN: ConnectionTimedOut at user_timeout, slot freed" {
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 20 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const st = try h.stack.dial(.{ .addr = hz.peer_addr, .port = 443 });
    defer st.close();
    var syns: usize = 0;
    const t0 = h.now();
    while (h.waitOut(limits.user_timeout_ns + 10 * sec)) |pkt| {
        const tp = try wire.parseTcp4(pkt);
        try t.expect(tp.tcp.flags.syn);
        syns += 1;
        if (syns > 50) return error.SynStorm;
    }
    const elapsed: u64 = @intCast(h.now() - t0);
    var buf: [4]u8 = undefined;
    try t.expectError(error.ConnectionTimedOut, st.read(&buf));
    std.debug.print("unanswered SYN: gave up after {d} ms (user_timeout {d} ms)\n", .{ elapsed / ms, limits.user_timeout_ns / ms });
    try t.expect(elapsed <= limits.user_timeout_ns + 1 * sec);
    try t.expect(h.stats().timeouts >= 1);
    try t.expect(syns >= 2);
}

test "hostile: a peer that never ACKs data: ConnectionTimedOut within user_timeout" {
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 20 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    defer c.stream.close();
    _ = try c.stream.write("hello?");
    const t0 = h.now();
    while (h.waitOut(limits.user_timeout_ns + 70 * sec)) |_| {}
    const elapsed: u64 = @intCast(h.now() - t0);
    try t.expectError(error.ConnectionTimedOut, c.stream.write("x"));
    var buf: [4]u8 = undefined;
    try t.expectError(error.ConnectionTimedOut, c.stream.read(&buf));
    std.debug.print("never-ACKs: gave up after {d} ms (user_timeout {d} ms)\n", .{ elapsed / ms, limits.user_timeout_ns / ms });
    try t.expect(elapsed <= limits.user_timeout_ns + 1 * sec);
}

test "hostile: closed stream whose FIN is never ACKed is freed in the background" {
    var limits: ns.Limits = .{};
    limits.user_timeout_ns = 20 * sec;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{});
    c.stream.close();
    try t.expectEqual(@as(u16, 1), h.stats().connections);
    while (h.waitOut(limits.user_timeout_ns + 70 * sec)) |_| {}
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    // FIN-WAIT-2 forever (peer ACKs our FIN, never sends its own):
    var c2 = try hz.openPassive(h, l, .{ .peer_port = 40002 });
    c2.stream.close();
    _ = (try h.waitSeg(&c2.peer, 1 * sec)) orelse return error.NoFin;
    c2.rcv_nxt +%= 1;
    c2.ack(h);
    var waited: u64 = 0;
    while (h.stats().connections != 0 and waited < 600 * sec) {
        const d = h.nextDeadline() orelse break;
        _ = h.drain();
        h.advance(@max(d, 1 * ms));
        waited += @max(d, 1 * ms);
    }
    if (h.stats().connections != 0) return error.FinWait2Forever;
    std.debug.print("orphaned FIN-WAIT-2 freed after {d} s\n", .{waited / sec});
}

// ---------------------------------------------------------------- handles

test "hostile: stale handles return Closed; double close / abort are harmless" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    const c = try hz.openPassive(h, l, .{});
    const st = c.stream;
    st.abort();
    _ = h.drain(); // its RST
    var buf: [4]u8 = undefined;
    try t.expectError(error.Closed, st.read(&buf));
    try t.expectError(error.Closed, st.write("x"));
    st.close();
    st.abort();
    st.shutdown();
    // A new connection reusing the slot: the old handle still says Closed.
    var c2 = try hz.openPassive(h, l, .{ .peer_port = 40001 });
    defer c2.stream.abort();
    try t.expectError(error.Closed, st.read(&buf));
    try t.expectEqual(ns.State.established, c2.state());
    l.close();
    l.close();
    try t.expectError(error.Closed, l.accept());
}

test "hostile: listener close resets queued connections and frees them" {
    const h = try H.create(gpa, .{});
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var a = try hz.openPassive(h, l, .{ .accept = false });
    var b = try hz.openPassive(h, l, .{ .peer_port = 40001, .accept = false });
    _ = h.drain();
    l.close();
    var resets: usize = 0;
    while (h.out()) |pkt| {
        const tp = try wire.parseTcp4(pkt);
        if (tp.tcp.flags.rst) resets += 1;
    }
    try t.expectEqual(@as(usize, 2), resets);
    try t.expectEqual(@as(u16, 0), h.stats().connections);
    _ = &a;
    _ = &b;
    _ = try h.stack.listen(8420); // the port is free again
}

test "hostile: too many listeners / port in use" {
    var limits: ns.Limits = .{};
    limits.max_listeners = 2;
    const h = try H.create(gpa, .{ .limits = limits });
    defer h.destroy();
    _ = try h.stack.listen(1);
    try t.expectError(error.AddressInUse, h.stack.listen(1));
    _ = try h.stack.listen(2);
    try t.expectError(error.TooManyListeners, h.stack.listen(3));
}

test "hostile: invalid options are refused at create" {
    var clock: ns.Clock = .{ .io = t.io };
    // A v4-mapped IPv6 address is never ours; a v6 address6 next to a v6 address neither.
    if (ns.Stack.create(gpa, &clock, .{ .address = .{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 8, 0, 1 } } })) |s| {
        s.destroy();
        return error.AcceptedV4MappedAddress;
    } else |_| {}
    if (ns.Stack.create(gpa, &clock, .{ .address = hz.stack_addr, .mtu = 40 })) |s| {
        s.destroy();
        return error.AcceptedMtu40;
    } else |e| try t.expectEqual(error.InvalidMtu, e);
    var limits: ns.Limits = .{};
    limits.max_connections = 0;
    if (ns.Stack.create(gpa, &clock, .{ .address = hz.stack_addr, .limits = limits })) |s| {
        s.destroy();
        return error.AcceptedZeroConnections;
    } else |_| {}
}

// ---------------------------------------------------------------- allocation failures

/// create / listen / dial / passive handshake / accept / data / destroy
/// with the allocator failing at `fail_index`. Returns true when no
/// failure was induced (the scenario ran to the end).
fn allocScenario(fail_index: usize) !bool {
    var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = fail_index });
    const a = fa.allocator();
    var clock: ns.Clock = .{ .io = t.io };
    const s = ns.Stack.create(a, &clock, .{ .address = hz.stack_addr }) catch |e| {
        try t.expect(e == error.OutOfMemory or e == error.SystemResources);
        try t.expect(fa.has_induced_failure);
        return false;
    };
    defer s.destroy();
    var outbuf: [2048]u8 = undefined;
    var inbuf: [2048]u8 = undefined;
    const l = try s.listen(8420);
    if (s.dial(.{ .addr = hz.peer_addr, .port = 443 })) |st| {
        while (s.output(&outbuf)) |_| {}
        st.abort();
    } else |e| try t.expectEqual(error.TooManyConnections, e);
    var p = listenerPeer(40000);
    s.input(p.packet(&inbuf, .{ .seq = 1, .flags = .{ .syn = true } }));
    var iss: ?u32 = null;
    while (s.output(&outbuf)) |pkt| {
        const tp = wire.parseTcp4(pkt) catch continue;
        if (tp.tcp.flags.syn and tp.tcp.flags.ack) iss = tp.tcp.seq;
    }
    if (iss) |x| {
        s.input(p.packet(&inbuf, .{ .seq = 2, .ack = x +% 1, .flags = .{ .ack = true, .psh = true }, .payload = "hi" }));
        while (s.output(&outbuf)) |_| {}
        if (l.accept()) |st| {
            var b: [4]u8 = undefined;
            _ = st.read(&b) catch {};
            _ = st.write("yo") catch {};
            while (s.output(&outbuf)) |_| {}
            st.close();
        } else |_| {}
    }
    return !fa.has_induced_failure;
}

test "hostile: allocation-failure sweep over create / listen / dial / accept: no leak, no panic" {
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        if (try allocScenario(i)) break;
    } else return error.SweepDidNotFinish;
    std.debug.print("allocation-failure sweep: {d} failure points\n", .{i});
}
/// The per-connection record (tcp.Conn), reached through the public
/// `Stream.debugConn` (which returns a copy of it).
const ConnType = @typeInfo(@typeInfo(@TypeOf(ns.Stream.debugConn)).@"fn".return_type.?).optional.child;

test "hostile: per-connection fixed state matches the Limits doc (< 1 KiB)" {
    // root.zig: "max_connections * small fixed state (< 1 KiB)".
    std.debug.print("tcp.Conn is {d} bytes\n", .{@sizeOf(ConnType)});
    try t.expect(@sizeOf(ConnType) < 1024);
}