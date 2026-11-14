//! IPv6 in the stack (Options.address6, MSS 1360, ICMPv6 echo): handshakes
//! in both directions, malformed headers, extension-header chains past the
//! cap, fragments, addresses that are not ours, the TCP / ICMPv6 checksum
//! over the IPv6 pseudo-header checked against an independent
//! byte-by-byte layout (RFC 8200 8.1), and a mutation sweep.
const std = @import("std");
const t = std.testing;
const hz = @import("harness.zig");
const ns = hz.ns;
const wire = hz.wire;
const H = hz.H;
const Peer = hz.Peer;
const sec = hz.sec;

const gpa = t.allocator;
const has_wire6 = @hasDecl(wire, "Ip6") and @hasDecl(wire, "buildTcp");

fn needV6() !void {
    if (comptime !(hz.has_ipv6 and has_wire6)) return hz.skip("IPv6 not on feat/netstack yet");
}

fn dual() !*H {
    return H.create(gpa, .{ .address6 = hz.stack_addr6 });
}

fn peer6(port: u16) Peer {
    return .{ .peer = .{ .addr = hz.peer_addr6, .port = port }, .stack = .{ .addr = hz.stack_addr6, .port = 8420 } };
}

/// The IPv6 pseudo-header sum laid out byte by byte (RFC 8200 8.1), an
/// independent check of wire.pseudoHeader and of what the stack sends.
fn referenceSum6(src: [16]u8, dst: [16]u8, nh: u8, upper: []const u8) u16 {
    var c: wire.Checksum = .{};
    c.add(&src);
    c.add(&dst);
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(upper.len), .big);
    c.add(&len);
    c.add(&.{ 0, 0, 0, nh });
    c.add(upper);
    return c.final();
}

test "ipv6: passive open on address6: SYN-ACK MSS 1360, data both ways, checksum by the RFC layout" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .peer_addr = hz.peer_addr6, .stack_addr = hz.stack_addr6, .syn_options = .{ .mss = 1440 } });
    defer c.stream.abort();
    try t.expectEqual(@as(?u16, 1360), c.syn_options.mss);
    try t.expectEqual(ns.State.established, c.state());
    try t.expect(c.stream.remote().addr.eql(hz.peer_addr6));
    try t.expect(c.stream.local().addr.eql(hz.stack_addr6));
    c.data(h, "over six");
    var buf: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 8), try c.stream.read(&buf));
    // The stack's segments: <= 1360 bytes, checksum valid per the RFC layout.
    var data: [5000]u8 = undefined;
    hz.fillPattern(61, 0, &data);
    _ = try hz.writeSome(c.stream, &data);
    var got: usize = 0;
    while (h.waitOut(1 * sec)) |pkt| {
        const ip = try wire.Ip6.parse(pkt);
        try t.expectEqual(@as(u16, 0), referenceSum6(ip.header.src, ip.header.dst, wire.proto_tcp, ip.payload));
        const s = try c.peer.expect(pkt);
        try t.expect(s.payload.len <= 1360);
        if (s.payload.len != 0 and s.seq == c.rcv_nxt) {
            try t.expectEqualSlices(u8, data[got..][0..s.payload.len], s.payload);
            got += s.payload.len;
            c.rcv_nxt +%= @intCast(s.payload.len);
            c.ack(h);
        }
        if (got == data.len) break;
    }
    try t.expectEqual(data.len, got);
}

test "ipv6: dial to a v6 peer uses address6; v4 dials still use the v4 address" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    var c = try hz.openActive(h, .{ .peer_addr = hz.peer_addr6 });
    defer c.stream.abort();
    try t.expect(c.peer.stack.addr.eql(hz.stack_addr6));
    try t.expectEqual(@as(?u16, 1360), c.syn_options.mss);
    var c4 = try hz.openActive(h, .{ .port = 444 });
    defer c4.stream.abort();
    try t.expect(c4.peer.stack.addr.eql(hz.stack_addr));
    try t.expectEqual(@as(?u16, 1380), c4.syn_options.mss);
}

test "ipv6: one listener serves both families; ISNs differ per tuple" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var a = try hz.openPassive(h, l, .{});
    defer a.stream.abort();
    var b = try hz.openPassive(h, l, .{ .peer_addr = hz.peer_addr6, .stack_addr = hz.stack_addr6 });
    defer b.stream.abort();
    try t.expect(a.iss != b.iss);
}

test "ipv6: a v4-only stack drops IPv6, a v6 dial fails cleanly" {
    try needV6();
    const h = try H.create(gpa, .{});
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = peer6(40000);
    var buf: [256]u8 = undefined;
    h.sendRaw(p.packet(&buf, .{ .seq = 1, .flags = .{ .syn = true } }));
    try h.expectSilent();
    if (h.stack.dial(.{ .addr = hz.peer_addr6, .port = 1 })) |st| {
        st.abort();
        return error.DialedV6WithoutAddress6;
    } else |e| try t.expectEqual(error.AddressFamilyUnsupported, e);
}

/// A valid v6 SYN to the listener; returns its length in `buf`.
fn goodSyn(buf: []u8, p: *Peer) usize {
    return p.packet(buf, .{ .seq = 9, .flags = .{ .syn = true }, .options = .{ .mss = 1360 } }).len;
}

fn expectStillServes6(h: *H, port: u16) !void {
    var p = peer6(port);
    h.send(&p, .{ .seq = 1, .flags = .{ .syn = true } });
    const sa = (try h.seg(&p)) orelse return error.ListenerStoppedServing;
    try t.expect(sa.flags.syn and sa.flags.ack);
    h.send(&p, .{ .seq = 2, .flags = .{ .rst = true } });
    try h.expectSilent();
}

const Ext = struct {
    /// Next-header value that announces this header (0 hop-by-hop, 60
    /// destination options, 43 routing, 44 fragment, ...).
    kind: u8,
    /// Everything after the 2-byte (next, length) prefix: 6 + 8k bytes.
    body: []const u8,
};

const pad6 = [_]u8{ 1, 4, 0, 0, 0, 0 }; // PadN, 4 bytes
const router_alert = [_]u8{ 5, 2, 0, 0, 1, 0 }; // a real option

/// [IPv6 | extension headers | TCP SYN] peer6 -> stack6, checksums valid.
fn withExt(buf: []u8, p: *Peer, exts: []const Ext) []u8 {
    var tcp_buf: [128]u8 = undefined;
    const syn = p.packet(&tcp_buf, .{ .seq = 9, .flags = .{ .syn = true } });
    const tcp = syn[wire.ip6_header_len..];
    var off: usize = wire.ip6_header_len;
    for (exts, 0..) |e, i| {
        buf[off] = if (i + 1 < exts.len) exts[i + 1].kind else wire.proto_tcp;
        buf[off + 1] = @intCast((e.body.len + 2) / 8 - 1);
        @memcpy(buf[off + 2 ..][0..e.body.len], e.body);
        off += 2 + e.body.len;
    }
    @memcpy(buf[off..][0..tcp.len], tcp);
    (wire.Ip6{ .next_header = if (exts.len > 0) exts[0].kind else wire.proto_tcp, .src = hz.peer_ip6, .dst = hz.stack_ip6 }).write(buf, off - wire.ip6_header_len + tcp.len) catch unreachable;
    return buf[0 .. off + tcp.len];
}

test "ipv6: padding-only hop-by-hop / destination options are walked; the SYN is answered" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = peer6(40000);
    var buf: [512]u8 = undefined;
    h.sendRaw(withExt(&buf, &p, &.{ .{ .kind = 0, .body = &pad6 }, .{ .kind = 60, .body = &pad6 } }));
    const sa = (try h.seg(&p)) orelse return error.NoSynAck;
    try t.expect(sa.flags.syn and sa.flags.ack);
    try t.expectEqual(@as(u32, 10), sa.ack);
}

test "ipv6: malformed headers, bad extension chains and fragments are dropped silently" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var p = peer6(40000);
    var buf: [1024]u8 = undefined;
    const before = h.stats().dropped_malformed + h.stats().dropped_not_for_us;
    var sent: u64 = 0;

    // Fragment header body: offset (13 bits) | res | M, then the 32-bit id.
    const frag_first = [_]u8{ 0, 1, 0, 0, 0, 1 }; // offset 0, M=1
    const frag_later = [_]u8{ 0, 8, 0, 0, 0, 1 }; // offset 1, M=0
    const frag_atomic = [_]u8{ 0, 0, 0, 0, 0, 1 }; // offset 0, M=0 (RFC 6946 atomic)
    const routing = [_]u8{ 0, 0, 0, 0, 0, 0 };
    const chains = [_][]const Ext{
        &.{ .{ .kind = 60, .body = &pad6 }, .{ .kind = 60, .body = &pad6 }, .{ .kind = 60, .body = &pad6 }, .{ .kind = 60, .body = &pad6 }, .{ .kind = 60, .body = &pad6 } }, // 5 > max_ext_headers
        &.{.{ .kind = 0, .body = &router_alert }}, // a real hop-by-hop option
        &.{ .{ .kind = 60, .body = &pad6 }, .{ .kind = 0, .body = &pad6 } }, // hop-by-hop not first
        &.{.{ .kind = 44, .body = &frag_first }},
        &.{.{ .kind = 44, .body = &frag_later }},
        &.{.{ .kind = 44, .body = &frag_atomic }},
        &.{ .{ .kind = 0, .body = &pad6 }, .{ .kind = 44, .body = &frag_first } },
        &.{.{ .kind = 43, .body = &routing }},
        &.{.{ .kind = 51, .body = &routing }}, // AH
        &.{.{ .kind = 135, .body = &routing }}, // mobility
        &.{.{ .kind = 60, .body = &([_]u8{ 1, 5, 0, 0, 0, 0 }) }}, // PadN past the header
        &.{.{ .kind = 60, .body = &(pad6 ++ @as([256]u8, @splat(0))) }}, // past max_ext_bytes
    };
    for (chains, 0..) |chain, ci| {
        const pkt = withExt(&buf, &p, chain);
        h.sendRaw(pkt);
        sent += 1;
        h.expectSilent() catch |e| {
            std.debug.print("answered extension chain #{d}\n", .{ci});
            return e;
        };
    }
    // Fixed-header edits.
    var good_buf: [256]u8 = undefined;
    const n = goodSyn(&good_buf, &p);
    const good = good_buf[0..n];
    var b: [256]u8 = undefined;
    const edits = [_]struct { at: usize, val: u8 }{
        .{ .at = 0, .val = 0x40 }, // version 4 in a v6 packet
        .{ .at = 0, .val = 0x70 },
        .{ .at = 4, .val = 0xff }, // payload length past the packet
        .{ .at = 6, .val = 59 }, // no next header
        .{ .at = 6, .val = 50 }, // ESP
        .{ .at = 6, .val = 17 }, // UDP
        .{ .at = 6, .val = 1 }, // ICMPv4 inside IPv6
    };
    for (edits) |e| {
        @memcpy(b[0..n], good);
        b[e.at] = e.val;
        h.sendRaw(b[0..n]);
        sent += 1;
        try h.expectSilent();
    }
    // Every truncation.
    for (0..n) |k| {
        h.sendRaw(good[0..k]);
        sent += 1;
        try h.expectSilent();
    }
    // The TCP checksum covers the v6 pseudo-header: a changed address bit
    // (checksum left as is) must be caught. Only bytes 8..40 (addresses).
    for (8..40) |k| {
        @memcpy(b[0..n], good);
        b[k] ^= 0x10;
        if (k >= 24 and !std.mem.eql(u8, b[24..40], &hz.stack_ip6)) {
            // Destination no longer ours: dropped either way.
        }
        h.sendRaw(b[0..n]);
        sent += 1;
        try h.expectSilent();
    }
    const st = h.stats();
    try t.expect(st.dropped_malformed + st.dropped_not_for_us >= before + sent - 2); // counted (UDP / ICMPv4-in-v6 may count elsewhere)
    try t.expectEqual(@as(u64, 0), st.rst_sent);
    try t.expectEqual(@as(u16, 0), st.connections);
    try expectStillServes6(h, 40001);
}

test "ipv6: not our address / multicast / unspecified / v4-mapped: dropped" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    _ = try h.stack.listen(8420);
    var buf: [256]u8 = undefined;
    const others = [_][16]u8{
        .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 }, // a neighbor
        .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, // all-nodes multicast
        @splat(0), // unspecified
        .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 8, 0, 1 }, // ::ffff:10.8.0.1
        .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, // ::1
    };
    for (others) |dst| {
        var p: Peer = .{ .peer = .{ .addr = hz.peer_addr6, .port = 40000 }, .stack = .{ .addr = .{ .v6 = dst }, .port = 8420 } };
        h.sendRaw(p.packet(&buf, .{ .seq = 1, .flags = .{ .syn = true } }));
        try h.expectSilent();
    }
    // Bogus sources to our address: no SYN-ACK either (RFC 9293 3.10.7.2).
    for ([_][16]u8{ others[1], others[2], hz.stack_ip6 }) |src| {
        var p: Peer = .{ .peer = .{ .addr = .{ .v6 = src }, .port = 40000 }, .stack = .{ .addr = hz.stack_addr6, .port = 8420 } };
        h.sendRaw(p.packet(&buf, .{ .seq = 1, .flags = .{ .syn = true } }));
        if (h.out()) |_| {
            std.debug.print("SYN from bogus IPv6 source {x} answered\n", .{src});
            return error.AnsweredBogusSource;
        }
    }
    try t.expectEqual(@as(u16, 0), h.stats().connections);
}

/// An ICMPv6 message peer6 -> `dst` with a valid checksum.
fn icmp6(buf: []u8, dst: [16]u8, kind: u8, payload: []const u8) ![]u8 {
    const msg = buf[wire.ip6_header_len..][0 .. 8 + payload.len];
    msg[0] = kind;
    msg[1] = 0;
    @memset(msg[2..8], 0);
    std.mem.writeInt(u16, msg[4..6], 0x77, .big);
    std.mem.writeInt(u16, msg[6..8], 3, .big);
    @memcpy(msg[8..], payload);
    std.mem.writeInt(u16, msg[2..4], wire.icmp6Checksum(hz.peer_addr6, .{ .v6 = dst }, msg), .big);
    try (wire.Ip6{ .next_header = wire.proto_icmp6, .src = hz.peer_ip6, .dst = dst }).write(buf, msg.len);
    return buf[0 .. wire.ip6_header_len + msg.len];
}

test "ipv6: ICMPv6 echo answered (checksum by the RFC layout); other types, bad checksums, disabled: silent" {
    try needV6();
    {
        const h = try dual();
        defer h.destroy();
        var buf: [256]u8 = undefined;
        h.sendRaw(try icmp6(&buf, hz.stack_ip6, wire.icmp6_echo_request, "ping six"));
        const rep = h.out() orelse return error.NoEchoReply;
        const ip = try wire.Ip6.parse(rep);
        try t.expectEqual(wire.proto_icmp6, ip.header.next_header);
        try t.expectEqualSlices(u8, &hz.stack_ip6, &ip.header.src);
        try t.expectEqualSlices(u8, &hz.peer_ip6, &ip.header.dst);
        try t.expectEqual(@as(u16, 0), referenceSum6(ip.header.src, ip.header.dst, wire.proto_icmp6, ip.payload));
        try t.expectEqual(wire.icmp6_echo_reply, ip.payload[0]);
        try t.expectEqual(@as(u16, 0x77), std.mem.readInt(u16, ip.payload[4..6], .big));
        try t.expectEqualStrings("ping six", ip.payload[8..]);
        // Neighbor solicitation, router advertisement, an echo reply, a bad checksum: nothing.
        for ([_]u8{ 135, 134, 133, wire.icmp6_echo_reply, 1 }) |kind| {
            h.sendRaw(try icmp6(&buf, hz.stack_ip6, kind, "x"));
            try h.expectSilent();
        }
        const bad = try icmp6(&buf, hz.stack_ip6, wire.icmp6_echo_request, "y");
        bad[bad.len - 1] ^= 1;
        h.sendRaw(bad);
        try h.expectSilent();
        // Echo to multicast: not answered.
        h.sendRaw(try icmp6(&buf, .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, wire.icmp6_echo_request, "z"));
        try h.expectSilent();
    }
    {
        var limits: ns.Limits = .{};
        _ = &limits;
        const h = try H.create(gpa, .{ .address6 = hz.stack_addr6, .icmp_echo = false });
        defer h.destroy();
        var buf: [256]u8 = undefined;
        h.sendRaw(try icmp6(&buf, hz.stack_ip6, wire.icmp6_echo_request, "x"));
        try h.expectSilent();
    }
}

test "ipv6: mutation sweep (valid SYN / data, edited and re-checksummed): no panic, only valid output" {
    try needV6();
    const h = try dual();
    defer h.destroy();
    const l = try h.stack.listen(8420);
    var c = try hz.openPassive(h, l, .{ .peer_addr = hz.peer_addr6, .stack_addr = hz.stack_addr6 });
    defer c.stream.abort();
    var prng: std.Random.DefaultPrng = .init(0x6666);
    const r = prng.random();
    var buf: [1600]u8 = undefined;
    var payload: [600]u8 = undefined;
    for (0..20_000) |i| {
        const len = r.uintAtMost(usize, payload.len);
        r.bytes(payload[0..len]);
        const pkt = c.peer.packet(&buf, .{
            .seq = if (r.boolean()) c.snd_nxt else r.int(u32),
            .ack = if (r.boolean()) c.rcv_nxt else r.int(u32),
            .flags = @bitCast(r.int(u8)),
            .window = r.int(u16),
            .payload = payload[0..len],
        });
        var n = pkt.len;
        for (0..r.uintAtMost(usize, 4)) |_| {
            switch (r.uintLessThan(u8, 3)) {
                0 => pkt[r.uintLessThan(usize, n)] ^= @as(u8, 1) << r.int(u3),
                1 => pkt[r.uintLessThan(usize, n)] = r.int(u8),
                else => n = r.uintAtMost(usize, n),
            }
            if (n == 0) break;
        }
        // Half the time fix the payload length and TCP checksum so the
        // edit reaches the TCP layer.
        if (n >= 60 and r.boolean()) {
            std.mem.writeInt(u16, pkt[4..6], @intCast(n - 40), .big);
            if (pkt[6] == wire.proto_tcp) {
                @memset(pkt[56..58], 0);
                std.mem.writeInt(u16, pkt[56..58], referenceSum6(pkt[8..24].*, pkt[24..40].*, wire.proto_tcp, pkt[40..n]), .big);
            }
        }
        h.sendRaw(pkt[0..n]);
        while (h.out()) |o| {
            const ip = try wire.parseIp(o);
            try t.expect(ip.src.eql(hz.stack_addr6) or ip.src.eql(hz.stack_addr));
        }
        if (i % 1000 == 0) h.advance(r.uintAtMost(u64, 2 * sec));
        try t.expect(h.stats().connections <= 64);
    }
}