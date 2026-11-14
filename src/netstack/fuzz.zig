//! Fuzz targets for the netstack (see src/fuzz.zig for how to run them
//! with real coverage-guided fuzzing; without `--fuzz` each runs once per
//! corpus entry as an ordinary test).
//!
//!   * wire parsers: any bytes, IPv4 or IPv6 (extension headers
//!     included); whatever parses must re-serialize to a packet that
//!     parses to the same fields (round trip).
//!   * stack input: a stack with a listener fed a fuzzed sequence of
//!     crafted-then-mutated segments (IPv6 ones sometimes behind fuzzed
//!     extension-header chains), ICMP / ICMPv6 echo and junk, with fuzzed
//!     time steps; everything the stack sends must be a well-formed packet
//!     from its own address of the destination's family to a peer, and
//!     the connection table stays within its limits. Run IPv4-only and
//!     dual-stack (peers on both families).
const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const shared = @import("../fuzz.zig");
const root = @import("root.zig");
const wire = @import("wire.zig");

const stack_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 1 } };
const peer_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 2 } };
const stack_addr6: root.Addr = .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
const peer_addr6: root.Addr = .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } };

fn fuzzWire(_: void, s: *Smith) anyerror!void {
    var buf: [1600]u8 = undefined;
    const n = s.slice(&buf);
    const pkt = buf[0..n];
    _ = wire.icmp4Type(pkt) catch {};
    _ = wire.icmp6Type(peer_addr6, stack_addr6, pkt) catch {};
    _ = wire.TcpOptions.parse(pkt[0..@min(pkt.len, wire.tcp_max_options_len)]) catch {};
    _ = wire.Tcp.parse(peer_addr, stack_addr, pkt) catch {};
    _ = wire.Tcp.parse(peer_addr6, stack_addr6, pkt) catch {};
    _ = wire.parseIp(pkt) catch {};
    const p = wire.parseTcp(pkt) catch return;
    // Round trip: rebuild from the parsed fields (no IPv4 options, no IPv6
    // extension headers), parse again, compare.
    var out: [1600]u8 = undefined;
    const again_bytes = wire.buildTcp(&out, p.ip.src, p.ip.dst, 0, p.tcp) catch return;
    const again = try wire.parseTcp(again_bytes);
    const a = p.tcp;
    const b = again.tcp;
    try testing.expectEqual(a.src_port, b.src_port);
    try testing.expectEqual(a.dst_port, b.dst_port);
    try testing.expectEqual(a.seq, b.seq);
    try testing.expectEqual(a.ack, b.ack);
    try testing.expectEqual(a.flags, b.flags);
    try testing.expectEqual(a.window, b.window);
    try testing.expectEqual(a.options.mss, b.options.mss);
    try testing.expectEqual(a.options.window_scale, b.options.window_scale);
    try testing.expectEqual(a.options.sack_permitted, b.options.sack_permitted);
    try testing.expectEqual(a.options.timestamp, b.options.timestamp);
    try testing.expectEqual(a.options.sack == null, b.options.sack == null);
    if (a.options.sack) |sa| try testing.expectEqualSlices(wire.SackBlock, sa.slice(), b.options.sack.?.slice());
    try testing.expectEqualSlices(u8, a.payload, b.payload);
    try testing.expectEqual(p.ip.src, again.ip.src);
    try testing.expectEqual(p.ip.dst, again.ip.dst);
    try testing.expectEqual(p.ip.protocol, again.ip.protocol);
}

/// Seeds for the wire target: a SYN over IPv4, the same over IPv6 behind
/// hop-by-hop + destination options, and an ICMPv6 echo request.
fn wireSeeds(storage: *[3][4 + 256]u8) [3][]const u8 {
    var seeds: [3][]const u8 = undefined;
    var tmp: [256]u8 = undefined;
    var peer4: root.testing.Peer = .{ .peer = .{ .addr = peer_addr, .port = 40000 }, .stack = .{ .addr = stack_addr, .port = 8420 } };
    var peer6: root.testing.Peer = .{ .peer = .{ .addr = peer_addr6, .port = 40000 }, .stack = .{ .addr = stack_addr6, .port = 8420 } };
    const syn: root.testing.Peer.Seg = .{ .seq = 1, .flags = .{ .syn = true }, .options = .{ .mss = 1380, .window_scale = 7, .sack_permitted = true } };
    const lens = [3]usize{
        peer4.packet(storage[0][4..], syn).len,
        root.testing.withExtHeaders6(storage[1][4..], peer6.packet(&tmp, syn), &.{ 0, 60 }).len,
        root.testing.icmpPacket(storage[2][4..], peer_addr6, stack_addr6, wire.icmp6_echo_request, "ping").len,
    };
    for (lens, 0..) |len, i| {
        std.mem.writeInt(u32, storage[i][0..4], @intCast(len), .little);
        seeds[i] = storage[i][0 .. 4 + len];
    }
    return seeds;
}

test "fuzz: netstack wire parsers (round trip)" {
    var storage: [3][4 + 256]u8 = undefined;
    const seeds = wireSeeds(&storage);
    try testing.fuzz({}, fuzzWire, .{ .corpus = &seeds });
}

/// SACK blocks near `ack` (often plausible, sometimes hostile: reversed,
/// huge, overlapping, outside anything sent).
fn drawSack(s: *Smith, ack: u32) wire.Sack {
    var sk: wire.Sack = .{ .len = s.valueRangeAtMost(u8, 1, wire.max_sack_blocks) };
    for (sk.blocks[0..sk.len]) |*b| {
        // Often near the ACK (plausible SACK), sometimes just below it (a
        // D-SACK shape), sometimes anywhere.
        const start = switch (s.valueRangeAtMost(u8, 0, 3)) {
            0, 1 => ack +% s.valueRangeAtMost(u32, 0, 20_000),
            2 => ack -% s.valueRangeAtMost(u32, 1, 70_000),
            else => s.value(u32),
        };
        b.* = .{ .start = start, .end = if (s.boolWeighted(3, 1)) start +% s.valueRangeAtMost(u32, 0, 3000) else s.value(u32) };
    }
    return sk;
}

/// The input target's stack addresses and the peers it is fed from.
const InputCase = struct {
    address: root.Addr,
    address6: ?root.Addr = null,
    /// Each of a family the stack has; a step picks one.
    peers: []const root.Addr,

    /// The stack's own address for `a`'s family.
    fn ours(c: InputCase, a: root.Addr) root.Addr {
        return if (a == .v6) c.address6 orelse c.address else c.address;
    }
};

const case_v4: InputCase = .{ .address = stack_addr, .peers = &.{peer_addr} };
const case_dual: InputCase = .{ .address = stack_addr, .address6 = stack_addr6, .peers = &.{ peer_addr6, peer_addr } };

/// IPv6 extension-header kinds the input target chains in front of its
/// segments: mostly accepted padding headers, some that must be dropped.
const ext_kinds = [_]u8{ 0, 60, 60, 60, 44, 43, 51, 59 };

fn fuzzInput(case: InputCase, s: *Smith) anyerror!void {
    var clock: root.Clock = .{ .io = testing.io };
    const limits: root.Limits = .{ .max_connections = 4, .syn_backlog = 2, .accept_backlog = 2, .recv_buffer = 4096, .send_buffer = 4096, .max_ooo_segments = 4 };
    const stack = try root.Stack.create(testing.allocator, &clock, .{ .address = case.address, .address6 = case.address6, .limits = limits });
    defer stack.destroy();
    const l = try stack.listen(8420);
    var peer: root.testing.Peer = .{ .peer = .{ .addr = case.peers[0], .port = 40000 }, .stack = .{ .addr = case.ours(case.peers[0]), .port = 8420 } };
    var buf: [1600]u8 = undefined;
    var tmp: [1600]u8 = undefined;
    var out: [1600]u8 = undefined;
    var accepted: [4]?root.Stream = @splat(null);
    var payload: [600]u8 = undefined;
    @memset(&payload, 0x5a);
    // A plausible sequence space so that fuzzed segments often land in
    // the window instead of always being rejected.
    var seq: u32 = s.value(u32);
    var ack: u32 = 0;

    var steps: usize = 0;
    while (steps < 64 and !s.eos()) : (steps += 1) {
        switch (s.valueRangeAtMost(u8, 0, 9)) {
            0...5 => {
                if (case.peers.len > 1) {
                    peer.peer.addr = case.peers[s.index(case.peers.len)];
                    peer.stack.addr = case.ours(peer.peer.addr);
                }
                peer.peer.port = 40000 + s.valueRangeAtMost(u16, 0, 5);
                var flags: wire.Flags = @bitCast(s.value(u8));
                if (s.boolWeighted(1, 1)) flags = .{ .ack = true };
                const len = s.valueRangeAtMost(u16, 0, payload.len);
                var pkt = peer.packet(&buf, .{
                    .seq = if (s.boolWeighted(3, 1)) seq else s.value(u32),
                    .ack = if (s.boolWeighted(3, 1)) ack else s.value(u32),
                    .flags = flags,
                    .window = s.value(u16),
                    .options = .{
                        .mss = if (s.boolWeighted(1, 3)) s.value(u16) else null,
                        .window_scale = if (s.boolWeighted(1, 3)) s.value(u8) else null,
                        .sack_permitted = s.boolWeighted(1, 1),
                        .sack = if (s.boolWeighted(1, 1)) drawSack(s, ack) else null,
                    },
                    .payload = payload[0..len],
                });
                if (peer.peer.addr == .v6 and s.boolWeighted(1, 3)) {
                    var kinds: [wire.max_ext_headers + 1]u8 = undefined;
                    const nk: usize = s.valueRangeAtMost(u8, 1, kinds.len);
                    for (kinds[0..nk]) |*k| k.* = ext_kinds[s.index(ext_kinds.len)];
                    @memcpy(tmp[0..pkt.len], pkt);
                    pkt = root.testing.withExtHeaders6(&buf, tmp[0..pkt.len], kinds[0..nk]);
                }
                const n = shared.mutate(s, pkt, pkt.len);
                stack.input(buf[0..n]);
                if (flags.syn) seq +%= 1;
                seq +%= len;
            },
            6 => if (s.boolWeighted(1, 1)) {
                const n = s.slice(&buf);
                stack.input(buf[0..n]);
            } else {
                // An echo request (ICMPv4 or ICMPv6 by the peer), mutated.
                const pa = case.peers[s.index(case.peers.len)];
                const kind = if (pa == .v6) wire.icmp6_echo_request else wire.icmp_echo_request;
                const pkt = root.testing.icmpPacket(&buf, pa, case.ours(pa), kind, payload[0..s.valueRangeAtMost(u16, 0, 64)]);
                stack.input(buf[0..shared.mutate(s, pkt, pkt.len)]);
            },
            7 => {
                // Advance time (fires retransmissions, TIME-WAIT, ...).
                clock.advance(@as(i64, s.valueRangeAtMost(u32, 0, 5_000)) * std.time.ns_per_ms);
                _ = stack.runTimers();
            },
            8 => {
                // Host side: accept, read, write, close / abort.
                if (l.accept()) |st| {
                    for (&accepted) |*a| if (a.* == null) {
                        a.* = st;
                        break;
                    } else st.abort();
                } else |_| {}
                for (&accepted) |*a| if (a.*) |st| {
                    var rb: [256]u8 = undefined;
                    _ = st.read(&rb) catch {};
                    _ = st.write(payload[0..s.valueRangeAtMost(u16, 0, 300)]) catch {};
                    if (s.boolWeighted(1, 4)) {
                        if (s.boolWeighted(1, 1)) st.close() else st.abort();
                        a.* = null;
                    }
                };
            },
            else => {
                const pa = case.peers[s.index(case.peers.len)];
                _ = stack.dial(.{ .addr = pa, .port = 9000 + s.valueRangeAtMost(u16, 0, 3) }) catch {};
            },
        }
        // Drain and check everything the stack sends.
        var sent: usize = 0;
        while (stack.output(&out)) |p| : (sent += 1) {
            try testing.expect(sent < 10_000);
            try testing.expect(p.len <= stack.options.mtu);
            const ip = try wire.parseIp(p);
            try testing.expectEqual(case.ours(ip.dst), ip.src);
            for (case.peers) |pa| {
                if (pa.eql(ip.dst)) break;
            } else return error.SentToAStranger;
            switch (ip.protocol) {
                wire.proto_tcp => {
                    const tcp = try wire.Tcp.parse(ip.src, ip.dst, ip.payload);
                    if (tcp.flags.ack) ack = tcp.seq +% tcp.segLen();
                },
                wire.proto_icmp => {
                    try testing.expect(ip.dst == .v4);
                    try testing.expectEqual(wire.icmp_echo_reply, try wire.icmp4Type(ip.payload));
                },
                wire.proto_icmp6 => {
                    try testing.expect(ip.dst == .v6);
                    try testing.expectEqual(wire.icmp6_echo_reply, try wire.icmp6Type(ip.src, ip.dst, ip.payload));
                },
                else => return error.UnexpectedProtocol,
            }
        }
        try testing.expect(stack.stats().connections <= limits.max_connections);
    }
    for (accepted) |a| if (a) |st| st.abort();
}

const input_corpus = [_][]const u8{
    shared.sliceInput(""),
    &[_]u8{ 0, 0, 0, 0, 0, 2, 0, 0x12, 0, 0, 1, 2, 3, 4, 8, 8, 8, 8, 7, 7, 7, 7 },
};

test "fuzz: netstack input (segments, junk, time, host calls)" {
    try testing.fuzz(case_v4, fuzzInput, .{ .corpus = &input_corpus });
}

test "fuzz: netstack input, dual-stack (IPv6 and IPv4 peers, extension headers, ICMPv6)" {
    try testing.fuzz(case_dual, fuzzInput, .{ .corpus = &input_corpus });
}

// Windows has no `--fuzz` in this Zig version: drive both targets with
// seeded random inputs too, so `zig build test` exercises them broadly on
// every host (a failing seed is printed and reproduces exactly).
test "netstack fuzz targets: seeded random inputs" {
    var prng = std.Random.DefaultPrng.init(0x6e6574737461636b);
    var bytes: [4096]u8 = undefined;
    for (0..3000) |i| {
        const n = prng.random().uintAtMost(usize, bytes.len);
        prng.random().bytes(bytes[0..n]);
        var s: Smith = .{ .in = bytes[0..n] };
        fuzzWire({}, &s) catch |e| {
            std.debug.print("fuzzWire failed on random input #{d}\n", .{i});
            return e;
        };
    }
    for (0..400) |i| {
        const n = prng.random().uintAtMost(usize, bytes.len);
        prng.random().bytes(bytes[0..n]);
        var s: Smith = .{ .in = bytes[0..n] };
        fuzzInput(if (i % 2 == 0) case_v4 else case_dual, &s) catch |e| {
            std.debug.print("fuzzInput failed on random input #{d}\n", .{i});
            return e;
        };
    }
    // Mutations of valid packets (random bytes almost never get past an
    // IPv6 header and a TCP checksum): reach the extension-header walk and
    // the TCP / ICMPv6 parsers on either family.
    var storage: [3][4 + 256]u8 = undefined;
    const seeds = wireSeeds(&storage);
    for (0..3000) |i| {
        const seed = seeds[i % seeds.len];
        @memcpy(bytes[0..seed.len], seed);
        const k = prng.random().uintAtMost(usize, 4);
        for (0..k) |_| bytes[4 + prng.random().uintLessThan(usize, seed.len - 4)] = prng.random().int(u8);
        var s: Smith = .{ .in = bytes[0..seed.len] };
        fuzzWire({}, &s) catch |e| {
            std.debug.print("fuzzWire failed on mutated seed #{d}\n", .{i});
            return e;
        };
    }
}