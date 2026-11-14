//! Fuzz targets for the netstack (see src/fuzz.zig for how to run them
//! with real coverage-guided fuzzing; without `--fuzz` each runs once per
//! corpus entry as an ordinary test).
//!
//!   * wire parsers: any bytes; whatever parses must re-serialize to a
//!     packet that parses to the same fields (round trip).
//!   * stack input: a stack with a listener fed a fuzzed sequence of
//!     crafted-then-mutated segments, ICMP and junk, with fuzzed time
//!     steps; everything the stack sends must be a well-formed packet from
//!     its own address, and the connection table stays within its limits.
const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const shared = @import("../fuzz.zig");
const root = @import("root.zig");
const wire = @import("wire.zig");

const stack_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 1 } };
const peer_addr: root.Addr = .{ .v4 = .{ 10, 8, 0, 2 } };

fn fuzzWire(_: void, s: *Smith) anyerror!void {
    var buf: [1600]u8 = undefined;
    const n = s.slice(&buf);
    const pkt = buf[0..n];
    _ = wire.icmp4Type(pkt) catch {};
    _ = wire.TcpOptions.parse(pkt[0..@min(pkt.len, wire.tcp_max_options_len)]) catch {};
    _ = wire.Tcp.parse(peer_addr, stack_addr, pkt) catch {};
    const p = wire.parseTcp4(pkt) catch return;
    // Round trip: rebuild from the parsed fields, parse again, compare.
    var out: [1600]u8 = undefined;
    const again_bytes = wire.buildTcp4(&out, p.ip.header, p.tcp) catch return;
    const again = try wire.parseTcp4(again_bytes);
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
    try testing.expectEqualSlices(u8, a.payload, b.payload);
    try testing.expectEqual(p.ip.header.src, again.ip.header.src);
    try testing.expectEqual(p.ip.header.dst, again.ip.header.dst);
}

test "fuzz: netstack wire parsers (round trip)" {
    var syn: [64]u8 = undefined;
    const p = try wire.buildTcp4(&syn, .{ .protocol = wire.proto_tcp, .src = peer_addr.v4, .dst = stack_addr.v4 }, .{
        .src_port = 40000,
        .dst_port = 8420,
        .seq = 1,
        .flags = .{ .syn = true },
        .window = 65535,
        .options = .{ .mss = 1380, .window_scale = 7, .sack_permitted = true },
    });
    var corpus_buf: [4 + 64]u8 = undefined;
    std.mem.writeInt(u32, corpus_buf[0..4], @intCast(p.len), .little);
    @memcpy(corpus_buf[4..][0..p.len], p);
    try testing.fuzz({}, fuzzWire, .{ .corpus = &.{corpus_buf[0 .. 4 + p.len]} });
}

fn fuzzInput(_: void, s: *Smith) anyerror!void {
    var clock: root.Clock = .{ .io = testing.io };
    const limits: root.Limits = .{ .max_connections = 4, .syn_backlog = 2, .accept_backlog = 2, .recv_buffer = 4096, .send_buffer = 4096, .max_ooo_segments = 4 };
    const stack = try root.Stack.create(testing.allocator, &clock, .{ .address = stack_addr, .limits = limits });
    defer stack.destroy();
    const l = try stack.listen(8420);
    var peer: root.testing.Peer = .{ .peer = .{ .addr = peer_addr, .port = 40000 }, .stack = .{ .addr = stack_addr, .port = 8420 } };
    var buf: [1600]u8 = undefined;
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
                peer.peer.port = 40000 + s.valueRangeAtMost(u16, 0, 5);
                var flags: wire.Flags = @bitCast(s.value(u8));
                if (s.boolWeighted(1, 1)) flags = .{ .ack = true };
                const len = s.valueRangeAtMost(u16, 0, payload.len);
                const pkt = peer.packet(&buf, .{
                    .seq = if (s.boolWeighted(3, 1)) seq else s.value(u32),
                    .ack = if (s.boolWeighted(3, 1)) ack else s.value(u32),
                    .flags = flags,
                    .window = s.value(u16),
                    .options = .{
                        .mss = if (s.boolWeighted(1, 3)) s.value(u16) else null,
                        .window_scale = if (s.boolWeighted(1, 3)) s.value(u8) else null,
                    },
                    .payload = payload[0..len],
                });
                const n = shared.mutate(s, pkt, pkt.len);
                stack.input(buf[0..n]);
                if (flags.syn) seq +%= 1;
                seq +%= len;
            },
            6 => {
                const n = s.slice(&buf);
                stack.input(buf[0..n]);
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
                _ = stack.dial(.{ .addr = peer_addr, .port = 9000 + s.valueRangeAtMost(u16, 0, 3) }) catch {};
            },
        }
        // Drain and check everything the stack sends.
        var sent: usize = 0;
        while (stack.output(&out)) |p| : (sent += 1) {
            try testing.expect(sent < 10_000);
            const ip = try wire.Ip4.parse(p);
            try testing.expectEqual(stack_addr.v4, ip.header.src);
            try testing.expectEqual(peer_addr.v4, ip.header.dst);
            switch (ip.header.protocol) {
                wire.proto_tcp => {
                    const tcp = try wire.Tcp.parse(.{ .v4 = ip.header.src }, .{ .v4 = ip.header.dst }, ip.payload);
                    try testing.expect(p.len <= stack.options.mtu);
                    if (tcp.flags.ack) ack = tcp.seq +% tcp.segLen();
                },
                wire.proto_icmp => _ = try wire.icmp4Type(ip.payload),
                else => return error.UnexpectedProtocol,
            }
        }
        try testing.expect(stack.stats().connections <= limits.max_connections);
    }
    for (accepted) |a| if (a) |st| st.abort();
}

test "fuzz: netstack input (segments, junk, time, host calls)" {
    try testing.fuzz({}, fuzzInput, .{ .corpus = &.{
        shared.sliceInput(""),
        &[_]u8{ 0, 0, 0, 0, 0, 2, 0, 0x12, 0, 0, 1, 2, 3, 4, 8, 8, 8, 8, 7, 7, 7, 7 },
    } });
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
        fuzzInput({}, &s) catch |e| {
            std.debug.print("fuzzInput failed on random input #{d}\n", .{i});
            return e;
        };
    }
}