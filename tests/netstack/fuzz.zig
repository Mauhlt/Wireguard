//! Fuzz target: random bytes and crafted / mutated segments into
//! Stack.input, interleaved with host calls and clock jumps. Invariants
//! after every step: no panic; every packet the stack sends is a valid,
//! checksummed IPv4 packet from its address within the MTU; buffers and
//! connection counts within Limits; bytes read are exactly what the peer
//! sent at those sequence numbers, and bytes sent are exactly what the
//! host wrote at those offsets (no corruption, no reordering).
//!
//! `zig build fuzz-netstack --fuzz` (Linux / macOS) fuzzes it; on Windows
//! (no --fuzz in this Zig) the corpus runs once and a seeded random sweep
//! feeds a few hundred random inputs.
const std = @import("std");
const t = std.testing;
const Smith = t.Smith;
const hz = @import("harness.zig");
const ns = hz.ns;
const wire = hz.wire;
const H = hz.H;
const Peer = hz.Peer;

const ports = [_]u16{ 40000, 40001, 40002, 40003 };
const listen_port: u16 = 8420;
const write_seed: u32 = 0xa5a5_0000;

fn isnFor(pi: usize) u32 {
    return @as(u32, ports[pi]) *% 2654435761;
}

/// The byte the fuzz peer sends at sequence number `seq` on port index `pi`.
fn peerByte(pi: usize, seq: u32) u8 {
    return hz.patternByte(ports[pi], seq);
}

/// How deep the inputs got (printed by the sweep, to see it is not all
/// rejected at the parser).
var reach: struct { accepted: u64 = 0, read_bytes: u64 = 0, sent_bytes: u64 = 0, established: u64 = 0 } = .{};

const Held = struct {
    st: ns.Stream,
    /// Index into `ports`, or null for a dialed stream.
    pi: ?usize,
    read_off: u64 = 0,
    write_off: u64 = 0,
};

const Model = struct {
    h: *H,
    peers: [ports.len]Peer,
    /// Peer's next sequence number, steered by the stack's ACKs.
    peer_nxt: [ports.len]u32,
    /// What the peer ACKs: the stack's highest sequence seen + 1.
    ack_hint: [ports.len]u32 = @splat(0),
    /// The stack's ISS per port (from its SYN-ACK).
    iss: [ports.len]?u32 = @splat(null),
    /// A checksum-fixed mutated packet went to this port: the peer's
    /// sequence space may have been redefined, skip read integrity there.
    tainted: [ports.len]bool = @splat(false),
    held: [8]?Held = @splat(null),
    listener: ns.Listener,
    pkt: [1600]u8 = undefined,
    payload: [1400]u8 = undefined,
};

fn limits() ns.Limits {
    var l: ns.Limits = .{};
    l.max_connections = 6;
    l.max_listeners = 2;
    l.send_buffer = 16 * 1024;
    l.recv_buffer = 16 * 1024;
    l.syn_backlog = 3;
    l.accept_backlog = 2;
    l.max_ooo_segments = 4;
    l.ring_packets = 32;
    l.user_timeout_ns = 30 * hz.sec;
    l.bulk_unsent_lowat = 8 * 1024;
    return l;
}

fn checkOutput(m: *Model) !void {
    const lim = limits();
    var n: usize = 0;
    while (m.h.out()) |pkt| {
        n += 1;
        if (n > 4096) return error.OutputStorm;
        const ip = try wire.Ip4.parse(pkt);
        try t.expectEqualSlices(u8, &hz.stack_ip, &ip.header.src);
        try t.expectEqual(pkt.len, ip.header_len + ip.payload.len);
        switch (ip.header.protocol) {
            wire.proto_icmp => _ = try wire.icmp4Type(ip.payload),
            wire.proto_tcp => {
                const tcp = (try wire.parseTcp4(pkt)).tcp;
                try t.expect(tcp.payload.len <= wire.mssForMtu(m.h.cfg.mtu));
                if (tcp.src_port != listen_port) continue;
                const pi = std.mem.indexOfScalar(u16, &ports, tcp.dst_port) orelse continue;
                if (!std.mem.eql(u8, &ip.header.dst, &hz.peer_ip)) continue;
                if (tcp.flags.syn) m.iss[pi] = tcp.seq;
                const end = tcp.seq +% tcp.segLen();
                if (hz.seqLt(m.ack_hint[pi], end) or tcp.flags.syn) m.ack_hint[pi] = end;
                if (tcp.flags.ack and !tcp.flags.rst) m.peer_nxt[pi] = tcp.ack;
                if (tcp.payload.len != 0) reach.sent_bytes += tcp.payload.len;
                if (tcp.payload.len != 0) if (m.iss[pi]) |iss| {
                    // Bytes sent are the host's bytes at those offsets.
                    const off: u32 = tcp.seq -% (iss +% 1);
                    for (tcp.payload, 0..) |b, i| {
                        const want = hz.patternByte(write_seed ^ ports[pi], @as(u32, off +% @as(u32, @intCast(i))));
                        if (b != want) return error.SentCorruptData;
                    }
                };
            },
            else => return error.UnexpectedProtocol,
        }
    }
    try t.expect(m.h.stats().connections <= lim.max_connections);
    for (&m.held) |*slot| if (slot.*) |*hd| {
        const s = hd.st.status();
        try t.expect(s.read_available <= lim.recv_buffer);
        try t.expect(s.write_available <= lim.send_buffer);
    };
}

fn craft(m: *Model, s: *Src, pi: usize) []u8 {
    const p = &m.peers[pi];
    var flags: wire.Flags = @bitCast(s.value(u8));
    if (s.boolWeighted(1, 3)) {
        flags = .{ .ack = true, .psh = s.value(bool), .fin = s.boolWeighted(15, 1) };
    } else if (s.boolWeighted(2, 1)) {
        flags = .{ .syn = true };
    }
    const seq: u32 = switch (s.valueRangeAtMost(u8, 0, 4)) {
        0 => isnFor(pi),
        1, 2 => m.peer_nxt[pi],
        3 => m.peer_nxt[pi] +% @as(u32, s.valueRangeAtMost(u16, 0, 20000)) -% 10000,
        else => s.value(u32),
    };
    // Every SYN uses the port's ISN, so the peer's sequence space (and so
    // the byte at each offset) is fixed per port.
    const seq_final = if (flags.syn) isnFor(pi) else seq;
    const ack: u32 = switch (s.valueRangeAtMost(u8, 0, 3)) {
        0, 1 => m.ack_hint[pi],
        2 => m.ack_hint[pi] +% @as(u32, s.valueRangeAtMost(u16, 0, 4000)) -% 2000,
        else => s.value(u32),
    };
    var opts: wire.TcpOptions = .{};
    if (s.boolWeighted(1, 1)) opts.mss = if (s.value(bool)) 1380 else s.value(u16);
    if (s.boolWeighted(2, 1)) opts.window_scale = s.valueRangeAtMost(u8, 0, 20);
    opts.sack_permitted = s.boolWeighted(1, 1);
    if (s.boolWeighted(4, 1)) opts.timestamp = .{ s.value(u32), s.value(u32) };
    // SACK / D-SACK blocks: near the stack's sequence space (valid, stale,
    // overlapping, inverted) or anywhere.
    if (comptime @hasField(wire.TcpOptions, "sack")) if (s.boolWeighted(2, 1)) {
        var sk: wire.Sack = .{ .len = s.valueRangeAtMost(u8, 1, wire.max_sack_blocks) };
        for (sk.blocks[0..sk.len]) |*b| {
            const anchor = m.ack_hint[pi];
            b.start = if (s.boolWeighted(1, 3)) s.value(u32) else anchor +% @as(u32, s.valueRangeAtMost(u16, 0, 60000)) -% 30000;
            b.end = if (s.boolWeighted(1, 6)) s.value(u32) else b.start +% s.valueRangeAtMost(u16, 0, 9000);
        }
        opts.sack = sk;
        // Fit the 40-byte option space.
        while (opts.len() > wire.tcp_max_options_len) {
            if (opts.timestamp != null) {
                opts.timestamp = null;
            } else if (opts.sack.?.len > 1) {
                opts.sack.?.len -= 1;
            } else break;
        }
    };
    const len: usize = if (s.boolWeighted(1, 1)) 0 else s.valueRangeAtMost(u16, 1, 1380);
    for (m.payload[0..len], 0..) |*b, i| b.* = peerByte(pi, seq_final +% @as(u32, @intCast(i)));
    return p.packet(&m.pkt, .{
        .seq = seq_final,
        .ack = ack,
        .flags = flags,
        .window = if (s.boolWeighted(1, 6)) s.value(u16) else 65535,
        .options = opts,
        .payload = m.payload[0..len],
    });
}

fn mutate(s: *Src, buf: []u8) usize {
    var n = buf.len;
    var edits: usize = 0;
    while (edits < 4 and s.boolWeighted(1, 3)) : (edits += 1) {
        switch (s.valueRangeAtMost(u8, 0, 2)) {
            0 => if (n != 0) {
                buf[s.index(n)] ^= @as(u8, 1) << s.value(u3);
            },
            1 => if (n != 0) {
                buf[s.index(n)] = s.value(u8);
            },
            else => n = s.index(n + 1),
        }
    }
    return n;
}

fn fixChecksums(pkt: []u8) void {
    if (pkt.len < 40) return;
    pkt[0] = 0x45;
    std.mem.writeInt(u16, pkt[2..4], @intCast(pkt.len), .big);
    @memset(pkt[10..12], 0);
    std.mem.writeInt(u16, pkt[10..12], wire.checksum(pkt[0..20]), .big);
    const seg = pkt[20..];
    @memset(seg[16..18], 0);
    var c = wire.pseudoHeader(.{ .v4 = pkt[12..16].* }, .{ .v4 = pkt[16..20].* }, wire.proto_tcp, @intCast(seg.len));
    c.add(seg);
    std.mem.writeInt(u16, seg[16..18], c.final(), .big);
}

fn freeSlot(m: *Model) ?*?Held {
    for (&m.held) |*slot| if (slot.* == null) return slot;
    return null;
}

fn pickHeld(m: *Model, s: *Src) ?*?Held {
    const i = s.index(m.held.len);
    return if (m.held[i] != null) &m.held[i] else null;
}

fn step(m: *Model, s: *Src) !void {
    const pi = s.index(ports.len);
    switch (s.valueRangeAtMost(u8, 0, 13)) {
        12, 13 => {
            // A whole handshake (and maybe data), to get deep quickly.
            m.peer_nxt[pi] = isnFor(pi);
            m.h.send(&m.peers[pi], .{ .seq = isnFor(pi), .flags = .{ .syn = true }, .options = .{ .mss = 1380 } });
            try checkOutput(m);
            m.h.send(&m.peers[pi], .{ .seq = isnFor(pi) +% 1, .ack = m.ack_hint[pi], .flags = .{ .ack = true } });
            if (s.value(bool)) {
                const nxt = isnFor(pi) +% 1;
                const len = s.valueRangeAtMost(u16, 1, 1380);
                for (m.payload[0..len], 0..) |*b, i| b.* = peerByte(pi, nxt +% @as(u32, @intCast(i)));
                m.h.send(&m.peers[pi], .{ .seq = nxt, .ack = m.ack_hint[pi], .flags = .{ .ack = true, .psh = true }, .payload = m.payload[0..len] });
            }
        },
        0 => {
            const n = s.slice(&m.pkt);
            m.h.sendRaw(m.pkt[0..n]);
        },
        1, 2, 3 => m.h.sendRaw(craft(m, s, pi)),
        4 => {
            const pkt = craft(m, s, pi);
            m.h.sendRaw(pkt[0..mutate(s, pkt)]);
        },
        5 => {
            const pkt = craft(m, s, pi);
            const n = mutate(s, pkt);
            fixChecksums(pkt[0..n]);
            m.tainted[pi] = true;
            m.h.sendRaw(pkt[0..n]);
        },
        6 => {
            const d: u64 = switch (s.valueRangeAtMost(u8, 0, 3)) {
                0 => s.valueRangeAtMost(u64, 0, 10 * hz.ms),
                1 => s.valueRangeAtMost(u64, 0, 1 * hz.sec),
                2 => m.h.nextDeadline() orelse 0,
                else => s.valueRangeAtMost(u64, 0, 120 * hz.sec),
            };
            m.h.advance(d);
        },
        7 => if (freeSlot(m)) |slot| {
            if (m.listener.accept()) |st| {
                slot.* = .{ .st = st, .pi = std.mem.indexOfScalar(u16, &ports, st.remote().port) };
                reach.accepted += 1;
            } else |_| {}
        },
        8 => if (pickHeld(m, s)) |slot| {
            const hd = &slot.*.?;
            var buf: [4096]u8 = undefined;
            const want = @as(usize, s.valueRangeAtMost(u16, 1, @intCast(buf.len)));
            const n = hd.st.read(buf[0..want]) catch 0;
            if (hd.pi) |p| if (!m.tainted[p]) {
                for (buf[0..n], 0..) |b, i| {
                    const seq = isnFor(p) +% 1 +% @as(u32, @truncate(hd.read_off + i));
                    if (b != peerByte(p, seq)) return error.ReadCorruptData;
                }
            };
            hd.read_off += n;
            reach.read_bytes += n;
        },
        9 => if (pickHeld(m, s)) |slot| {
            const hd = &slot.*.?;
            var buf: [8192]u8 = undefined;
            const want = @as(usize, s.valueRangeAtMost(u16, 1, @intCast(buf.len)));
            const p = hd.pi orelse 0;
            for (buf[0..want], 0..) |*b, i| b.* = hz.patternByte(write_seed ^ ports[p], @as(u32, @truncate(hd.write_off + i)));
            const n = hd.st.write(buf[0..want]) catch 0;
            if (hd.pi != null) hd.write_off += n;
        },
        10 => if (pickHeld(m, s)) |slot| {
            const hd = slot.*.?;
            switch (s.valueRangeAtMost(u8, 0, 2)) {
                0 => hd.st.shutdown(),
                1 => {
                    hd.st.close();
                    slot.* = null;
                },
                else => {
                    hd.st.abort();
                    slot.* = null;
                },
            }
        },
        else => if (freeSlot(m)) |slot| {
            const prio: ns.Priority = if (s.value(bool)) .bulk else .interactive;
            if (m.h.stack.dialWith(.{ .addr = hz.peer_addr, .port = 443 }, prio)) |st| {
                slot.* = .{ .st = st, .pi = null };
            } else |_| {}
        },
    }
    try checkOutput(m);
}

/// The choices a run makes: from the fuzzer (Smith) or, for the seeded
/// sweep, from a PRNG (an `in` Smith maps random bytes to mostly-minimum
/// values, which would never get past the first op).
const Src = union(enum) {
    smith: *Smith,
    rng: std.Random,

    fn value(s: *Src, T: type) T {
        return switch (s.*) {
            .smith => |m| m.value(T),
            .rng => |r| if (T == bool) r.boolean() else r.int(T),
        };
    }
    fn valueRangeAtMost(s: *Src, T: type, a: T, b: T) T {
        return switch (s.*) {
            .smith => |m| m.valueRangeAtMost(T, a, b),
            .rng => |r| r.intRangeAtMost(T, a, b),
        };
    }
    fn boolWeighted(s: *Src, f: u64, tr: u64) bool {
        return switch (s.*) {
            .smith => |m| m.boolWeighted(f, tr),
            .rng => |r| r.uintLessThan(u64, f + tr) >= f,
        };
    }
    fn index(s: *Src, n: usize) usize {
        return switch (s.*) {
            .smith => |m| m.index(n),
            .rng => |r| r.uintLessThan(usize, n),
        };
    }
    fn slice(s: *Src, buf: []u8) u32 {
        return switch (s.*) {
            .smith => |m| m.slice(buf),
            .rng => |r| blk: {
                const n = r.uintAtMost(usize, buf.len);
                r.bytes(buf[0..n]);
                break :blk @intCast(n);
            },
        };
    }
    fn exhausted(s: *Src) bool {
        return switch (s.*) {
            .smith => |m| if (m.in) |in| in.len == 0 else false,
            .rng => false,
        };
    }
};

fn fuzzStack(_: void, smith: *Smith) anyerror!void {
    var src: Src = .{ .smith = smith };
    try runModel(&src);
}

fn runModel(s: *Src) !void {
    const h = try H.create(t.allocator, .{ .limits = limits() });
    defer h.destroy();
    var m: Model = .{ .h = h, .peers = undefined, .peer_nxt = undefined, .listener = try h.stack.listen(listen_port) };
    for (&m.peers, &m.peer_nxt, 0..) |*p, *nx, i| {
        p.* = .{ .peer = .{ .addr = hz.peer_addr, .port = ports[i] }, .stack = .{ .addr = hz.stack_addr, .port = listen_port } };
        nx.* = isnFor(i) +% 1;
    }
    // A step count up front (an `in` Smith ends at the first non-zero eos byte).
    const n_steps = s.valueRangeAtMost(u16, 1, 400);
    for (0..n_steps) |_| {
        if (s.exhausted()) break;
        try step(&m, s);
    }
    for (&m.held) |*slot| if (slot.*) |hd| hd.st.abort();
}

test "netstack fuzz: Stack.input with random and mutated segments, host calls, clock jumps" {
    try hz.need(hz.manual_api);
    try t.fuzz({}, fuzzStack, .{});
}

test "netstack fuzz: seeded random sweep (what runs on Windows, where --fuzz is unavailable)" {
    try hz.need(hz.manual_api);
    var prng: std.Random.DefaultPrng = .init(0x6e65_7473_7461_636b);
    for (0..300) |_| {
        var src: Src = .{ .rng = prng.random() };
        try runModel(&src);
    }
    std.debug.print("fuzz sweep reach: {d} accepted, {d} bytes read, {d} data bytes sent\n", .{ reach.accepted, reach.read_bytes, reach.sent_bytes });
    try t.expect(reach.accepted > 0 and reach.read_bytes > 0 and reach.sent_bytes > 0);
}
