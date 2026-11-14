//! Shared driver for tests/netstack: a Stack in manual mode (input / output /
//! runTimers on a virtual device clock) plus fake peers. Packet crafting and
//! parsing is `ns.testing.Peer` + `ns.wire` only; this file drives the stack
//! and gates tests on what is implemented.
const std = @import("std");
pub const wg = @import("WireGuard");
pub const ns = wg.netstack;
pub const wire = ns.wire;
pub const Peer = ns.testing.Peer;
pub const Seg = Peer.Seg;
pub const options = @import("netstack_test_options");

pub const stack_ip: [4]u8 = .{ 10, 8, 0, 1 };
pub const peer_ip: [4]u8 = .{ 10, 8, 0, 2 };
pub const stack_addr: ns.Addr = .{ .v4 = stack_ip };
pub const peer_addr: ns.Addr = .{ .v4 = peer_ip };
pub const ms: u64 = std.time.ns_per_ms;
pub const sec: u64 = std.time.ns_per_s;

// ---- gating on the implementation ----------------------------------------

/// src/netstack/stack.zig as built (build.zig anonymous import).
const stack_src = @embedFile("netstack_stack_src");

/// True when `Container.name` in src/netstack/stack.zig still calls todo().
pub fn isStub(name: []const u8) bool {
    var container: []const u8 = "";
    var func: []const u8 = "";
    var it = std.mem.splitScalar(u8, stack_src, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "pub const ") and std.mem.indexOf(u8, line, " = struct") != null) {
            const rest = line["pub const ".len..];
            container = rest[0 .. std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len];
            func = "";
        } else if (std.mem.indexOf(u8, line, "pub fn ")) |i| {
            const rest = line[i + "pub fn ".len ..];
            func = rest[0 .. std.mem.indexOfScalar(u8, rest, '(') orelse rest.len];
        } else if (std.mem.indexOf(u8, line, "todo();") != null and func.len != 0) {
            if (name.len == container.len + 1 + func.len and std.mem.startsWith(u8, name, container) and
                name[container.len] == '.' and std.mem.endsWith(u8, name, func)) return true;
        }
    }
    return false;
}

/// Skips the test (error.SkipZigTest) while any of `names` is still a stub.
pub fn need(names: []const []const u8) error{SkipZigTest}!void {
    for (names) |n| if (isStub(n)) {
        std.debug.print("SKIP: netstack {s} not implemented yet\n", .{n});
        return error.SkipZigTest;
    };
}

pub fn skip(comptime reason: []const u8) error{SkipZigTest} {
    std.debug.print("SKIP: " ++ reason ++ "\n", .{});
    return error.SkipZigTest;
}

/// What the manual-drive tests need.
pub const manual_api: []const []const u8 = &.{
    "Stack.create",  "Stack.destroy", "Stack.input",     "Stack.output",    "Stack.runTimers",
    "Stack.listen",  "Stack.dial",    "Stack.stats",     "Listener.accept", "Listener.close",
    "Listener.port", "Stream.read",   "Stream.write",    "Stream.status",   "Stream.shutdown",
    "Stream.close",  "Stream.abort",
};
/// What the threaded tests (Node, blocking calls) need on top.
pub const threaded_api: []const []const u8 = &.{
    "Node.start",      "Node.destroy",   "Stack.dialWait",       "Listener.acceptWait",
    "Stream.readWait", "Stream.writeAll", "Stream.waitConnected", "Stack.tun",
    "Stack.start",     "Stack.stop",
};

/// IPv6 in the stack (Options.address6).
pub const has_ipv6 = @hasField(ns.Options, "address6");

pub const stack_ip6: [16]u8 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const peer_ip6: [16]u8 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
pub const stack_addr6: ns.Addr = .{ .v6 = stack_ip6 };
pub const peer_addr6: ns.Addr = .{ .v6 = peer_ip6 };

/// The per-stream priority feature (interactive-first output scheduler).
pub const has_priority = @hasDecl(ns.Stream, "setPriority");

// ---- manual-mode harness ---------------------------------------------------

pub const Config = struct {
    address: ns.Addr = stack_addr,
    /// IPv6 address next to the IPv4 one (Options.address6, when the
    /// stack has it).
    address6: ?ns.Addr = null,
    limits: ns.Limits = .{},
    mtu: u16 = 1420,
    icmp_echo: bool = true,
    keepalive_idle_ns: ?u64 = null,
};

/// One stack in manual mode on a virtual clock. Heap-allocated (the stack
/// keeps a pointer to `clock`). `fa` counts every byte the stack allocates.
pub const H = struct {
    gpa: std.mem.Allocator,
    fa: std.testing.FailingAllocator,
    clock: ns.Clock,
    stack: *ns.Stack,
    cfg: Config,
    inbuf: [wire.ip4_header_len + 65535]u8 = undefined,
    outbuf: [65535]u8 = undefined,

    pub fn create(gpa: std.mem.Allocator, cfg: Config) !*H {
        try need(manual_api);
        const h = try gpa.create(H);
        errdefer gpa.destroy(h);
        h.* = .{ .gpa = gpa, .fa = .init(gpa, .{}), .clock = .{ .io = std.testing.io }, .stack = undefined, .cfg = cfg };
        var opts: ns.Options = .{
            .address = cfg.address,
            .mtu = cfg.mtu,
            .limits = cfg.limits,
            .icmp_echo = cfg.icmp_echo,
            .keepalive_idle_ns = cfg.keepalive_idle_ns,
        };
        if (comptime has_ipv6) opts.address6 = cfg.address6 else if (cfg.address6 != null) return skip("IPv6 (Options.address6) not on feat/netstack yet");
        h.stack = try ns.Stack.create(h.fa.allocator(), &h.clock, opts);
        return h;
    }

    pub fn destroy(h: *H) void {
        h.stack.destroy();
        const gpa = h.gpa;
        gpa.destroy(h);
    }

    /// Bytes the stack holds right now.
    pub fn liveBytes(h: *const H) usize {
        return h.fa.allocated_bytes - h.fa.freed_bytes;
    }

    pub fn now(h: *const H) i64 {
        return h.clock.now();
    }

    pub fn send(h: *H, p: *Peer, s: Seg) void {
        h.stack.input(p.packet(&h.inbuf, s));
    }

    pub fn sendRaw(h: *H, pkt: []const u8) void {
        h.stack.input(pkt);
    }

    /// Next raw packet (valid until the next output call), no time passing.
    /// Every packet must fit the MTU.
    pub fn out(h: *H) ?[]u8 {
        const p = h.stack.output(&h.outbuf) orelse return null;
        if (p.len > h.cfg.mtu) std.debug.panic("netstack sent {d} bytes, over the MTU {d}", .{ p.len, h.cfg.mtu });
        return p;
    }

    /// Next packet parsed as TCP from `p.stack` to `p.peer` (fails if
    /// anything else comes out), no time passing.
    pub fn seg(h: *H, p: *const Peer) !?wire.Tcp {
        const pkt = h.out() orelse return null;
        return try p.expect(pkt);
    }

    /// Moves the virtual clock forward and fires due timers.
    pub fn advance(h: *H, d: u64) void {
        h.clock.advance(@intCast(d));
        _ = h.stack.runTimers();
    }

    /// The next deadline (ns from now; 0 if due), or null when no timer.
    pub fn nextDeadline(h: *H) ?u64 {
        const d = h.stack.runTimers() orelse return null;
        const n = h.now();
        return if (d <= n) 0 else @intCast(d - n);
    }

    /// Next packet from the stack, letting virtual time run to each timer
    /// deadline (event-driven on the stack's own deadlines) for at most
    /// `budget` ns. Returns null if nothing comes within the budget.
    pub fn waitOut(h: *H, budget: u64) ?[]u8 {
        var left = budget;
        var spins: u32 = 0;
        while (true) {
            if (h.out()) |p| return p;
            const d_opt = h.nextDeadline();
            // Timers that fired may have queued output (and armed nothing yet).
            if (h.out()) |p| return p;
            const d = d_opt orelse return null;
            if (d == 0) {
                spins += 1;
                if (spins > 1000) @panic("netstack: runTimers keeps returning a past deadline and sends nothing");
                continue;
            }
            if (d > left) return null;
            left -= d;
            h.clock.advance(@intCast(d));
        }
    }

    pub fn waitSeg(h: *H, p: *const Peer, budget: u64) !?wire.Tcp {
        const pkt = h.waitOut(budget) orelse return null;
        return try p.expect(pkt);
    }

    /// Discards everything queued for output (no time passing); returns count.
    pub fn drain(h: *H) usize {
        var n: usize = 0;
        while (h.out() != null) n += 1;
        return n;
    }

    pub fn expectSilent(h: *H) !void {
        if (h.out()) |p| {
            std.debug.print("unexpected packet from the stack: {x}\n", .{p[0..@min(p.len, 60)]});
            return error.UnexpectedPacket;
        }
    }

    pub fn stats(h: *H) ns.Stats {
        return h.stack.stats();
    }
};

/// A connection between the stack and a fake peer, tracked from the peer's
/// point of view.
pub const Conn = struct {
    peer: Peer,
    stream: ns.Stream,
    /// Peer's next sequence number to send.
    snd_nxt: u32,
    /// Next sequence number expected from the stack (what the peer ACKs).
    rcv_nxt: u32,
    /// The stack's ISS (its SYN's sequence number).
    iss: u32,
    /// The stack's SYN / SYN-ACK fields (payload not kept).
    syn_options: wire.TcpOptions,
    syn_window: u16,
    /// Window the peer advertises by default.
    window: u16 = 65535,

    pub fn data(c: *Conn, h: *H, payload: []const u8) void {
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true, .psh = true }, .window = c.window, .payload = payload });
        c.snd_nxt +%= @intCast(payload.len);
    }

    pub fn ack(c: *Conn, h: *H) void {
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true }, .window = c.window });
    }

    pub fn fin(c: *Conn, h: *H) void {
        h.send(&c.peer, .{ .seq = c.snd_nxt, .ack = c.rcv_nxt, .flags = .{ .ack = true, .fin = true }, .window = c.window });
        c.snd_nxt +%= 1;
    }

    pub fn state(c: *const Conn) ns.State {
        return c.stream.status().state;
    }

    /// Like `pull`, but first waits (virtual time, at most `budget`) for
    /// the stack to send something.
    pub fn pullWait(c: *Conn, h: *H, sink: ?*std.ArrayList(u8), gpa: std.mem.Allocator, budget: u64) !usize {
        var n: usize = 0;
        var pkt: ?[]u8 = h.waitOut(budget);
        while (pkt) |raw| : (pkt = h.out()) {
            const t = try c.peer.expect(raw);
            if (t.payload.len != 0 and t.seq == c.rcv_nxt) {
                if (sink) |s| try s.appendSlice(gpa, t.payload);
                c.rcv_nxt +%= @intCast(t.payload.len);
                n += t.payload.len;
            }
            if (t.flags.fin and t.seq +% @as(u32, @intCast(t.payload.len)) == c.rcv_nxt) c.rcv_nxt +%= 1;
        }
        if (n != 0) c.ack(h);
        return n;
    }

    /// Collects the stack's data segments (no time passing) and ACKs them
    /// all; returns the payload bytes seen (appended to `sink` if given).
    pub fn pull(c: *Conn, h: *H, sink: ?*std.ArrayList(u8), gpa: std.mem.Allocator) !usize {
        var n: usize = 0;
        while (try h.seg(&c.peer)) |t| {
            if (t.payload.len != 0 and t.seq == c.rcv_nxt) {
                if (sink) |s| try s.appendSlice(gpa, t.payload);
                c.rcv_nxt +%= @intCast(t.payload.len);
                n += t.payload.len;
            }
            if (t.flags.fin and t.seq +% @as(u32, @intCast(t.payload.len)) == c.rcv_nxt) c.rcv_nxt +%= 1;
        }
        if (n != 0) c.ack(h);
        return n;
    }
};

pub const PassiveOpts = struct {
    peer_port: u16 = 40000,
    isn: u32 = 1_000_000,
    window: u16 = 65535,
    syn_options: wire.TcpOptions = .{ .mss = 1380 },
    /// Accept the connection (else `stream` is undefined).
    accept: bool = true,
    /// IPv6: peer_addr6 / stack_addr6.
    peer_addr: ns.Addr = peer_addr,
    stack_addr: ns.Addr = stack_addr,
};

/// Peer -> SYN, stack -> SYN-ACK, peer -> ACK, then accept.
pub fn openPassive(h: *H, l: ns.Listener, o: PassiveOpts) !Conn {
    var p: Peer = .{ .peer = .{ .addr = o.peer_addr, .port = o.peer_port }, .stack = .{ .addr = o.stack_addr, .port = l.port() } };
    h.send(&p, .{ .seq = o.isn, .flags = .{ .syn = true }, .window = o.window, .options = o.syn_options });
    const sa = (try h.seg(&p)) orelse return error.NoSynAck;
    try std.testing.expect(sa.flags.syn and sa.flags.ack and !sa.flags.rst);
    try std.testing.expectEqual(o.isn +% 1, sa.ack);
    var c: Conn = .{ .peer = p, .stream = undefined, .snd_nxt = o.isn +% 1, .rcv_nxt = sa.seq +% 1, .iss = sa.seq, .syn_options = sa.options, .syn_window = sa.window, .window = o.window };
    c.ack(h);
    if (o.accept) c.stream = try l.accept();
    return c;
}

pub const ActiveOpts = struct {
    port: u16 = 443,
    isn: u32 = 7_000_000,
    window: u16 = 65535,
    synack_options: wire.TcpOptions = .{ .mss = 1380 },
    /// The peer to dial (peer_addr6 for IPv6); the stack picks its source.
    peer_addr: ns.Addr = peer_addr,
};

/// stack.dial -> SYN, peer -> SYN-ACK, stack -> ACK.
pub fn openActive(h: *H, o: ActiveOpts) !Conn {
    const st = try h.stack.dial(.{ .addr = o.peer_addr, .port = o.port });
    const pkt = h.out() orelse return error.NoSyn;
    const tp = try wire.parseTcp(pkt);
    const t = .{ .tcp = tp.tcp };
    try std.testing.expect(t.tcp.flags.syn and !t.tcp.flags.ack);
    var c: Conn = .{
        .peer = .{ .peer = .{ .addr = o.peer_addr, .port = o.port }, .stack = .{ .addr = tp.ip.src, .port = t.tcp.src_port } },
        .stream = st,
        .snd_nxt = o.isn +% 1,
        .rcv_nxt = t.tcp.seq +% 1,
        .iss = t.tcp.seq,
        .syn_options = t.tcp.options,
        .syn_window = t.tcp.window,
        .window = o.window,
    };
    h.send(&c.peer, .{ .seq = o.isn, .ack = c.rcv_nxt, .flags = .{ .syn = true, .ack = true }, .window = o.window, .options = o.synack_options });
    const a = (try h.waitSeg(&c.peer, 1 * sec)) orelse return error.NoHandshakeAck;
    try std.testing.expect(a.flags.ack and !a.flags.syn);
    try std.testing.expectEqual(c.snd_nxt, a.ack);
    return c;
}

/// Byte `i` of a deterministic test stream: what a sender writes and a
/// receiver checks without keeping a copy.
pub fn patternByte(seed: u32, i: u64) u8 {
    var x: u64 = i *% 0x9E3779B97F4A7C15 +% seed;
    x ^= x >> 29;
    x *%= 0xBF58476D1CE4E5B9;
    return @truncate(x >> 32);
}

pub fn fillPattern(seed: u32, offset: u64, out: []u8) void {
    for (out, 0..) |*b, i| b.* = patternByte(seed, offset + i);
}

/// RFC 9293 modular sequence comparison.
pub fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}
pub fn seqLe(a: u32, b: u32) bool {
    return a == b or seqLt(a, b);
}
/// Reads everything buffered right now (non-blocking) into `into`;
/// returns true at end of stream.
pub fn readAvailable(st: ns.Stream, gpa: std.mem.Allocator, into: *std.ArrayList(u8)) !bool {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = st.read(&buf) catch |e| switch (e) {
            error.WouldBlock => return false,
            else => return e,
        };
        if (n == 0) return true;
        try into.appendSlice(gpa, buf[0..n]);
    }
}

/// Writes `data` with non-blocking writes until the send buffer refuses
/// more; returns how much was accepted.
pub fn writeSome(st: ns.Stream, data: []const u8) !usize {
    var off: usize = 0;
    while (off < data.len) {
        off += st.write(data[off..]) catch |e| switch (e) {
            error.WouldBlock => return off,
            else => return e,
        };
    }
    return off;
}