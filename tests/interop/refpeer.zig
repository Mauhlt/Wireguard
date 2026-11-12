//! refpeer: a minimal one-peer WireGuard endpoint built on the reference
//! model (spec.zig) with a UdpTun, speaking the same CLI contract as zwg:
//!
//!     refpeer up <conf> --tun udp:<port>
//!
//! It exists to test the harness itself (the loopback runner runs against
//! it today, and against zwg once the device lands) and to give a second,
//! independent peer for interop. Not a device: one peer, no timers beyond a
//! bounded handshake retry, no roaming, no cookies, no PSK. Event-driven:
//! it sleeps on {WireGuard socket, TUN socket} and wakes only for traffic.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const wg = @import("WireGuard");
const spec = @import("spec.zig");
const tun = wg.tun;

const usage =
    \\usage: refpeer up <conf> --tun udp:<port>
    \\  conf: [Interface] PrivateKey, ListenPort; [Peer] PublicKey, Endpoint = 127.0.0.1:<port>
    \\
;

const Conf = struct {
    private: [32]u8 = undefined,
    listen_port: u16 = 0,
    peer_public: [32]u8 = undefined,
    endpoint_port: ?u16 = null,
};

fn parseConf(text: []const u8) !Conf {
    var c: Conf = .{};
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.eql(u8, key, "PrivateKey")) {
            try std.base64.standard.Decoder.decode(&c.private, val);
        } else if (std.mem.eql(u8, key, "PublicKey")) {
            try std.base64.standard.Decoder.decode(&c.peer_public, val);
        } else if (std.mem.eql(u8, key, "ListenPort")) {
            c.listen_port = try std.fmt.parseInt(u16, val, 10);
        } else if (std.mem.eql(u8, key, "Endpoint")) {
            const colon = std.mem.lastIndexOfScalar(u8, val, ':') orelse return error.BadEndpoint;
            c.endpoint_port = try std.fmt.parseInt(u16, val[colon + 1 ..], 10);
        }
    }
    return c;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(init.arena.allocator());
    _ = args.skip();
    const cmd = args.next() orelse {
        std.debug.print(usage, .{});
        return;
    };
    if (!std.mem.eql(u8, cmd, "up")) return error.Usage;
    const conf_path = args.next() orelse return error.Usage;
    if (!std.mem.eql(u8, args.next() orelse "", "--tun")) return error.Usage;
    const tun_port = try tun.UdpTun.parseSpec(args.next() orelse return error.Usage);

    var text_buf: [4096]u8 = undefined;
    const text = try Io.Dir.cwd().readFile(io, conf_path, &text_buf);
    const conf = try parseConf(text);

    var net = try tun.UdpTun.open(conf.listen_port, 2048); // the WireGuard socket
    defer net.close();
    if (conf.endpoint_port) |p| net.setPeerPort(p);
    var dev = try tun.UdpTun.open(tun_port, 1420); // the TUN
    defer dev.close();
    var peer: Peer = .{ .io = io, .conf = conf, .net = net.tun(), .dev = dev.tun() };
    try peer.loop();
}

const Peer = struct {
    io: Io,
    conf: Conf,
    net: tun.Tun,
    dev: tun.Tun,
    keys: ?spec.Keys = null,
    counter: u64 = 0,
    initiator: ?spec.Initiator = null,
    /// One packet held while the handshake runs (bounded queue of one).
    pending: [2048]u8 = undefined,
    pending_len: usize = 0,

    fn loop(p: *Peer) !void {
        var buf: [2048]u8 = undefined;
        while (true) {
            while (try p.dev.read(&buf)) |pkt| try p.outbound(pkt);
            while (try p.net.read(&buf)) |msg| try p.inbound(msg);
            // Handshake in flight: wake at the 5 s retry deadline at the latest.
            const timeout: u32 = if (p.initiator != null) 5000 else std.math.maxInt(u32);
            if (!waitAny(p.dev.waitHandle(), p.net.waitHandle(), timeout) and p.initiator != null) try p.initiate();
        }
    }

    fn outbound(p: *Peer, pkt: []const u8) !void {
        if (p.keys) |k| {
            var out: [2048 + 64]u8 = undefined;
            try p.net.write(spec.sealTransport(&out, k, p.counter, pkt));
            p.counter += 1;
            return;
        }
        @memcpy(p.pending[0..pkt.len], pkt);
        p.pending_len = pkt.len;
        if (p.initiator == null) try p.initiate();
    }

    fn initiate(p: *Peer) !void {
        p.initiator = spec.Initiator.init(p.conf.private, p.conf.peer_public, @splat(0));
        var eph: [32]u8 = undefined;
        p.io.random(&eph);
        const ts = Io.Clock.real.now(p.io);
        const ns: u96 = @intCast(ts.nanoseconds);
        const m = try p.initiator.?.createInitiation(eph, randomIndex(p.io), spec.tai64n(@intCast(ns / std.time.ns_per_s), @intCast(ns % std.time.ns_per_s)), null);
        try p.net.write(&m);
    }

    fn inbound(p: *Peer, msg: []const u8) !void {
        if (msg.len == 0) return;
        var plain: [2048]u8 = undefined;
        switch (msg[0]) {
            spec.msg_initiation => {
                var r = spec.Responder.init(p.conf.private, @splat(0));
                r.consumeInitiation(msg) catch return;
                if (!std.mem.eql(u8, &r.peer_static, &p.conf.peer_public)) return;
                var eph: [32]u8 = undefined;
                p.io.random(&eph);
                const r2 = try r.createResponse(eph, randomIndex(p.io));
                try p.net.write(&r2.msg);
                p.install(r2.keys);
            },
            spec.msg_response => {
                var ini = p.initiator orelse return;
                const k = ini.consumeResponse(msg) catch return;
                p.initiator = null;
                p.install(k);
                var out: [64]u8 = undefined;
                if (p.pending_len == 0) {
                    // Confirm the session to the responder with a keepalive.
                    try p.net.write(spec.sealTransport(&out, k, p.counter, ""));
                    p.counter += 1;
                } else {
                    const n = p.pending_len;
                    p.pending_len = 0;
                    try p.outbound(p.pending[0..n]);
                }
            },
            spec.msg_transport => {
                const k = p.keys orelse return;
                const o = spec.openTransport(&plain, k, msg) catch return;
                if (o.plain.len == 0) return; // keepalive
                const total = if (o.plain[0] >> 4 == 4) std.mem.readInt(u16, o.plain[2..4], .big) else o.plain.len;
                try p.dev.write(o.plain[0..@min(total, o.plain.len)]);
            },
            else => {},
        }
    }

    fn install(p: *Peer, k: spec.Keys) void {
        p.keys = k;
        p.counter = 0;
    }
};

fn randomIndex(io: Io) u32 {
    var b: [4]u8 = undefined;
    io.random(&b);
    return std.mem.readInt(u32, &b, .little);
}

/// Sleep until either handle is ready (true) or the timeout passes (false).
fn waitAny(a: tun.WaitHandle, b: tun.WaitHandle, timeout_ms: u32) bool {
    if (builtin.os.tag == .windows) {
        const w = tun.queue.win;
        const hs = [2]tun.WaitHandle{ a, b };
        return w.WaitForMultipleObjects(2, &hs, 0, timeout_ms) < 2;
    } else {
        var pfd = [2]std.posix.pollfd{
            .{ .fd = a, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = b, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const t: i32 = if (timeout_ms == std.math.maxInt(u32)) -1 else @intCast(timeout_ms);
        const rc = std.posix.system.poll(&pfd, 2, t);
        return std.posix.errno(rc) == .SUCCESS and rc > 0;
    }
}
