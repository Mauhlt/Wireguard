//! Two netstacks joined by two real zwg Devices over UDP on 127.0.0.1
//! (loopback-only sockets: no firewall prompt, nothing reachable from the
//! network). The hub (10.8.0.1) is an `ns.Node`; the device side
//! (10.8.0.2) is an `ns.Node` too, or, with an impairment, the same
//! wiring by hand with `ns.testing.ImpairedTun` between its device and
//! its stack (so both directions of every connection are impaired).
const std = @import("std");
const hz = @import("harness.zig");
const wg = hz.wg;
const ns = hz.ns;
const crypto = wg.crypto;
const dev = wg.device;

pub const hub_addr: ns.Addr = .{ .v4 = .{ 10, 8, 0, 1 } };
pub const dev_addr: ns.Addr = .{ .v4 = .{ 10, 8, 0, 2 } };

pub const Options = struct {
    impairment: ?ns.testing.Impairment = null,
    seed: u64 = 1,
    limits: ns.Limits = .{},
};

pub const Pair = struct {
    gpa: std.mem.Allocator,
    clock: ns.Clock,
    hub: *ns.Node,
    /// Device side, as a Node (no impairment) ...
    node: ?*ns.Node = null,
    /// ... or by hand around an ImpairedTun.
    stack: *ns.Stack,
    device: ?*dev.Device = null,
    impaired: ?*ns.testing.ImpairedTun = null,
    device_thread: ?std.Thread = null,

    fn keyPair() struct { priv: crypto.PrivateKey, public: crypto.PublicKey } {
        var priv: crypto.PrivateKey = undefined;
        std.testing.io.random(&priv);
        crypto.clampPrivateKey(&priv);
        return .{ .priv = priv, .public = crypto.publicKey(priv) };
    }

    pub fn create(gpa: std.mem.Allocator, o: Options) !*Pair {
        try hz.need(hz.manual_api);
        try hz.need(hz.threaded_api);
        const p = try gpa.create(Pair);
        errdefer gpa.destroy(p);
        p.* = .{ .gpa = gpa, .clock = .{ .io = std.testing.io }, .hub = undefined, .stack = undefined };
        const kh = keyPair();
        const kd = keyPair();
        const hub_cidr = try dev.ip.Cidr.parse("10.8.0.1/32");
        const dev_cidr = try dev.ip.Cidr.parse("10.8.0.2/32");
        p.hub = try ns.Node.start(gpa, &p.clock, .{
            .private_key = kh.priv,
            .loopback_only = true,
            .peers = &.{.{ .public_key = kd.public, .allowed_ips = &.{dev_cidr} }},
        }, .{ .address = hub_addr, .limits = o.limits });
        errdefer p.hub.destroy();
        const dev_opts: dev.device.Options = .{
            .private_key = kd.priv,
            .loopback_only = true,
            .peers = &.{.{
                .public_key = kh.public,
                .endpoint = .{ .ip4 = .loopback(p.hub.device.listen_port) },
                .allowed_ips = &.{hub_cidr},
            }},
        };
        const stack_opts: ns.Options = .{ .address = dev_addr, .limits = o.limits };
        if (o.impairment) |imp| {
            p.stack = try ns.Stack.create(gpa, &p.clock, stack_opts);
            errdefer p.stack.destroy();
            const it = try gpa.create(ns.testing.ImpairedTun);
            errdefer gpa.destroy(it);
            it.* = .init(p.stack.tun(), o.seed, imp, imp);
            p.impaired = it;
            p.device = try dev.Device.create(gpa, &p.clock, it.tun(), dev_opts);
            errdefer p.device.?.destroy();
            try p.stack.start();
            p.device_thread = try std.Thread.spawn(.{}, runDevice, .{p.device.?});
        } else {
            p.node = try ns.Node.start(gpa, &p.clock, dev_opts, stack_opts);
            p.stack = p.node.?.stack;
        }
        return p;
    }

    fn runDevice(d: *dev.Device) void {
        d.run() catch |err| std.debug.print("device loop ended: {s}\n", .{@errorName(err)});
    }

    pub fn destroy(p: *Pair) void {
        if (p.node) |n| {
            n.destroy();
        } else {
            p.stack.abortAll();
            if (p.device_thread) |t| {
                p.device.?.stop();
                t.join();
            }
            p.stack.stop();
            p.device.?.destroy();
            p.stack.destroy();
            p.gpa.destroy(p.impaired.?);
        }
        p.hub.destroy();
        p.gpa.destroy(p);
    }

    pub fn hubStack(p: *Pair) *ns.Stack {
        return p.hub.stack;
    }

    /// Device side dials hub:port (priority as given); the hub accepts.
    pub fn connect(p: *Pair, l: ns.Listener, prio: ns.Priority) !struct { dev: ns.Stream, hub: ns.Stream } {
        const d = try p.stack.dialWith(.{ .addr = hub_addr, .port = l.port() }, prio);
        errdefer d.abort();
        try d.waitConnected(20 * hz.sec);
        const h = try l.acceptWait(20 * hz.sec);
        if (prio == .bulk) h.setPriority(.bulk);
        return .{ .dev = d, .hub = h };
    }

    pub fn now(p: *Pair) i64 {
        return p.clock.now();
    }
};

// ---- bulk transfer helpers (threads; blocking calls with timeouts) -------

pub const io_timeout: u64 = 120 * hz.sec;

pub const Sent = struct {
    digest: [32]u8 = undefined,
    bytes: u64 = 0,
    err: ?anyerror = null,
};

pub const Received = struct {
    digest: [32]u8 = undefined,
    bytes: u64 = 0,
    err: ?anyerror = null,
};

/// Writes `total` PRNG bytes (seeded) and shuts the stream down.
pub fn sendAll(st: ns.Stream, seed: u64, total: u64, out: *Sent) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    var sha: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var left = total;
    while (left > 0) {
        const n: usize = @intCast(@min(left, buf.len));
        prng.random().bytes(buf[0..n]);
        sha.update(buf[0..n]);
        st.writeAll(buf[0..n], io_timeout) catch |e| {
            out.err = e;
            return;
        };
        left -= n;
        out.bytes += n;
    }
    st.shutdown();
    out.digest = sha.finalResult();
}

/// Reads to end of stream.
pub fn recvAll(st: ns.Stream, out: *Received) void {
    var sha: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = st.readWait(&buf, io_timeout) catch |e| {
            out.err = e;
            return;
        };
        if (n == 0) break;
        sha.update(buf[0..n]);
        out.bytes += n;
    }
    out.digest = sha.finalResult();
}

pub fn percentile(sorted: []const u64, p: u64) u64 {
    if (sorted.len == 0) return 0;
    const i = @min(sorted.len - 1, (sorted.len * p) / 100);
    return sorted[i];
}