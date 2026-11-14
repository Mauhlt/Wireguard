//! In-process end to end: two zwg Devices talking real UDP over
//! 127.0.0.1, each with a netstack as its Tun (behind a seeded
//! ImpairedTun). Built as its own test binary in ReleaseSafe (`zig build
//! test` runs it), because 100 MiB through Debug-mode crypto is slow.
//!
//!   * 50 MiB each way at once with loss / reordering / duplication,
//!     SHA-256 checked on both ends; prints throughput and loss counts.
//!   * Interactive latency under a saturating bulk stream, without loss
//!     and with 1% loss on the bulk stream only.
//!   * Node (device + stack + threads) with the std.Io Reader / Writer
//!     adapters and the ready callback. (No TLS smoke test: std has a
//!     TLS client but no server to run it against in-process.)
//!
//! The transfer and latency runs go over IPv4 (10.8.0.1 / 10.8.0.2,
//! IPv4-only stacks) and over IPv6 (fd0a:8::1 / fd0a:8::2 on dual-stack
//! stacks that also hold the IPv4 addresses, as Portal would configure
//! them). Only the inner addresses change: the outer WireGuard UDP stays
//! on 127.0.0.1.
//!
//! Everything waits on real events (blocking stream calls with
//! timeouts); nothing sleeps or polls. Sockets bind 127.0.0.1 only.
const std = @import("std");
const wg = @import("WireGuard");
const ns = wg.netstack;
const dev = wg.device;
const t = std.testing;

const server_addr: ns.Addr = .{ .v4 = .{ 10, 8, 0, 1 } };
const client_addr: ns.Addr = .{ .v4 = .{ 10, 8, 0, 2 } };
const server_addr6: ns.Addr = .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
const client_addr6: ns.Addr = .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } };

/// The inner address family a Pair's connections use. `.v6`: both stacks
/// are dual-stack (IPv4 + IPv6 addresses, both in AllowedIPs) and the
/// connections go over IPv6.
const Family = enum { v4, v6 };
const port_main: u16 = 8420;
const port_bulk: u16 = 8421;
const io_timeout_ns: u64 = 60 * std.time.ns_per_s;

const Side = struct {
    stack: *ns.Stack,
    imp: ns.testing.ImpairedTun,
    device: *dev.Device,
    thread: ?std.Thread = null,

    fn create(gpa: std.mem.Allocator, clock: *dev.device.Clock, options: ns.Options, priv: wg.crypto.PrivateKey, peer: dev.device.PeerConfig, seed: u64, imp_in: ns.testing.Impairment, imp_out: ns.testing.Impairment) !*Side {
        const s = try gpa.create(Side);
        errdefer gpa.destroy(s);
        s.stack = try ns.Stack.create(gpa, clock, options);
        errdefer s.stack.destroy();
        s.imp = .init(s.stack.tun(), seed, imp_in, imp_out);
        s.device = try dev.Device.create(gpa, clock, s.imp.tun(), .{
            .private_key = priv,
            .loopback_only = true,
            .peers = &.{peer},
        });
        s.thread = null;
        return s;
    }

    fn start(s: *Side) !void {
        try s.stack.start();
        s.thread = try std.Thread.spawn(.{}, runDevice, .{s.device});
    }

    fn runDevice(d: *dev.Device) void {
        d.run() catch |err| std.debug.print("device loop ended: {s}\n", .{@errorName(err)});
    }

    fn destroy(s: *Side, gpa: std.mem.Allocator) void {
        s.stack.abortAll();
        if (s.thread) |th| {
            s.device.stop();
            th.join();
        }
        s.stack.stop();
        s.device.destroy();
        s.stack.destroy();
        gpa.destroy(s);
    }
};

const Pair = struct {
    clock: dev.device.Clock,
    family: Family,
    server: *Side,
    client: *Side,

    fn create(gpa: std.mem.Allocator, family: Family, imp_in: ns.testing.Impairment, imp_out: ns.testing.Impairment) !*Pair {
        const p = try gpa.create(Pair);
        errdefer gpa.destroy(p);
        p.clock = .{ .io = t.io };
        p.family = family;
        var ks: wg.crypto.PrivateKey = undefined;
        var kc: wg.crypto.PrivateKey = undefined;
        t.io.random(&ks);
        t.io.random(&kc);
        wg.crypto.clampPrivateKey(&ks);
        wg.crypto.clampPrivateKey(&kc);
        defer wg.crypto.wipe(&ks);
        defer wg.crypto.wipe(&kc);
        const server_cidrs = [_]dev.ip.Cidr{ try dev.ip.Cidr.parse("10.8.0.1/32"), try dev.ip.Cidr.parse("fd0a:8::1/128") };
        const client_cidrs = [_]dev.ip.Cidr{ try dev.ip.Cidr.parse("10.8.0.2/32"), try dev.ip.Cidr.parse("fd0a:8::2/128") };
        const n_cidrs: usize = if (family == .v6) 2 else 1;
        const dual = family == .v6;
        p.server = try Side.create(gpa, &p.clock, .{ .address = server_addr, .address6 = if (dual) server_addr6 else null }, ks, .{
            .public_key = wg.crypto.publicKey(kc),
            .allowed_ips = client_cidrs[0..n_cidrs],
        }, 0x5e5e, imp_in, imp_out);
        errdefer p.server.destroy(gpa);
        p.client = try Side.create(gpa, &p.clock, .{ .address = client_addr, .address6 = if (dual) client_addr6 else null }, kc, .{
            .public_key = wg.crypto.publicKey(ks),
            .allowed_ips = server_cidrs[0..n_cidrs],
            .endpoint = .{ .ip4 = .loopback(p.server.device.listen_port) },
        }, 0xc1c1, imp_in, imp_out);
        errdefer p.client.destroy(gpa);
        try p.server.start();
        try p.client.start();
        return p;
    }

    fn destroy(p: *Pair, gpa: std.mem.Allocator) void {
        p.client.destroy(gpa);
        p.server.destroy(gpa);
        gpa.destroy(p);
    }

    /// The server's inner address the client dials.
    fn serverAddr(p: *const Pair) ns.Addr {
        return if (p.family == .v6) server_addr6 else server_addr;
    }

    /// Dials the server's `port` from the client and accepts it; checks
    /// both ends use the Pair's family.
    fn connect(p: *Pair, l: ns.Listener, port: u16, priority: ns.Priority) !struct { c: ns.Stream, s: ns.Stream } {
        const c = try p.client.stack.dialWith(.{ .addr = p.serverAddr(), .port = port }, priority);
        errdefer c.abort();
        try c.waitConnected(20 * std.time.ns_per_s);
        const s = try l.acceptWait(5 * std.time.ns_per_s);
        try t.expectEqual(p.serverAddr(), c.remote().addr);
        try t.expectEqual(std.meta.activeTag(p.serverAddr()), std.meta.activeTag(s.remote().addr));
        return .{ .c = c, .s = s };
    }
};

/// Deterministic byte stream: seeded PRNG, hashed as written / read.
const Pump = struct {
    stream: ns.Stream,
    total: usize,
    seed: u64,
    digest: [32]u8 = undefined,
    bytes: usize = 0,
    err: ?anyerror = null,

    fn send(p: *Pump) void {
        p.sendInner() catch |e| {
            p.err = e;
        };
    }

    fn sendInner(p: *Pump) !void {
        var prng = std.Random.DefaultPrng.init(p.seed);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var chunk: [32 * 1024]u8 = undefined;
        while (p.bytes < p.total) {
            const n = @min(chunk.len, p.total - p.bytes);
            prng.random().bytes(chunk[0..n]);
            h.update(chunk[0..n]);
            try p.stream.writeAll(chunk[0..n], io_timeout_ns);
            p.bytes += n;
        }
        p.stream.shutdown();
        h.final(&p.digest);
    }

    fn recv(p: *Pump) void {
        p.recvInner() catch |e| {
            p.err = e;
        };
    }

    fn recvInner(p: *Pump) !void {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try p.stream.readWait(&buf, io_timeout_ns);
            if (n == 0) break;
            h.update(buf[0..n]);
            p.bytes += n;
        }
        h.final(&p.digest);
    }
};

fn transfer(gpa: std.mem.Allocator, family: Family, size: usize, loss_ppm: u32, reorder_ppm: u32, dup_ppm: u32) !void {
    const imp: ns.testing.Impairment = .{ .loss_ppm = loss_ppm, .reorder_ppm = reorder_ppm, .duplicate_ppm = dup_ppm };
    const p = try Pair.create(gpa, family, imp, imp);
    defer p.destroy(gpa);

    const l = try p.server.stack.listen(port_main);
    const conn = try p.connect(l, port_main, .interactive);
    const c = conn.c;
    const s = conn.s;

    const t0 = p.clock.now();
    var c_out: Pump = .{ .stream = c, .total = size, .seed = 1 };
    var s_in: Pump = .{ .stream = s, .total = size, .seed = 0 };
    var s_out: Pump = .{ .stream = s, .total = size, .seed = 2 };
    var c_in: Pump = .{ .stream = c, .total = size, .seed = 0 };
    const threads = [_]std.Thread{
        try std.Thread.spawn(.{}, Pump.send, .{&c_out}),
        try std.Thread.spawn(.{}, Pump.recv, .{&s_in}),
        try std.Thread.spawn(.{}, Pump.send, .{&s_out}),
        try std.Thread.spawn(.{}, Pump.recv, .{&c_in}),
    };
    for (threads) |th| th.join();
    const elapsed = p.clock.now() - t0;

    for ([_]*Pump{ &c_out, &s_in, &s_out, &c_in }, [_][]const u8{ "client send", "server recv", "server send", "client recv" }) |pp, name| if (pp.err) |e| {
        std.debug.print("pump {s} failed: {s} after {d} bytes, now={d}\n  client stats {any}\n  server stats {any}\n", .{
            name, @errorName(e), pp.bytes, p.clock.now(), p.client.stack.stats(), p.server.stack.stats(),
        });
        ns.testing.dumpStream("client", c);
        ns.testing.dumpStream("server", s);
        std.debug.print("  device client {any}\n  device server {any}\n  imp client {any}\n  imp server {any}\n", .{ p.client.device.stats, p.server.device.stats, p.client.imp.counts, p.server.imp.counts });
        return e;
    };
    try t.expectEqual(size, s_in.bytes);
    try t.expectEqual(size, c_in.bytes);
    try t.expectEqualSlices(u8, &c_out.digest, &s_in.digest);
    try t.expectEqualSlices(u8, &s_out.digest, &c_in.digest);

    c.close();
    s.close();
    l.close();

    const secs = @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s;
    const mib = @as(f64, @floatFromInt(2 * size)) / (1024 * 1024);
    const ss = p.server.stack.stats();
    const cs = p.client.stack.stats();
    const sc = p.server.imp.counts;
    const cc = p.client.imp.counts;
    std.debug.print(
        \\
        \\netstack e2e ({t}): {d} MiB each way, loss {d} ppm, reorder {d} ppm, dup {d} ppm per direction per side
        \\  {d:.2} s, {d:.1} MiB/s aggregate ({d:.1} MiB/s each way)
        \\  impaired: dropped {d}, reordered {d}, duplicated {d}, passed {d}
        \\  server: tx {d} rx {d} retransmits {d} fast {d} rto {d} ooo-drop {d} ring-drop {d}
        \\  client: tx {d} rx {d} retransmits {d} fast {d} rto {d} ooo-drop {d} ring-drop {d}
        \\
    , .{
        family,
        size / (1024 * 1024),
        loss_ppm,
        reorder_ppm,
        dup_ppm,
        secs,
        mib / secs,
        mib / 2 / secs,
        sc.dropped + cc.dropped,
        sc.reordered + cc.reordered,
        sc.duplicated + cc.duplicated,
        sc.passed + cc.passed,
        ss.tx_packets,
        ss.rx_packets,
        ss.retransmits,
        ss.fast_retransmits,
        ss.rto_expirations,
        ss.dropped_ooo,
        ss.dropped_ring_full,
        cs.tx_packets,
        cs.rx_packets,
        cs.retransmits,
        cs.fast_retransmits,
        cs.rto_expirations,
        cs.dropped_ooo,
        cs.dropped_ring_full,
    });
}

test "e2e: 50 MiB both ways, 1% loss + reordering + duplication, SHA-256 checked" {
    // 0.5% per impairment point; a packet crosses two (sender's outbound,
    // receiver's inbound), so about 1% end to end, both directions.
    try transfer(t.allocator, .v4, 50 * 1024 * 1024, 5_000, 5_000, 1_000);
}

test "e2e: 50 MiB both ways, 5% loss + reordering + duplication, SHA-256 checked" {
    // 2.5% per impairment point: ~5% end to end, both directions.
    try transfer(t.allocator, .v4, 50 * 1024 * 1024, 25_000, 5_000, 1_000);
}

test "e2e: 50 MiB both ways, clean path" {
    try transfer(t.allocator, .v4, 50 * 1024 * 1024, 0, 0, 0);
}

test "e2e IPv6: 50 MiB both ways over fd0a:8::/64, 1% loss + reordering + duplication, SHA-256 checked" {
    try transfer(t.allocator, .v6, 50 * 1024 * 1024, 5_000, 5_000, 1_000);
}

test "e2e IPv6: 50 MiB both ways over fd0a:8::/64, clean path" {
    try transfer(t.allocator, .v6, 50 * 1024 * 1024, 0, 0, 0);
}

// ---- interactive latency under bulk -----------------------------------------

const Bulk = struct {
    stream: ns.Stream,
    stop: std.atomic.Value(bool) = .init(false),
    bytes: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,

    fn send(b: *Bulk) void {
        var chunk: [64 * 1024]u8 = @splat(0xb0);
        while (!b.stop.load(.acquire)) {
            b.stream.writeAll(&chunk, io_timeout_ns) catch |e| {
                b.err = e;
                return;
            };
            _ = b.bytes.fetchAdd(chunk.len, .monotonic);
        }
        b.stream.shutdown();
    }

    fn drain(b: *Bulk) void {
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = b.stream.readWait(&buf, io_timeout_ns) catch |e| {
                b.err = e;
                return;
            };
            if (n == 0) return;
            _ = b.bytes.fetchAdd(n, .monotonic);
        }
    }
};

const Echo = struct {
    stream: ns.Stream,
    clock: *dev.device.Clock,
    max_ns: i64 = 0,
    sum_ns: i64 = 0,
    count: usize = 0,
    /// The first samples, for percentiles.
    samples: [8192]i64 = undefined,
    err: ?anyerror = null,

    fn percentile(e: *Echo, p: usize) i64 {
        const n = @min(e.count, e.samples.len);
        if (n == 0) return 0;
        std.mem.sort(i64, e.samples[0..n], {}, std.sort.asc(i64));
        return e.samples[@min(n - 1, n * p / 100)];
    }

    /// Server side: every 8-byte message carries the sender's clock; the
    /// one-way latency is now - that (same process, same clock).
    fn serve(e: *Echo) void {
        var buf: [8]u8 = undefined;
        while (true) {
            var got: usize = 0;
            while (got < buf.len) {
                const n = e.stream.readWait(buf[got..], io_timeout_ns) catch |err| {
                    e.err = err;
                    return;
                };
                if (n == 0) return;
                got += n;
            }
            const sent = std.mem.readInt(i64, &buf, .little);
            const lat = e.clock.now() - sent;
            if (e.count < e.samples.len) e.samples[e.count] = lat;
            e.max_ns = @max(e.max_ns, lat);
            e.sum_ns += lat;
            e.count += 1;
            e.stream.writeAll(&buf, io_timeout_ns) catch |err| {
                e.err = err;
                return;
            };
        }
    }
};

/// One-way latency of interactive round trips while a bulk stream
/// saturates the tunnel. `loss_ppm` applies to `lossy_port` only; the
/// p99 must stay under `p99_bound_ns`.
fn latencyUnderBulk(gpa: std.mem.Allocator, family: Family, loss_ppm: u32, lossy_port: u16, p99_bound_ns: i64) !void {
    const bulk_loss_ppm = loss_ppm;
    const imp: ns.testing.Impairment = .{ .loss_ppm = loss_ppm, .only_port = lossy_port };
    const p = try Pair.create(gpa, family, imp, imp);
    defer p.destroy(gpa);

    const lb = try p.server.stack.listen(port_bulk);
    const li = try p.server.stack.listen(port_main);
    const bulk = try p.connect(lb, port_bulk, .bulk);
    const cb = bulk.c;
    const sb = bulk.s;
    sb.setPriority(.bulk);
    const inter = try p.connect(li, port_main, .interactive);
    const ci = inter.c;
    const si = inter.s;

    // Bulk: server -> client, saturating; the client drains it.
    var bulk_tx: Bulk = .{ .stream = sb };
    var bulk_rx: Bulk = .{ .stream = cb };
    const tx = try std.Thread.spawn(.{}, Bulk.send, .{&bulk_tx});
    const rx = try std.Thread.spawn(.{}, Bulk.drain, .{&bulk_rx});
    const echo = try gpa.create(Echo);
    defer gpa.destroy(echo);
    echo.* = .{ .stream = si, .clock = &p.clock };
    const eth = try std.Thread.spawn(.{}, Echo.serve, .{echo});

    // Ping-pong until at least `samples` round trips AND the bulk stream
    // has moved `bulk_target` bytes meanwhile (the counter is observed
    // between blocking round trips; nothing sleeps).
    var rounds: usize = 0;
    var rtt_max: i64 = 0;
    const samples = 300;
    const bulk_target = 16 * 1024 * 1024;
    var buf: [8]u8 = undefined;
    while (rounds < samples or bulk_rx.bytes.load(.monotonic) < bulk_target) : (rounds += 1) {
        const sent = p.clock.now();
        std.mem.writeInt(i64, &buf, sent, .little);
        try ci.writeAll(&buf, io_timeout_ns);
        var got: usize = 0;
        while (got < buf.len) {
            const n = try ci.readWait(buf[got..], io_timeout_ns);
            if (n == 0) return error.EchoClosed;
            got += n;
        }
        rtt_max = @max(rtt_max, p.clock.now() - sent);
    }
    bulk_tx.stop.store(true, .release);
    ci.shutdown();
    tx.join();
    rx.join();
    eth.join();
    if (bulk_tx.err) |e| return e;
    if (bulk_rx.err) |e| return e;
    if (echo.err) |e| return e;
    const bulk_bytes_during = bulk_rx.bytes.load(.monotonic);

    const avg = @divTrunc(echo.sum_ns, @as(i64, @intCast(@max(echo.count, 1))));
    std.debug.print(
        \\
        \\netstack latency under bulk ({t}, {d} ppm loss on port {d}): {d} samples, one-way avg {d} us, p99 {d} us, max {d} us, echo RTT max {d} us; bulk moved {d} MiB; probes {d}+{d}, rto {d}+{d}
        \\
    , .{
        family,
        bulk_loss_ppm,
        lossy_port,
        echo.count,
        @divTrunc(avg, 1000),
        @divTrunc(echo.percentile(99), 1000),
        @divTrunc(echo.max_ns, 1000),
        @divTrunc(rtt_max, 1000),
        bulk_bytes_during / (1024 * 1024),
        p.client.stack.stats().tail_loss_probes,
        p.server.stack.stats().tail_loss_probes,
        p.client.stack.stats().rto_expirations,
        p.server.stack.stats().rto_expirations,
    });
    try t.expectEqual(rounds, echo.count);
    try t.expect(bulk_bytes_during >= bulk_target);
    try t.expect(echo.percentile(99) < p99_bound_ns);
    ci.close();
    si.close();
    cb.close();
    sb.close();
}

test "e2e: interactive latency stays low under a saturating bulk stream (no loss)" {
    try latencyUnderBulk(t.allocator, .v4, 0, port_bulk, 20 * std.time.ns_per_ms);
}

test "e2e: interactive latency under 1 RTO with 1% loss on the bulk stream" {
    try latencyUnderBulk(t.allocator, .v4, 5_000, port_bulk, 200 * std.time.ns_per_ms);
}

test "e2e IPv6: interactive latency stays low under a saturating bulk stream (no loss)" {
    try latencyUnderBulk(t.allocator, .v6, 0, port_bulk, 20 * std.time.ns_per_ms);
}

test "e2e IPv6: interactive latency with 1% loss on the bulk stream" {
    try latencyUnderBulk(t.allocator, .v6, 5_000, port_bulk, 200 * std.time.ns_per_ms);
}

test "e2e: lost keystrokes are repaired by the tail loss probe (1% loss on the interactive stream)" {
    // 0.5% at each of two impairment points per direction: ~1% per packet.
    // Without TLP the p99 is one 200 ms RTO; with it, ~max(2 SRTT, 10 ms).
    try latencyUnderBulk(t.allocator, .v4, 5_000, port_main, 60 * std.time.ns_per_ms);
}

test "e2e IPv6: lost keystrokes are repaired by the tail loss probe (1% loss on the interactive stream)" {
    try latencyUnderBulk(t.allocator, .v6, 5_000, port_main, 60 * std.time.ns_per_ms);
}

test "e2e: Node (device + stack + threads) with the std.Io Reader / Writer adapters" {
    const gpa = t.allocator;
    var clock: dev.device.Clock = .{ .io = t.io };
    var ks: wg.crypto.PrivateKey = undefined;
    var kc: wg.crypto.PrivateKey = undefined;
    t.io.random(&ks);
    t.io.random(&kc);
    wg.crypto.clampPrivateKey(&ks);
    wg.crypto.clampPrivateKey(&kc);
    defer wg.crypto.wipe(&ks);
    defer wg.crypto.wipe(&kc);
    const server_cidr = [_]dev.ip.Cidr{try dev.ip.Cidr.parse("10.8.0.1/32")};
    const client_cidr = [_]dev.ip.Cidr{try dev.ip.Cidr.parse("10.8.0.2/32")};
    const server = try ns.Node.start(gpa, &clock, .{
        .private_key = ks,
        .loopback_only = true,
        .peers = &.{.{ .public_key = wg.crypto.publicKey(kc), .allowed_ips = &client_cidr }},
    }, .{ .address = server_addr });
    defer server.destroy();
    const client = try ns.Node.start(gpa, &clock, .{
        .private_key = kc,
        .loopback_only = true,
        .peers = &.{.{ .public_key = wg.crypto.publicKey(ks), .allowed_ips = &server_cidr, .endpoint = .{ .ip4 = .loopback(server.device.listen_port) } }},
    }, .{ .address = client_addr });
    defer client.destroy();

    // The ready callback fires (stack thread) when the connection arrives.
    const Flag = struct {
        hits: std.atomic.Value(u32) = .init(0),
        fn ready(ctx: ?*anyopaque) void {
            const f: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = f.hits.fetchAdd(1, .monotonic);
        }
    };
    var flag: Flag = .{};
    server.stack.setReadyCallback(&flag, Flag.ready);

    const l = try server.stack.listen(port_main);
    const c = try client.stack.dialWait(.{ .addr = server_addr, .port = port_main }, 20 * std.time.ns_per_s);
    const s = try l.acceptWait(5 * std.time.ns_per_s);
    try t.expect(flag.hits.load(.monotonic) > 0);
    try t.expectEqual(client_addr.v4, s.remote().addr.v4);
    try t.expectEqual(port_main, c.remote().port);

    var wbuf: [64]u8 = undefined;
    var w = c.writer(&wbuf, 5 * std.time.ns_per_s);
    try w.interface.print("hello over {s}\n", .{"netstack"});
    try w.interface.flush();
    c.shutdown();

    var rbuf: [64]u8 = undefined;
    var r = s.reader(&rbuf, 5 * std.time.ns_per_s);
    const line = try r.interface.take(20);
    try t.expectEqualStrings("hello over netstack\n", line);
    try t.expectError(error.EndOfStream, r.interface.takeByte());

    s.close();
    c.close();
    l.close();
}
