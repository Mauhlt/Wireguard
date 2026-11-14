//! In-process integration test: two Devices, each on a FakeTun, talking
//! real UDP over 127.0.0.1. Handshake, data both ways, inbound source check,
//! endpoint roaming, and rekey after simulated time.

const std = @import("std");
const testing = std.testing;
const crypto = @import("../crypto.zig");
const tun = @import("../tun/root.zig");
const ip = @import("../ip.zig");
const dev = @import("device.zig");
const os = @import("os.zig");

const Device = dev.Device;

fn ipv4Packet(buf: []u8, src: [4]u8, dst: [4]u8, payload: []const u8) []u8 {
    const total = 20 + payload.len;
    @memset(buf[0..20], 0);
    buf[0] = 0x45;
    std.mem.writeInt(u16, buf[2..4], @intCast(total), .big);
    buf[8] = 64;
    buf[9] = 17;
    buf[12..16].* = src;
    buf[16..20].* = dst;
    @memcpy(buf[20..total], payload);
    return buf[0..total];
}

const Node = struct {
    fake: tun.FakeTun,
    device: *Device,
    thread: ?std.Thread = null,

    fn start(n: *Node) !void {
        n.thread = try std.Thread.spawn(.{}, runLoop, .{n.device});
    }

    fn runLoop(d: *Device) void {
        d.run() catch |err| std.debug.print("device loop ended: {s}\n", .{@errorName(err)});
    }

    fn halt(n: *Node) void {
        if (n.thread) |t| {
            n.device.stop();
            t.join();
            n.device.stop_requested.store(false, .release);
            n.thread = null;
        }
    }
};

fn expectDelivered(to: *Node, want: []const u8) !void {
    var buf: [2048]u8 = undefined;
    const got = (try to.fake.takeWait(&buf, 3000)) orelse return error.PacketNotDelivered;
    try testing.expectEqualSlices(u8, want, got);
}

test "two devices: handshake, both directions, source check, roaming, rekey" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };

    const priv_a = crypto.generatePrivateKey(testing.io);
    const priv_b = crypto.generatePrivateKey(testing.io);
    const pub_a = crypto.publicKey(priv_a);
    const pub_b = crypto.publicKey(priv_b);

    // B: the hub (10.8.0.1), no endpoint for A: it learns it from A's handshake.
    var b: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer b.fake.deinit();
    b.device = try Device.create(gpa, &clock, b.fake.tun(), .{
        .private_key = priv_b,
        .peers = &.{.{ .public_key = pub_a, .allowed_ips = &.{try ip.Cidr.parse("10.8.0.2/32")} }},
    });
    defer b.device.destroy();

    // A: the laptop (10.8.0.2), endpoint = B on loopback.
    var a: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer a.fake.deinit();
    a.device = try Device.create(gpa, &clock, a.fake.tun(), .{
        .private_key = priv_a,
        .peers = &.{.{
            .public_key = pub_b,
            .endpoint = .{ .ip4 = .loopback(b.device.listen_port) },
            .allowed_ips = &.{try ip.Cidr.parse("10.8.0.1/32")},
        }},
    });
    defer a.device.destroy();

    try a.start();
    defer a.halt();
    try b.start();
    defer b.halt();

    var pbuf: [256]u8 = undefined;
    // A -> B: the first packet waits for the handshake, then arrives.
    const p1 = ipv4Packet(&pbuf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "hello from the laptop");
    try a.fake.inject(p1);
    try expectDelivered(&b, p1);

    // B -> A: B learned A's endpoint from the handshake.
    var qbuf: [256]u8 = undefined;
    const p2 = ipv4Packet(&qbuf, .{ 10, 8, 0, 1 }, .{ 10, 8, 0, 2 }, "hello back from the desktop");
    try b.fake.inject(p2);
    try expectDelivered(&a, p2);

    // Several in a row, both ways.
    for (0..20) |i| {
        var x: [64]u8 = undefined;
        const pa = ipv4Packet(&x, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, &.{ @intCast(i), 1, 2, 3 });
        try a.fake.inject(pa);
        try expectDelivered(&b, pa);
        const pb = ipv4Packet(&x, .{ 10, 8, 0, 1 }, .{ 10, 8, 0, 2 }, &.{ @intCast(i), 4, 5 });
        try b.fake.inject(pb);
        try expectDelivered(&a, pb);
    }

    // A packet whose inner source is not in A's allowed IPs (on B) is
    // dropped by B's source check, even though it decrypts.
    {
        var x: [64]u8 = undefined;
        try a.fake.inject(ipv4Packet(&x, .{ 10, 9, 9, 9 }, .{ 10, 8, 0, 1 }, "spoofed"));
        var r: [256]u8 = undefined;
        try testing.expectEqual(@as(?[]u8, null), try b.fake.takeWait(&r, 300));
        // No route on A for an unknown destination: dropped before encryption.
        try a.fake.inject(ipv4Packet(&x, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 77 }, "nowhere"));
        try testing.expectEqual(@as(?[]u8, null), try b.fake.takeWait(&r, 100));
    }

    // Roaming: A moves to a new UDP port; B follows A's authenticated packets.
    a.halt();
    b.halt();
    try testing.expectEqual(@as(u64, 1), b.device.stats.dropped_source_check);
    try testing.expectEqual(@as(u64, 1), a.device.stats.dropped_no_route);
    const old_port = a.device.listen_port;
    try a.device.rebind(0);
    try testing.expect(a.device.listen_port != old_port);
    try a.start();
    try b.start();
    const p3 = ipv4Packet(&pbuf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "from a new port");
    try a.fake.inject(p3);
    try expectDelivered(&b, p3);
    const p4 = ipv4Packet(&qbuf, .{ 10, 8, 0, 1 }, .{ 10, 8, 0, 2 }, "reply to the new port");
    try b.fake.inject(p4);
    try expectDelivered(&a, p4);
    // A answers, so B has no unanswered data (its 15 s new-handshake timer
    // would otherwise make it initiate at the same simulated instant as A's
    // rekey below, and simultaneous initiations cancel each other until a
    // jittered retry).
    const p5 = ipv4Packet(&pbuf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "ack");
    try a.fake.inject(p5);
    try expectDelivered(&b, p5);
    b.halt();
    a.halt();
    const b_peer = b.device.peerByKey(pub_a).?;
    try testing.expectEqual(a.device.listen_port, b_peer.endpoint.?.getPort());

    // Rekey: after REKEY_AFTER_TIME the initiator's next send starts a new
    // handshake; traffic keeps flowing and the keypair changes.
    const a_peer = a.device.peerByKey(pub_b).?;
    const old_index = a_peer.sess.keypairs.current.?.local_index;
    clock.advance(125 * std.time.ns_per_s);
    try a.start();
    try b.start();
    for (0..5) |i| {
        var x: [64]u8 = undefined;
        const pa = ipv4Packet(&x, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, &.{ @intCast(i), 9 });
        try a.fake.inject(pa);
        try expectDelivered(&b, pa);
        const pb = ipv4Packet(&x, .{ 10, 8, 0, 1 }, .{ 10, 8, 0, 2 }, &.{ @intCast(i), 8 });
        try b.fake.inject(pb);
        try expectDelivered(&a, pb);
    }
    // If the rekey handshake is still in flight, let simulated time pass
    // (retransmission after REKEY_TIMEOUT) until the new keypair is in use.
    var rounds: usize = 0;
    while (true) : (rounds += 1) {
        a.halt();
        b.halt();
        const cur = a_peer.sess.keypairs.current;
        if (cur != null and cur.?.local_index != old_index) break;
        if (rounds == 10) break;
        clock.advance(6 * std.time.ns_per_s);
        try a.start();
        try b.start();
        var x: [64]u8 = undefined;
        const pa = ipv4Packet(&x, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "after rekey");
        try a.fake.inject(pa);
        try expectDelivered(&b, pa);
        const pb = ipv4Packet(&x, .{ 10, 8, 0, 1 }, .{ 10, 8, 0, 2 }, "after rekey too");
        try b.fake.inject(pb);
        try expectDelivered(&a, pb);
    }
    try testing.expect(a_peer.sess.keypairs.current.?.local_index != old_index);
    try testing.expect(a_peer.rx_bytes > 0 and a_peer.tx_bytes > 0);
    try testing.expect(a_peer.last_handshake_wall_ns != null);
}

test "under load: handshakes without a cookie get a cookie reply" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var priv: crypto.PrivateKey = undefined;
    testing.io.random(&priv);
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{ .private_key = priv });
    defer d.destroy();

    // A well-formed initiation (valid mac1, from a peer the device does not
    // know), replayed enough times to put the device under load.
    var other: crypto.PrivateKey = undefined;
    testing.io.random(&other);
    const noise = @import("../noise/root.zig");
    var local_other = noise.Local.init(other);
    defer local_other.wipe();
    var hs = noise.Handshake.init(&local_other, d.local.public, @splat(0));
    defer hs.wipe();
    var prng = std.Random.DefaultPrng.init(3);
    const msg = try hs.createInitiation(&local_other, clock.wall(), clock.now(), 77, prng.random());
    var bytes = msg.asBytes().*;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(9) };
    const now = clock.now();
    for (0..d.load.threshold + 5) |_| d.handleDatagram(&bytes, from, now);
    try testing.expect(d.load.underLoad(now));
    try testing.expect(d.stats.cookie_replies_sent >= 5);
}

test "load: datagrams with a wrong mac1 are dropped and never count towards load" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var priv: crypto.PrivateKey = undefined;
    testing.io.random(&priv);
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{ .private_key = priv });
    defer d.destroy();

    // Initiation- and response-sized junk with the right type byte, from a
    // stranger who does not know our public key: far above the threshold.
    const noise = @import("../noise/root.zig");
    var init_junk: [noise.Initiation.size]u8 = undefined;
    var resp_junk: [noise.Response.size]u8 = undefined;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(9) };
    const now = clock.now();
    for (0..d.load.threshold * 4) |i| {
        testing.io.random(&init_junk);
        testing.io.random(&resp_junk);
        init_junk[0..4].* = .{ 1, 0, 0, 0 };
        resp_junk[0..4].* = .{ 2, 0, 0, 0 };
        d.handleDatagram(if (i % 2 == 0) &init_junk else &resp_junk, from, now);
    }
    try testing.expect(!d.load.underLoad(now));
    try testing.expectEqual(@as(u64, 0), d.stats.cookie_replies_sent);
    try testing.expectEqual(@as(u64, d.load.threshold * 4), d.stats.dropped_invalid);

    // A sender that knows our key (valid mac1) still gets an answer without
    // a cookie round trip: the junk did not put the device under load.
    var other: crypto.PrivateKey = undefined;
    testing.io.random(&other);
    var local_other = noise.Local.init(other);
    defer local_other.wipe();
    var hs = noise.Handshake.init(&local_other, d.local.public, @splat(0));
    defer hs.wipe();
    var prng = std.Random.DefaultPrng.init(4);
    const msg = try hs.createInitiation(&local_other, clock.wall(), clock.now(), 78, prng.random());
    var bytes = msg.asBytes().*;
    d.handleDatagram(&bytes, from, now);
    try testing.expectEqual(@as(u64, 0), d.stats.cookie_replies_sent);
}

test "bind: an IPv6 port already held by another socket fails the device" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var priv: crypto.PrivateKey = undefined;
    testing.io.random(&priv);
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    // A host without IPv6 loopback cannot run this check.
    var squatter = os.Udp.open(.v6, 0) catch |err| switch (err) {
        error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer squatter.close();
    const port = squatter.localPort();
    try testing.expectError(error.AddressInUse, Device.create(gpa, &clock, fake.tun(), .{ .private_key = priv, .listen_port = port }));

    // With an ephemeral port the device just picks another pair.
    const d = try Device.create(gpa, &clock, fake.tun(), .{ .private_key = priv });
    defer d.destroy();
    try testing.expect(d.udp4 != null and d.udp6 != null);
}

test "first initiation since start does not move a known endpoint (replay after restart)" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    const noise = @import("../noise/root.zig");
    var priv: crypto.PrivateKey = undefined;
    testing.io.random(&priv);
    var peer_priv: crypto.PrivateKey = undefined;
    testing.io.random(&peer_priv);
    var peer_local = noise.Local.init(peer_priv);
    defer peer_local.wipe();
    const known: std.Io.net.IpAddress = .{ .ip4 = .loopback(9) };
    const elsewhere: std.Io.net.IpAddress = .{ .ip4 = .loopback(10) };
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{
        .private_key = priv,
        .peers = &.{.{ .public_key = peer_local.public, .endpoint = known }},
    });
    defer d.destroy();
    const p = d.peerByKey(peer_local.public).?;

    var hs = noise.Handshake.init(&peer_local, d.local.public, @splat(0));
    defer hs.wipe();
    var prng = std.Random.DefaultPrng.init(5);
    const now = clock.now();
    // A valid initiation (as an observer could have recorded it before a
    // restart) from another address: answered, but the endpoint stays.
    const m1 = try hs.createInitiation(&peer_local, clock.wall(), now, 91, prng.random());
    var b1 = m1.asBytes().*;
    d.handleDatagram(&b1, elsewhere, now);
    try testing.expect(!crypto.isZero(crypto.tai64n_len, &p.hs.latest_timestamp));
    try testing.expect(p.endpoint.?.eql(&known));
    // With a timestamp on record, a newer initiation roams as usual.
    const later = now + std.time.ns_per_s;
    const m2 = try hs.createInitiation(&peer_local, clock.wall() + std.time.ns_per_s, later, 92, prng.random());
    var b2 = m2.asBytes().*;
    d.handleDatagram(&b2, elsewhere, later);
    try testing.expect(p.endpoint.?.eql(&elsewhere));
}

test "run returns when the external stop handle (zwg down) is signaled" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var priv: crypto.PrivateKey = undefined;
    testing.io.random(&priv);
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{ .private_key = priv });
    defer d.destroy();
    var stop = try os.StopSignal.create("zwg-test-run-stop");
    defer stop.close();
    d.external_stop = stop.waitHandle();
    const t = try std.Thread.spawn(.{}, Node.runLoop, .{d});
    stop.signal();
    t.join();
}

test "control hook runs on the loop thread when its handle is signaled" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    var priv: crypto.PrivateKey = @splat(9);
    crypto.clampPrivateKey(&priv);
    const d = try Device.create(gpa, &clock, fake.tun(), .{
        .private_key = priv,
        .peers = &.{.{ .public_key = @splat(7), .allowed_ips = &.{try ip.Cidr.parse("10.9.0.2/32")} }},
    });
    defer d.destroy();

    const Ctx = struct {
        request: tun.queue.Waker,
        done: tun.queue.Waker,
        calls: u32 = 0,
        peers: usize = 0,
        fn ready(ctx: *anyopaque, dv: *Device) void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.request.clear();
            c.calls += 1;
            c.peers = dv.peers.items.len;
            c.done.signal();
        }
    };
    var ctx: Ctx = .{ .request = try .init(), .done = try .init() };
    defer ctx.request.deinit();
    defer ctx.done.deinit();
    d.control = .{ .handle = ctx.request.handle, .ctx = &ctx, .ready = Ctx.ready };

    const t = try std.Thread.spawn(.{}, Device.run, .{d});
    for (1..4) |i| {
        ctx.request.signal();
        try testing.expectEqual(@as(?usize, 0), try os.wait(&.{ctx.done.handle}, 2 * std.time.ns_per_s));
        ctx.done.clear();
        try testing.expectEqual(@as(u32, @intCast(i)), ctx.calls);
    }
    try testing.expectEqual(@as(usize, 1), ctx.peers);
    d.stop();
    t.join();
}

/// Endpoint names in tests: every name resolves to 127.0.0.1:<port>, where
/// the port is whatever the test points it at (0: fail).
const FakeDns = struct {
    port: std.atomic.Value(u16) = .init(0),
    calls: std.atomic.Value(u32) = .init(0),

    fn lookup(ctx: ?*anyopaque, io: std.Io, host: []const u8, port: u16) anyerror!std.Io.net.IpAddress {
        _ = io;
        _ = host;
        _ = port;
        const f: *FakeDns = @ptrCast(@alignCast(ctx.?));
        _ = f.calls.fetchAdd(1, .monotonic);
        const p = f.port.load(.monotonic);
        if (p == 0) return error.UnknownHostName;
        return .{ .ip4 = .loopback(p) };
    }
};

fn keyPair() struct { priv: crypto.PrivateKey, public: crypto.PublicKey } {
    const priv = crypto.generatePrivateKey(testing.io);
    return .{ .priv = priv, .public = crypto.publicKey(priv) };
}

// Outlive their tests: a lookup thread may still be finishing.
var dns_at_start: FakeDns = .{};
var dns_moved: FakeDns = .{};

test "endpoint name not resolvable at start: looked up again, then the tunnel comes up" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    const ka = keyPair();
    const kb = keyPair();

    var b: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer b.fake.deinit();
    b.device = try Device.create(gpa, &clock, b.fake.tun(), .{
        .private_key = kb.priv,
        .peers = &.{.{ .public_key = ka.public, .allowed_ips = &.{try ip.Cidr.parse("10.8.0.2/32")} }},
    });
    defer b.device.destroy();

    // A's endpoint is a name that did not resolve at start (endpoint null);
    // the first retry inside the device fails too, the next one works.
    var a: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer a.fake.deinit();
    a.device = try Device.create(gpa, &clock, a.fake.tun(), .{
        .private_key = ka.priv,
        .peers = &.{.{
            .public_key = kb.public,
            .endpoint_name = .{ .host = "home.example.org", .port = 51820 },
            .allowed_ips = &.{try ip.Cidr.parse("10.8.0.1/32")},
            .persistent_keepalive = 25,
        }},
        .lookup = .{ .ctx = &dns_at_start, .func = FakeDns.lookup },
    });
    defer a.device.destroy();

    try b.start();
    defer b.halt();
    try a.start();
    defer a.halt();

    var pbuf: [128]u8 = undefined;
    const p1 = ipv4Packet(&pbuf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "after the name resolved");
    var rounds: usize = 0;
    var delivered = false;
    var r: [256]u8 = undefined;
    while (!delivered and rounds < 20) : (rounds += 1) {
        a.halt();
        // From the second round on, DNS works; the failure backoff (1 s,
        // 2 s, ...) is waited out on simulated time.
        if (rounds == 1) dns_at_start.port.store(b.device.listen_port, .monotonic);
        clock.advance(3 * std.time.ns_per_s);
        try a.start();
        try a.fake.inject(p1);
        if (try b.fake.takeWait(&r, 300)) |got| {
            try testing.expectEqualSlices(u8, p1, got);
            delivered = true;
        }
    }
    try testing.expect(delivered);
    a.halt();
    try testing.expect(dns_at_start.calls.load(.monotonic) >= 2);
    try testing.expect(a.device.stats.endpoint_lookup_failures >= 1);
    try testing.expectEqual(b.device.listen_port, a.device.peerByKey(kb.public).?.endpoint.?.getPort());
}

test "endpoint name moved (dynamic DNS): unanswered handshakes look it up again" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    const ka = keyPair();
    const kb = keyPair();

    var b: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer b.fake.deinit();
    b.device = try Device.create(gpa, &clock, b.fake.tun(), .{
        .private_key = kb.priv,
        .peers = &.{.{ .public_key = ka.public, .allowed_ips = &.{try ip.Cidr.parse("10.8.0.2/32")} }},
    });
    defer b.device.destroy();

    // The address the name resolved to at start: a socket that swallows
    // everything (the desk's old address). The name now points at B.
    var old = try os.Udp.open(.v4, 0);
    defer old.close();
    dns_moved.port.store(b.device.listen_port, .monotonic);

    var a: Node = .{ .fake = try .init(gpa, .{}), .device = undefined };
    defer a.fake.deinit();
    a.device = try Device.create(gpa, &clock, a.fake.tun(), .{
        .private_key = ka.priv,
        .peers = &.{.{
            .public_key = kb.public,
            .endpoint = .{ .ip4 = .loopback(old.localPort()) },
            .endpoint_name = .{ .host = "home.example.org", .port = 51820 },
            .allowed_ips = &.{try ip.Cidr.parse("10.8.0.1/32")},
        }},
        .lookup = .{ .ctx = &dns_moved, .func = FakeDns.lookup },
    });
    defer a.device.destroy();

    try b.start();
    defer b.halt();
    try a.start();
    defer a.halt();

    var pbuf: [128]u8 = undefined;
    const p1 = ipv4Packet(&pbuf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "to the new address");
    try a.fake.inject(p1); // staged; the initiation goes to the old address
    var r: [256]u8 = undefined;
    try testing.expectEqual(@as(?[]u8, null), try b.fake.takeWait(&r, 200));
    try testing.expectEqual(@as(u32, 0), dns_moved.calls.load(.monotonic)); // answered so far: not looked up

    // Retransmissions (REKEY_TIMEOUT + jitter) on simulated time: the first
    // looks the name up, a later one reaches B and the staged packet flows.
    var rounds: usize = 0;
    var delivered = false;
    while (!delivered and rounds < 10) : (rounds += 1) {
        a.halt();
        clock.advance(6 * std.time.ns_per_s);
        try a.start();
        if (try b.fake.takeWait(&r, 500)) |got| {
            try testing.expectEqualSlices(u8, p1, got);
            delivered = true;
        }
    }
    try testing.expect(delivered);
    a.halt();
    try testing.expect(dns_moved.calls.load(.monotonic) >= 1);
    try testing.expectEqual(@as(u64, 1), a.device.stats.endpoint_updates);
    try testing.expectEqual(b.device.listen_port, a.device.peerByKey(kb.public).?.endpoint.?.getPort());
}

// ---- setPeers: the peer table replaced while the tunnel runs -------------

const config = @import("config.zig");

fn cidrOf(s: []const u8) ip.Cidr {
    return ip.Cidr.parse(s) catch unreachable;
}

fn addrOf(s: []const u8) ip.Addr {
    return ip.Addr.parse(s) catch unreachable;
}

/// A (10.8.0.2, endpoint = B) and B (10.8.0.1, the hub), both running on
/// loopback; B starts with `b_peers` and allocates from `b_gpa`.
const Pair = struct {
    ka: @TypeOf(keyPair()),
    kb: @TypeOf(keyPair()),
    psk: ?crypto.PresharedKey = null,
    a: Node = undefined,
    b: Node = undefined,

    fn init(p: *Pair, b_gpa: std.mem.Allocator, clock: *dev.Clock, b_peers: []const dev.PeerConfig) !void {
        const gpa = testing.allocator;
        p.b = .{ .fake = try .init(gpa, .{}), .device = undefined };
        errdefer p.b.fake.deinit();
        p.b.device = try Device.create(b_gpa, clock, p.b.fake.tun(), .{ .private_key = p.kb.priv, .loopback_only = true, .peers = b_peers });
        errdefer p.b.device.destroy();
        p.a = .{ .fake = try .init(gpa, .{}), .device = undefined };
        errdefer p.a.fake.deinit();
        p.a.device = try Device.create(gpa, clock, p.a.fake.tun(), .{
            .private_key = p.ka.priv,
            .loopback_only = true,
            .peers = &.{.{
                .public_key = p.kb.public,
                .preshared_key = p.psk,
                .endpoint = .{ .ip4 = .loopback(p.b.device.listen_port) },
                .allowed_ips = &.{cidrOf("10.8.0.0/16")},
            }},
        });
        errdefer p.a.device.destroy();
        try p.a.start();
        try p.b.start();
    }

    fn deinit(p: *Pair) void {
        p.a.halt();
        p.b.halt();
        p.a.device.destroy();
        p.a.fake.deinit();
        p.b.device.destroy();
        p.b.fake.deinit();
    }

    fn aToB(p: *Pair, payload: []const u8) !void {
        var buf: [256]u8 = undefined;
        const pkt = ipv4Packet(&buf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, payload);
        try p.a.fake.inject(pkt);
        try expectDelivered(&p.b, pkt);
    }

    fn bToA(p: *Pair, dst: [4]u8, payload: []const u8) !void {
        var buf: [256]u8 = undefined;
        const pkt = ipv4Packet(&buf, .{ 10, 8, 0, 1 }, dst, payload);
        try p.b.fake.inject(pkt);
        try expectDelivered(&p.a, pkt);
    }

    /// A's packet to B does not come out of B's TUN.
    fn aToBRefused(p: *Pair, payload: []const u8) !void {
        var buf: [256]u8 = undefined;
        try p.a.fake.inject(ipv4Packet(&buf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, payload));
        var r: [256]u8 = undefined;
        try testing.expectEqual(@as(?[]u8, null), try p.b.fake.takeWait(&r, 300));
    }
};

test "setPeers: a peer added to a running device can handshake" {
    var clock: dev.Clock = .{ .io = testing.io };
    var p: Pair = .{ .ka = keyPair(), .kb = keyPair() };
    try p.init(testing.allocator, &clock, &.{}); // B knows nobody yet
    defer p.deinit();

    // Unknown to B: A's initiation is dropped, its packet waits on A.
    try p.aToBRefused("before the peer was added");
    const a_ips = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    try p.b.device.setPeers(&.{.{ .public_key = p.ka.public, .allowed_ips = &a_ips }});

    // A's retransmission (REKEY_TIMEOUT, simulated) now completes and the
    // packet that waited is delivered, then traffic flows both ways.
    clock.advance(6 * std.time.ns_per_s);
    p.a.device.kick();
    var buf: [256]u8 = undefined;
    try expectDelivered(&p.b, ipv4Packet(&buf, .{ 10, 8, 0, 2 }, .{ 10, 8, 0, 1 }, "before the peer was added"));
    try p.aToB("after");
    try p.bToA(.{ 10, 8, 0, 2 }, "and back");
    p.b.halt();
    try testing.expectEqual(@as(usize, 1), p.b.device.peers.items.len);
    try testing.expect(p.b.device.stats.dropped_invalid >= 1);
    try testing.expect(p.b.device.peerByKey(p.ka.public).?.sess.keypairs.current != null);
}

test "setPeers: a removed peer's packets are refused and its key material is wiped" {
    var clock: dev.Clock = .{ .io = testing.io };
    var psk: crypto.PresharedKey = undefined;
    testing.io.random(&psk);
    var spy: config.FreeSpy = .{ .needles = &.{} };
    var p: Pair = .{ .ka = keyPair(), .kb = keyPair(), .psk = psk };
    const a_ips = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    try p.init(spy.allocator(), &clock, &.{.{ .public_key = p.ka.public, .preshared_key = psk, .allowed_ips = &a_ips }});
    defer p.deinit();
    try p.aToB("hello");
    try p.bToA(.{ 10, 8, 0, 2 }, "hello back");

    // The secrets B holds for A: session keys, the PSK, the static DH.
    p.b.halt();
    const peer = p.b.device.peerByKey(p.ka.public).?;
    const kp = peer.sess.keypairs.current.?;
    const send = kp.send_key;
    const recv = kp.recv_key;
    const ss = peer.hs.precomputed_static_static;
    const needles = [_][]const u8{ &send, &recv, &psk, &ss };
    spy.needles = &needles;
    try p.b.start();

    try p.b.device.setPeers(&.{});
    try testing.expect(!spy.leaked);
    try p.aToBRefused("after the peer was removed");
    p.b.halt();
    try testing.expectEqual(@as(usize, 0), p.b.device.peers.items.len);
    try testing.expectEqual(@as(?*dev.Peer, null), p.b.device.peerByKey(p.ka.public));
    try testing.expectEqual(@as(usize, 0), p.b.device.indices.count());
    try testing.expectEqual(@as(?u32, null), p.b.device.routes.lookup(addrOf("10.8.0.2")));
}

test "setPeers: an unchanged peer keeps its session (no new handshake), ids shift" {
    var clock: dev.Clock = .{ .io = testing.io };
    var p: Pair = .{ .ka = keyPair(), .kb = keyPair() };
    const a_ips = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    try p.init(testing.allocator, &clock, &.{.{ .public_key = p.ka.public, .allowed_ips = &a_ips }});
    defer p.deinit();
    try p.aToB("one");
    try p.bToA(.{ 10, 8, 0, 2 }, "two");
    p.a.halt();
    p.b.halt();
    const on_b = p.b.device.peerByKey(p.ka.public).?;
    const on_a = p.a.device.peerByKey(p.kb.public).?;
    const b_index = on_b.sess.keypairs.current.?.local_index;
    const a_index = on_a.sess.keypairs.current.?.local_index;
    const a_handshake = on_a.last_handshake_wall_ns;
    const rx = on_b.rx_bytes;
    try p.a.start();
    try p.b.start();

    // A new peer in front (A's id becomes 1) and one more prefix for A.
    const c = keyPair();
    const c_ips = [_]ip.Cidr{cidrOf("10.8.5.0/24")};
    const a_ips2 = [_]ip.Cidr{ cidrOf("10.8.0.2/32"), cidrOf("10.8.1.0/24") };
    try p.b.device.setPeers(&.{
        .{ .public_key = c.public, .allowed_ips = &c_ips },
        .{ .public_key = p.ka.public, .allowed_ips = &a_ips2 },
    });
    try p.aToB("three");
    try p.bToA(.{ 10, 8, 0, 2 }, "four");
    try p.bToA(.{ 10, 8, 1, 5 }, "to the new prefix");
    p.a.halt();
    p.b.halt();
    try testing.expectEqual(on_b, p.b.device.peerByKey(p.ka.public).?);
    try testing.expectEqual(@as(dev.PeerId, 1), on_b.id);
    try testing.expectEqual(b_index, on_b.sess.keypairs.current.?.local_index);
    try testing.expectEqual(a_index, on_a.sess.keypairs.current.?.local_index);
    try testing.expectEqual(a_handshake, on_a.last_handshake_wall_ns);
    try testing.expect(on_b.rx_bytes > rx);
    try testing.expectEqual(@as(?u32, 1), p.b.device.indices.get(b_index).?.peer);
}

test "setPeers: an invalid set changes nothing" {
    const gpa = testing.allocator;
    var clock: dev.Clock = .{ .io = testing.io };
    var p: Pair = .{ .ka = keyPair(), .kb = keyPair() };
    const a_ips = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    const a_cfg: dev.PeerConfig = .{ .public_key = p.ka.public, .allowed_ips = &a_ips };
    try p.init(gpa, &clock, &.{a_cfg});
    defer p.deinit();
    try p.aToB("before");
    p.b.halt();
    const on_b = p.b.device.peerByKey(p.ka.public).?;
    const b_index = on_b.sess.keypairs.current.?.local_index;
    try p.b.start();

    const c = keyPair();
    const e = keyPair();
    const d = p.b.device;
    const c_net = [_]ip.Cidr{cidrOf("10.8.0.0/24")};
    const e_net = [_]ip.Cidr{cidrOf("10.8.0.9/24")}; // the same prefix once masked
    const bad_prefix = [_]ip.Cidr{.{ .addr = .{ .v4 = .{ 10, 8, 0, 0 } }, .prefix = 33 }};
    const many_ips = try gpa.alloc(ip.Cidr, config.max_list_entries + 1);
    defer gpa.free(many_ips);
    for (many_ips, 0..) |*x, i| x.* = .{ .addr = .{ .v4 = .{ 10, 9, @intCast(i >> 8), @truncate(i) } }, .prefix = 32 };
    const many_peers = try gpa.alloc(dev.PeerConfig, config.max_peers + 1);
    defer gpa.free(many_peers);
    for (many_peers, 0..) |*x, i| {
        x.* = .{ .public_key = @splat(0) };
        std.mem.writeInt(u32, x.public_key[0..4], @intCast(i + 1), .little);
    }
    const long_host: [@import("resolver.zig").max_host + 1]u8 = @splat('a');

    // Each would remove A if it were applied.
    try testing.expectError(error.DuplicatePeer, d.setPeers(&.{ .{ .public_key = c.public }, .{ .public_key = c.public } }));
    try testing.expectError(error.OverlappingAllowedIps, d.setPeers(&.{ .{ .public_key = c.public, .allowed_ips = &c_net }, .{ .public_key = e.public, .allowed_ips = &e_net } }));
    try testing.expectError(error.OverlappingAllowedIps, d.setPeers(&.{ a_cfg, .{ .public_key = c.public, .allowed_ips = &a_ips } }));
    try testing.expectError(error.InvalidPeer, d.setPeers(&.{ .{ .public_key = c.public }, .{ .public_key = p.kb.public } }));
    try testing.expectError(error.InvalidPeer, d.setPeers(&.{.{ .public_key = c.public, .allowed_ips = &bad_prefix }}));
    try testing.expectError(error.TooManyAllowedIps, d.setPeers(&.{.{ .public_key = c.public, .allowed_ips = many_ips }}));
    try testing.expectError(error.TooManyPeers, d.setPeers(many_peers));
    try testing.expectError(error.InvalidHost, d.setPeers(&.{.{ .public_key = c.public, .endpoint_name = .{ .host = "", .port = 1 } }}));
    try testing.expectError(error.InvalidHost, d.setPeers(&.{.{ .public_key = c.public, .endpoint_name = .{ .host = &long_host, .port = 1 } }}));

    p.b.halt();
    try testing.expectEqual(@as(usize, 1), d.peers.items.len);
    try testing.expectEqual(on_b, d.peers.items[0]);
    try testing.expectEqual(@as(dev.PeerId, 0), on_b.id);
    try testing.expectEqual(@as(?dev.PeerId, 0), d.peerByKey(p.ka.public).?.id);
    try testing.expectEqual(@as(?dev.PeerId, null), if (d.peerByKey(c.public)) |x| x.id else null);
    try testing.expectEqual(@as(?u32, 0), d.routes.lookup(addrOf("10.8.0.2")));
    try testing.expectEqual(@as(?u32, null), d.routes.lookup(addrOf("10.8.0.9")));
    try testing.expectEqual(@as(?*@import("resolver.zig").Shared, null), d.resolver);
    try p.b.start();
    try p.aToB("after");
    try p.bToA(.{ 10, 8, 0, 2 }, "and back");
    p.b.halt();
    try testing.expectEqual(b_index, on_b.sess.keypairs.current.?.local_index);
}

test "setPeers: concurrent calls from other threads while traffic flows" {
    var clock: dev.Clock = .{ .io = testing.io };
    var p: Pair = .{ .ka = keyPair(), .kb = keyPair() };
    const a_ips = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    const a_cfg: dev.PeerConfig = .{ .public_key = p.ka.public, .allowed_ips = &a_ips };
    try p.init(testing.allocator, &clock, &.{a_cfg});
    defer p.deinit();
    try p.aToB("warm up");
    p.b.halt();
    const on_b = p.b.device.peerByKey(p.ka.public).?;
    const b_index = on_b.sess.keypairs.current.?.local_index;
    try p.b.start();

    const c = keyPair();
    const e = keyPair();
    const c_ips = [_]ip.Cidr{cidrOf("10.8.7.0/24")};
    const e_ips = [_]ip.Cidr{cidrOf("fd00::7/128")};
    const small = [_]dev.PeerConfig{a_cfg};
    const large = [_]dev.PeerConfig{ .{ .public_key = c.public, .allowed_ips = &c_ips }, a_cfg, .{ .public_key = e.public, .allowed_ips = &e_ips } };

    const Setter = struct {
        fn run(d: *Device, first: []const dev.PeerConfig, second: []const dev.PeerConfig, failures: *std.atomic.Value(u32)) void {
            for (0..60) |i| d.setPeers(if (i % 2 == 0) first else second) catch {
                _ = failures.fetchAdd(1, .monotonic);
            };
        }
    };
    var failures: std.atomic.Value(u32) = .init(0);
    const t1 = try std.Thread.spawn(.{}, Setter.run, .{ p.b.device, @as([]const dev.PeerConfig, &large), @as([]const dev.PeerConfig, &small), &failures });
    const t2 = try std.Thread.spawn(.{}, Setter.run, .{ p.b.device, @as([]const dev.PeerConfig, &small), @as([]const dev.PeerConfig, &large), &failures });
    for (0..30) |i| {
        try p.aToB(&.{ @intCast(i), 1 });
        try p.bToA(.{ 10, 8, 0, 2 }, &.{ @intCast(i), 2 });
    }
    t1.join();
    t2.join();
    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try p.b.device.setPeers(&large);
    try p.aToB("after the storm");
    p.b.halt();
    try testing.expectEqual(on_b, p.b.device.peerByKey(p.ka.public).?);
    try testing.expectEqual(@as(dev.PeerId, 1), on_b.id);
    try testing.expectEqual(b_index, on_b.sess.keypairs.current.?.local_index);
    try testing.expectEqual(@as(usize, 3), p.b.device.peers.items.len);
}

var dns_sweep: FakeDns = .{};

test "setPeers and create: every allocation failure leaves the device unchanged (FailingAllocator sweep)" {
    var clock: dev.Clock = .{ .io = testing.io };
    var fake: tun.FakeTun = try .init(testing.allocator, .{});
    defer fake.deinit();
    const k0 = keyPair();
    const k1 = keyPair();
    const k2 = keyPair();
    const k3 = keyPair();
    const k4 = keyPair();
    const ips1 = [_]ip.Cidr{cidrOf("10.8.0.2/32")};
    const ips2 = [_]ip.Cidr{cidrOf("10.8.0.3/32")};
    const ips2b = [_]ip.Cidr{ cidrOf("10.8.0.3/32"), cidrOf("10.8.3.0/24") };
    const ips3 = [_]ip.Cidr{ cidrOf("10.8.0.4/32"), cidrOf("fd00::4/128") };
    const ips4 = [_]ip.Cidr{cidrOf("10.8.0.5/32")};
    const first = [_]dev.PeerConfig{
        .{ .public_key = k1.public, .allowed_ips = &ips1, .endpoint_name = .{ .host = "one.example", .port = 1 } },
        .{ .public_key = k2.public, .allowed_ips = &ips2 },
    };
    const second = [_]dev.PeerConfig{
        .{ .public_key = k2.public, .allowed_ips = &ips2b, .persistent_keepalive = 25 },
        .{ .public_key = k3.public, .allowed_ips = &ips3, .endpoint_name = .{ .host = "three.example", .port = 3 } },
        .{ .public_key = k4.public, .allowed_ips = &ips4 },
    };
    const options: dev.Options = .{
        .private_key = k0.priv,
        .loopback_only = true,
        .peers = &first,
        .lookup = .{ .ctx = &dns_sweep, .func = FakeDns.lookup },
    };

    // The startup path: fails cleanly at every allocation (no leaks).
    var i: usize = 0;
    while (true) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (Device.create(fa.allocator(), &clock, fake.tun(), options)) |d| {
            d.destroy();
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
    try testing.expect(i > 5);

    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    const d = try Device.create(fa.allocator(), &clock, fake.tun(), options);
    defer d.destroy();
    const p1 = d.peerByKey(k1.public).?;
    const p2 = d.peerByKey(k2.public).?;
    const names = d.resolver.?;
    i = 0;
    while (true) : (i += 1) {
        fa.fail_index = fa.alloc_index + i;
        if (d.setPeers(&second)) |_| break else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(@as(usize, 2), d.peers.items.len);
            try testing.expectEqual(p1, d.peers.items[0]);
            try testing.expectEqual(p2, d.peers.items[1]);
            try testing.expectEqual(@as(dev.PeerId, 1), p2.id);
            try testing.expectEqual(@as(?u32, 0), d.routes.lookup(addrOf("10.8.0.2")));
            try testing.expectEqual(@as(?u32, null), d.routes.lookup(addrOf("10.8.3.1")));
            try testing.expectEqual(@as(?u32, null), d.routes.lookup(addrOf("10.8.0.4")));
            try testing.expectEqual(names, d.resolver.?);
            try testing.expectEqual(@as(u32, 0), p1.resolve.?.slot);
            try testing.expectEqual(@as(u16, 0), p2.persistent_keepalive);
            try testing.expectEqual(@as(usize, 2), d.by_key.count());
        }
    }
    try testing.expect(i > 5);
    fa.fail_index = std.math.maxInt(usize);
    try testing.expectEqual(@as(usize, 3), d.peers.items.len);
    try testing.expectEqual(p2, d.peers.items[0]);
    try testing.expectEqual(@as(dev.PeerId, 0), p2.id);
    try testing.expectEqual(@as(u16, 25), p2.persistent_keepalive);
    try testing.expectEqual(@as(?*dev.Peer, null), d.peerByKey(k1.public));
    try testing.expectEqual(@as(?u32, 0), d.routes.lookup(addrOf("10.8.3.1")));
    try testing.expectEqual(@as(?u32, 1), d.routes.lookup(addrOf("fd00::4")));
    try testing.expectEqual(@as(?u32, null), d.routes.lookup(addrOf("10.8.0.2")));
    try testing.expectEqual(@as(usize, 1), d.resolver.?.slots.len);
    try testing.expectEqual(@as(u32, 0), d.peers.items[1].resolve.?.slot);
    try testing.expect(d.peers.items[0].resolve == null);
}
