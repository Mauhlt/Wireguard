//! In-process integration test: two Devices, each on a FakeTun, talking
//! real UDP over 127.0.0.1. Handshake, data both ways, inbound source check,
//! endpoint roaming, and rekey after simulated time.

const std = @import("std");
const testing = std.testing;
const crypto = @import("../crypto.zig");
const tun = @import("../tun/root.zig");
const ip = @import("ip.zig");
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

    var priv_a: crypto.PrivateKey = undefined;
    var priv_b: crypto.PrivateKey = undefined;
    testing.io.random(&priv_a);
    testing.io.random(&priv_b);
    crypto.clampPrivateKey(&priv_a);
    crypto.clampPrivateKey(&priv_b);
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
