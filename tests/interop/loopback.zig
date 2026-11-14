//! Two-process loopback: two real `zwg` processes on 127.0.0.1 talk
//! WireGuard to each other; their TUNs are UdpTun sockets this driver
//! feeds and reads. No Wintun, no admin, any OS.
//!
//!     zwg-interop-loopback <peer A> [<peer B>]    (zig build interop runs
//!     zwg+zwg, refpeer+refpeer and zwg+refpeer)
//!
//! Contract with the device/CLI: `zwg up <conf> --tun udp:<port>` runs the
//! device in the foreground with a UdpTun bound to 127.0.0.1:<port>, and
//! `zwg` (no arguments) prints a usage text that mentions `--tun`. That
//! test mode is only in builds made with -Dtest-tun (`zwg-testtun`); a
//! binary that does not advertise it fails the run.
//!
//!     zwg-interop-loopback --refuses-tun <zwg>
//!
//! checks the opposite for the release build: no `--tun` in the usage, and
//! `zwg up <conf> --tun udp:<port>` is refused as a usage error.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const wg = @import("WireGuard");
const ip = @import("ip.zig");
const drive = @import("drive.zig");
const tun = wg.tun;

const addr_a = [4]u8{ 10, 88, 0, 1 };
const addr_b = [4]u8{ 10, 88, 0, 2 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(init.arena.allocator());
    _ = args.skip();
    const first = args.next() orelse return drive.fail("usage: zwg-interop-loopback <peer A binary> [<peer B binary>] | --refuses-tun <zwg>", .{});
    if (std.mem.eql(u8, first, "--refuses-tun")) {
        const bin = args.next() orelse return drive.fail("usage: zwg-interop-loopback --refuses-tun <zwg>", .{});
        const usage_out = drive.run(init.arena.allocator(), io, &.{bin}) catch return drive.fail("cannot run {s}", .{bin});
        if (std.mem.indexOf(u8, usage_out.stdout, "--tun") != null or std.mem.indexOf(u8, usage_out.stderr, "--tun") != null)
            return drive.fail("{s} advertises the --tun test mode (built with -Dtest-tun?)", .{bin});
        // A missing file: with the test mode the error would be about the
        // file; without it the arguments are a usage error.
        const r = drive.run(init.arena.allocator(), io, &.{ bin, "up", "zwg-no-such-file.conf", "--tun", "udp:9" }) catch return drive.fail("cannot run {s}", .{bin});
        if (r.ok or std.mem.indexOf(u8, r.stderr, "Usage:") == null or std.mem.indexOf(u8, r.stderr, "cannot read") != null)
            return drive.fail("{s} did not refuse `up <conf> --tun udp:<port>` as a usage error:\n{s}", .{ bin, r.stderr });
        std.debug.print("{s}: no --tun test mode (usage error, as it should be)\n", .{bin});
        return;
    }
    const zwg = first;
    const zwg_b = args.next() orelse zwg; // a different binary for B = cross-implementation

    for ([_][]const u8{ zwg, zwg_b }) |bin| {
        const usage_out = drive.run(init.arena.allocator(), io, &.{bin}) catch return drive.fail("cannot run {s}", .{bin});
        if (std.mem.indexOf(u8, usage_out.stdout, "--tun") == null and std.mem.indexOf(u8, usage_out.stderr, "--tun") == null)
            return drive.fail("{s} does not advertise `up <conf> --tun udp:<port>` (the interop runs need a -Dtest-tun build: zwg-testtun)", .{bin});
    }

    const tmp = init.environ_map.get(if (builtin.os.tag == .windows) "TEMP" else "TMPDIR") orelse
        (if (builtin.os.tag == .windows) return drive.fail("TEMP not set", .{}) else "/tmp");
    const sep = if (builtin.os.tag == .windows) "\\" else "/";

    var a = drive.KeyPair.generate(io);
    defer a.wipe();
    var b = drive.KeyPair.generate(io);
    defer b.wipe();
    const port_a = try drive.freePort();
    const port_b = try drive.freePort();
    const tun_a = try drive.freePort();
    const tun_b = try drive.freePort();

    var buf_a: [1024]u8 = undefined;
    var buf_b: [1024]u8 = undefined;
    const conf_a = try (drive.Conf{ .private = a.private, .listen_port = port_a, .peer_public = b.public, .allowed_ips = "10.88.0.2/32", .endpoint_port = port_b }).render(&buf_a);
    const conf_b = try (drive.Conf{ .private = b.private, .listen_port = port_b, .peer_public = a.public, .allowed_ips = "10.88.0.1/32", .endpoint_port = port_a }).render(&buf_b);
    const path_a = try std.fmt.allocPrint(init.arena.allocator(), "{s}{s}zwg-loop-a.conf", .{ tmp, sep });
    const path_b = try std.fmt.allocPrint(init.arena.allocator(), "{s}{s}zwg-loop-b.conf", .{ tmp, sep });
    try drive.writeFile(io, path_a, conf_a);
    defer drive.shredFile(io, path_a, conf_a.len);
    try drive.writeFile(io, path_b, conf_b);
    defer drive.shredFile(io, path_b, conf_b.len);

    const arg_a = try std.fmt.allocPrint(init.arena.allocator(), "udp:{d}", .{tun_a});
    const arg_b = try std.fmt.allocPrint(init.arena.allocator(), "udp:{d}", .{tun_b});
    var child_a = try std.process.spawn(io, .{ .argv = &.{ zwg, "up", path_a, "--tun", arg_a } });
    defer child_a.kill(io);
    var child_b = try std.process.spawn(io, .{ .argv = &.{ zwg_b, "up", path_b, "--tun", arg_b } });
    defer child_b.kill(io);

    var drv_a = try tun.UdpTun.open(0, 1500);
    defer drv_a.close();
    drv_a.setPeerPort(tun_a);
    var drv_b = try tun.UdpTun.open(0, 1500);
    defer drv_b.close();
    drv_b.setPeerPort(tun_b);
    // Register both drivers so each device knows where its TUN output goes.
    // (Sent again inside `exchange`: the processes may not be listening yet.)
    drv_a.hello();
    drv_b.hello();

    drive.step("A -> B (A initiates the handshake)", .{});
    try exchange(&drv_a, &drv_b, addr_a, addr_b, "hello from A");
    drive.step("B -> A (existing session)", .{});
    try exchange(&drv_b, &drv_a, addr_b, addr_a, "hello from B");
    drive.step("loopback passed", .{});
}

/// Push a UDP datagram into `from`'s TUN until it pops out of `to`'s TUN
/// (bounded: the processes may still be starting / handshaking).
fn exchange(from_drv: *tun.UdpTun, to_drv: *tun.UdpTun, src: [4]u8, dst: [4]u8, payload: []const u8) !void {
    const from = from_drv.tun();
    const to = to_drv.tun();
    var pbuf: [256]u8 = undefined;
    const pkt = ip.buildUdp4(&pbuf, src, 5000, dst, 6000, payload, 7);
    var rbuf: [2048]u8 = undefined;
    for (0..10) |_| {
        to_drv.hello();
        try from.write(pkt);
        while (try drive.recvWithin(to, &rbuf, 1000)) |p| {
            const u = ip.parseUdp4(p) orelse continue;
            if (std.mem.eql(u8, u.payload, payload) and std.mem.eql(u8, &u.src, &src)) return;
        }
    }
    return drive.fail("datagram never crossed the tunnel", .{});
}
