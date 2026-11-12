//! Live interop with the installed official WireGuard for Windows.
//!
//! Run ONCE from an elevated prompt (it installs a temporary tunnel service):
//!
//!     zig build interop-live                      (builds zig-out\bin\zwg-interop-live.exe)
//!     zig-out\bin\zwg-interop-live.exe [--zwg zig-out\bin\zwg.exe] [--record tests\interop\vectors\official.zig]
//!
//! Phase A (needs nothing but this driver): the official service initiates a
//! handshake to us on 127.0.0.1; the reference model (spec.zig) answers,
//! decrypts the official keepalive, and pushes a UDP datagram through the
//! official tunnel to an echo socket on the official side's tunnel address;
//! the echo reply comes back encrypted and is decrypted. `wg show` must
//! report the handshake. With --record, the transcript is written as a Zig
//! file the offline golden tests then replay forever.
//!
//! Phase B (once the device lands; skipped if zwg.exe lacks `--tun`): the
//! same official tunnel, now with a real `zwg up <conf> --tun udp:<port>`
//! process as the peer. zwg initiates this time (the other direction), and
//! the driver feeds/reads raw IP packets through UdpTun. No Wintun needed.
//!
//! Everything is torn down on exit (service uninstalled, firewall rule
//! removed, private-key files overwritten and deleted), also on failure.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const wg = @import("WireGuard");
const spec = @import("spec.zig");
const ip = @import("ip.zig");
const drive = @import("drive.zig");
const tun = wg.tun;

comptime {
    if (builtin.os.tag != .windows) @compileError("live interop targets WireGuard for Windows");
}

const tunnel_name = "zwgtest";
const official_addr = [4]u8{ 10, 77, 0, 1 };
const our_addr = [4]u8{ 10, 77, 0, 2 };
const echo_port: u16 = 7777;
const wireguard_exe = "C:\\Program Files\\WireGuard\\wireguard.exe";
const wg_exe = "C:\\Program Files\\WireGuard\\wg.exe";
const firewall_rule = "name=zwg-interop-echo";

const Options = struct {
    zwg: ?[]const u8 = null,
    record: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var opts: Options = .{};
    var args = try init.minimal.args.iterateAllocator(init.arena.allocator());
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--zwg")) opts.zwg = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--record")) opts.record = args.next() orelse return usage();
    }

    if (!tun.windows.isElevated()) {
        std.debug.print(
            \\This driver installs a temporary WireGuard tunnel service and a firewall
            \\rule, so it must run elevated. Open "Terminal (Admin)" and run it again.
            \\Nothing was changed.
            \\
        , .{});
        std.process.exit(2);
    }

    const temp = init.environ_map.get("TEMP") orelse return drive.fail("TEMP not set", .{});
    const conf_path = try std.fmt.allocPrint(init.arena.allocator(), "{s}\\{s}.conf", .{ temp, tunnel_name });
    const zwg_conf_path = try std.fmt.allocPrint(init.arena.allocator(), "{s}\\zwg-interop-peer.conf", .{temp});

    var official = drive.KeyPair.generate(io);
    defer official.wipe();
    var ours = drive.KeyPair.generate(io);
    defer ours.wipe();
    const official_port = try drive.freePort();
    const our_port = try drive.freePort();

    // Official side: address 10.77.0.1, peer = us at 127.0.0.1:our_port. The
    // keepalive makes the service initiate as soon as it is up.
    var conf_buf: [1024]u8 = undefined;
    const conf = try (drive.Conf{
        .private = official.private,
        .listen_port = official_port,
        .address = "10.77.0.1/24",
        .peer_public = ours.public,
        .allowed_ips = "10.77.0.2/32",
        .endpoint_port = our_port,
        .persistent_keepalive = 25,
    }).render(&conf_buf);
    try drive.writeFile(io, conf_path, conf);
    defer drive.shredFile(io, conf_path, conf.len);

    // Bind before the service starts so its first initiation reaches us.
    var sock = try tun.UdpTun.open(our_port, 1500);
    var sock_open = true;
    defer if (sock_open) sock.close();

    drive.step("install official tunnel service '{s}'", .{tunnel_name});
    if (!(try drive.run(gpa, io, &.{ wireguard_exe, "/installtunnelservice", conf_path })).ok)
        return drive.fail("wireguard.exe /installtunnelservice failed", .{});
    defer _ = drive.run(gpa, io, &.{ wireguard_exe, "/uninstalltunnelservice", tunnel_name }) catch {};

    _ = try drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "add", "rule", firewall_rule, "dir=in", "action=allow", "protocol=UDP", "localip=10.77.0.1", "localport=7777" });
    defer _ = drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "delete", "rule", firewall_rule }) catch {};

    // ---- Phase A: official <-> reference model -----------------------------
    drive.step("phase A: official initiates, reference model responds", .{});
    const t = sock.tun();
    var buf: [2048]u8 = undefined;
    const init_msg = (try drive.recvWithin(t, &buf, 20_000)) orelse return drive.fail("no handshake initiation from the official service within 20 s", .{});
    if (init_msg.len != spec.initiation_len) return drive.fail("expected a 148-byte initiation, got {d} bytes", .{init_msg.len});
    var initiation: [spec.initiation_len]u8 = init_msg[0..spec.initiation_len].*;

    var responder = spec.Responder.init(ours.private, @splat(0));
    responder.consumeInitiation(&initiation) catch |e| return drive.fail("reference model rejected the official initiation: {t}", .{e});
    if (!std.mem.eql(u8, &responder.peer_static, &official.public)) return drive.fail("initiation carries the wrong static key", .{});
    std.debug.print("  official initiation verified (mac1, static key, timestamp)\n", .{});

    var eph = drive.KeyPair.generate(io);
    defer eph.wipe();
    var sender_bytes: [4]u8 = undefined;
    io.random(&sender_bytes);
    const sender = std.mem.readInt(u32, &sender_bytes, .little);
    const r2 = try responder.createResponse(eph.private, sender);
    try t.write(&r2.msg);

    // The initiator confirms the session with a keepalive (transport, empty).
    var keepalive: [32]u8 = undefined;
    var plain: [2048]u8 = undefined;
    while (true) {
        const pkt = (try drive.recvWithin(t, &buf, 10_000)) orelse return drive.fail("no keepalive after our response", .{});
        if (pkt.len == spec.initiation_len) continue; // a retry raced our response
        const o = spec.openTransport(&plain, r2.keys, pkt) catch |e| return drive.fail("cannot decrypt official transport packet: {t}", .{e});
        if (o.plain.len != 0) return drive.fail("expected an empty keepalive, got {d} bytes", .{o.plain.len});
        keepalive = pkt[0..32].*;
        break;
    }
    std.debug.print("  official keepalive decrypted with the derived keys\n", .{});

    const show = try drive.run(gpa, io, &.{ wg_exe, "show", tunnel_name, "latest-handshakes" });
    if (!handshakeSeen(show.stdout)) return drive.fail("wg show reports no handshake:\n{s}", .{show.stdout});
    std.debug.print("  wg show latest-handshakes: {s}", .{show.stdout});

    // UDP echo through the official tunnel: our packet -> official -> Windows
    // stack -> echo socket on 10.77.0.1 -> reply routed back into the tunnel.
    var echo = try EchoSocket.bind(io, official_addr, echo_port);
    defer echo.close();
    const payload = "zwg-interop-echo";
    var ipbuf: [128]u8 = undefined;
    const pkt = ip.buildUdp4(&ipbuf, our_addr, 40000, official_addr, echo_port, payload, 1);
    var out: [256]u8 = undefined;
    try t.write(spec.sealTransport(&out, r2.keys, 0, pkt));
    try echo.answerOnce(5000);
    var echo_reply_buf: [256]u8 = undefined;
    var echo_reply: []const u8 = undefined;
    while (true) {
        const p = (try drive.recvWithin(t, &buf, 10_000)) orelse return drive.fail("echo reply never came back through the official tunnel", .{});
        const o = spec.openTransport(&plain, r2.keys, p) catch continue;
        if (o.plain.len == 0) continue; // keepalive
        const u = ip.parseUdp4(o.plain) orelse return drive.fail("tunnel delivered a non-UDP packet", .{});
        if (!std.mem.eql(u8, u.payload, payload)) return drive.fail("echo payload mismatch", .{});
        @memcpy(echo_reply_buf[0..p.len], p);
        echo_reply = echo_reply_buf[0..p.len];
        break;
    }
    std.debug.print("  UDP echo through the official tunnel: OK\n", .{});
    drive.step("phase A passed", .{});

    if (opts.record) |path| {
        try record(gpa, io, path, .{
            .our_private = ours.private,
            .official_public = official.public,
            .initiation = initiation,
            .eph = eph.private,
            .sender = sender,
            .response = r2.msg,
            .keepalive = keepalive,
            .payload = payload,
            .echo_reply = echo_reply,
        });
        std.debug.print("  transcript written to {s} (throwaway keys; commit it)\n", .{path});
    }

    // ---- Phase B: official <-> zwg -------------------------------------------
    const zwg = opts.zwg orelse {
        drive.step("phase B skipped (pass --zwg <path to zwg.exe> once the device is merged)", .{});
        return;
    };
    drive.step("phase B: zwg initiates to the official tunnel", .{});
    sock.close();
    sock_open = false;
    const tun_port = try drive.freePort();
    var zconf_buf: [1024]u8 = undefined;
    const zconf = try (drive.Conf{
        .private = ours.private,
        .listen_port = our_port,
        .peer_public = official.public,
        .allowed_ips = "10.77.0.1/32",
        .endpoint_port = official_port,
    }).render(&zconf_buf);
    try drive.writeFile(io, zwg_conf_path, zconf);
    defer drive.shredFile(io, zwg_conf_path, zconf.len);
    const tun_arg = try std.fmt.allocPrint(init.arena.allocator(), "udp:{d}", .{tun_port});
    var child = try std.process.spawn(io, .{ .argv = &.{ zwg, "up", zwg_conf_path, "--tun", tun_arg } });
    defer child.kill(io);

    var driver = try tun.UdpTun.open(0, 1500);
    defer driver.close();
    driver.setPeerPort(tun_port);
    const d = driver.tun();
    const pkt_b = ip.buildUdp4(&ipbuf, our_addr, 40001, official_addr, echo_port, payload, 2);
    // zwg may still be starting: offer the packet a few times (bounded).
    var delivered = false;
    for (0..10) |_| {
        driver.hello();
        try d.write(pkt_b);
        echo.answerOnce(1000) catch continue;
        delivered = true;
        break;
    }
    if (!delivered) return drive.fail("no packet from zwg reached the official side (is `zwg up --tun udp:<port>` implemented?)", .{});
    while (true) {
        const p = (try drive.recvWithin(d, &buf, 10_000)) orelse return drive.fail("echo reply did not come back out of zwg", .{});
        const u = ip.parseUdp4(p) orelse continue;
        if (u.dport == 40001 and std.mem.eql(u8, u.payload, payload)) break;
    }
    const show_b = try drive.run(gpa, io, &.{ wg_exe, "show", tunnel_name, "latest-handshakes" });
    if (!handshakeSeen(show_b.stdout)) return drive.fail("wg show reports no handshake with zwg", .{});
    drive.step("phase B passed: zwg <-> WireGuard for Windows, handshake + UDP echo both ways", .{});
}

fn usage() error{InteropFailed} {
    return drive.fail("usage: zwg-interop-live [--zwg <zwg.exe>] [--record <file.zig>]", .{});
}

/// `wg show <if> latest-handshakes` prints "<pubkey>\t<unix seconds>".
fn handshakeSeen(out: []const u8) bool {
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        const tab = std.mem.lastIndexOfScalar(u8, line, '\t') orelse continue;
        const ts = std.fmt.parseInt(u64, std.mem.trim(u8, line[tab + 1 ..], " \r"), 10) catch continue;
        if (ts > 0) return true;
    }
    return false;
}

const Transcript = struct {
    our_private: [32]u8,
    official_public: [32]u8,
    initiation: [148]u8,
    eph: [32]u8,
    sender: u32,
    response: [92]u8,
    keepalive: [32]u8,
    payload: []const u8,
    echo_reply: []const u8,
};

fn record(gpa: std.mem.Allocator, io: Io, path: []const u8, tr: Transcript) !void {
    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;
    try w.writeAll(
        \\//! Transcript recorded from the official WireGuard for Windows by
        \\//! tests/interop/live.zig --record. Throwaway keys, safe to commit.
        \\const hex = @import("std").fmt.hexToBytes;
        \\fn h(comptime n: usize, comptime s: []const u8) [n]u8 {
        \\    var out: [n]u8 = undefined;
        \\    _ = hex(&out, s) catch unreachable;
        \\    return out;
        \\}
        \\pub const available = true;
        \\
    );
    try w.print("pub const our_private = h(32, \"{x}\");\n", .{&tr.our_private});
    try w.print("pub const official_public = h(32, \"{x}\");\n", .{&tr.official_public});
    try w.print("pub const initiation = h(148, \"{x}\");\n", .{&tr.initiation});
    try w.print("pub const response_ephemeral_private = h(32, \"{x}\");\n", .{&tr.eph});
    try w.print("pub const response_sender: u32 = 0x{x};\n", .{tr.sender});
    try w.print("pub const response = h(92, \"{x}\");\n", .{&tr.response});
    try w.print("pub const keepalive = h(32, \"{x}\");\n", .{&tr.keepalive});
    try w.print("pub const echo_payload: []const u8 = \"{s}\";\n", .{tr.payload});
    try w.print("pub const echo_reply: []const u8 = &h({d}, \"{x}\");\n", .{ tr.echo_reply.len, tr.echo_reply });
    try drive.writeFile(io, path, aw.written());
}

/// A plain blocking UDP socket on the official side's tunnel address that
/// answers one datagram (bounded by SO_RCVTIMEO).
const EchoSocket = struct {
    s: usize,

    fn bind(io: Io, addr: [4]u8, port: u16) !EchoSocket {
        const s = ws.socket(2, 2, 17);
        if (s == ws.INVALID_SOCKET) return drive.fail("socket() failed", .{});
        var sa: ws.SockaddrIn = .{ .port_be = std.mem.nativeToBig(u16, port), .addr = addr };
        // The tunnel address can take a moment to become usable after the
        // service starts: bounded retries.
        var tries: usize = 0;
        while (ws.bind(s, &sa, @sizeOf(ws.SockaddrIn)) != 0) : (tries += 1) {
            if (tries == 40) return drive.fail("cannot bind 10.77.0.1:{d} (Winsock {d})", .{ port, ws.WSAGetLastError() });
            drive.sleepMs(io, 250);
        }
        return .{ .s = s };
    }

    fn close(e: *EchoSocket) void {
        _ = ws.closesocket(e.s);
    }

    fn answerOnce(e: *EchoSocket, timeout_ms: u32) !void {
        var ms: u32 = timeout_ms;
        _ = ws.setsockopt(e.s, 0xffff, 0x1006, @ptrCast(&ms), 4); // SOL_SOCKET, SO_RCVTIMEO
        var buf: [2048]u8 = undefined;
        var from: ws.SockaddrIn = undefined;
        var len: c_int = @sizeOf(ws.SockaddrIn);
        const n = ws.recvfrom(e.s, &buf, buf.len, 0, &from, &len);
        if (n < 0) return error.Timeout;
        _ = ws.sendto(e.s, &buf, n, 0, &from, len);
    }
};

const ws = struct {
    const INVALID_SOCKET: usize = std.math.maxInt(usize);
    const SockaddrIn = extern struct { family: u16 = 2, port_be: u16, addr: [4]u8, zero: [8]u8 = @splat(0) };
    extern "ws2_32" fn socket(af: c_int, kind: c_int, proto: c_int) callconv(.winapi) usize;
    extern "ws2_32" fn bind(s: usize, addr: *const SockaddrIn, len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recvfrom(s: usize, buf: [*]u8, len: c_int, flags: c_int, from: *SockaddrIn, fromlen: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn sendto(s: usize, buf: [*]const u8, len: c_int, flags: c_int, to: *const SockaddrIn, tolen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn setsockopt(s: usize, level: c_int, name: c_int, val: [*]const u8, len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: usize) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
};
