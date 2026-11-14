//! `zwg`: command-line front end (owned by the device agent; see DESIGN.md).
//!
//!   zwg genkey               new private key (base64) on stdout
//!   zwg pubkey               private key on stdin -> public key on stdout
//!   zwg show <file.conf>     the parsed configuration, `wg show` style, no secrets
//!   zwg up <file.conf>       run the tunnel in the foreground (Ctrl+C or `zwg down` stops it)
//!   zwg down <name|file.conf>  stop a running `zwg up` for that interface
//!   zwg installtunnel / uninstalltunnel / show [<name>] / down / up <name>
//!                            installed tunnels on Windows (src/service/cli.zig)
//!
//! The interface name is the file name without ".conf" (as wg-quick and
//! WireGuard for Windows name tunnels).

const std = @import("std");
const wg = @import("WireGuard");
const dev = wg.device;
const keys = dev.keys;
const config = dev.config;
const is_windows = @import("builtin").os.tag == .windows;
/// `up <conf> --tun udp:<port>`: the TUN is a 127.0.0.1 UDP socket (no
/// adapter, no privileges). A test-harness hook for tests/interop, compiled
/// in only by `-Dtest-tun` and into the `zwg-testtun` build.
const test_tun_enabled = @import("build_options").test_tun;

// In the tunnel service, std.log output goes to the tunnel's log file.
pub const std_options: std.Options = .{ .logFn = if (is_windows) wg.service.log.logFn else std.log.defaultLog };

const usage =
    \\Usage: zwg <command> [arguments]
    \\
    \\  genkey                 print a new private key
    \\  pubkey                 read a private key on stdin, print its public key
    \\  show <file.conf>       show a configuration (keys other than public ones hidden)
    \\  up <file.conf>         bring the tunnel up (foreground; needs Administrator on Windows)
    \\
++ (if (test_tun_enabled)
    \\  up <file.conf> --tun udp:<port>
    \\                         test mode: the TUN is a 127.0.0.1 UDP socket (tests/interop)
    \\
else "") ++
    \\  down <name|file.conf>  stop a tunnel started with `zwg up`
    \\
++ (if (is_windows) "\nInstalled tunnels (Windows service; nothing else runs elevated):\n" ++ wg.service.cli.usage else "");

pub fn main(init: std.process.Init) !void {
    // zwg runs elevated (installer, `zwg up`) and as SYSTEM (the service):
    // DLLs loaded without a full path come from System32 only, never from
    // the (possibly user-writable) application or current directory.
    if (is_windows) wg.tun.windows.restrictDllSearch();
    const gpa = init.gpa;
    const io = init.io;
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, a);

    var out_buf: [4096]u8 = undefined;
    var out_w = std.Io.File.stdout().writer(io, &out_buf);
    const out = &out_w.interface;
    var err_buf: [1024]u8 = undefined;
    var err_w = std.Io.File.stderr().writer(io, &err_buf);
    const errw = &err_w.interface;

    const code = run(gpa, io, args.items, out, errw) catch |err| blk: {
        errw.print("zwg: {s}\n", .{@errorName(err)}) catch {};
        break :blk 1;
    };
    out.flush() catch {};
    errw.flush() catch {};
    std.process.exit(code);
}

fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    if (args.len == 0) {
        try errw.writeAll(usage);
        return 1;
    }
    // installtunnel, uninstalltunnel, show/down/up <installed name>, and the
    // service's internal verbs (src/service/cli.zig).
    if (is_windows) if (try wg.service.cli.dispatch(gpa, io, args, out, errw)) |code| return code;
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "genkey") and args.len == 1) {
        var k = keys.generatePrivate(io);
        defer std.crypto.secureZero(u8, &k);
        var t = keys.encode(&k);
        defer std.crypto.secureZero(u8, &t);
        try out.print("{s}\n", .{&t});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "pubkey") and args.len == 1) {
        var buf: [256]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        var r = std.Io.File.stdin().readerStreaming(io, &.{});
        const n = try r.interface.readSliceShort(&buf);
        const text = std.mem.trim(u8, buf[0..n], " \t\r\n");
        var k = keys.decode(text) catch {
            try errw.writeAll("zwg: key is not the correct length or format\n");
            return 1;
        };
        defer std.crypto.secureZero(u8, &k);
        try out.print("{s}\n", .{&keys.encode(&keys.publicFromPrivate(&k))});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "show") and args.len == 2) {
        var c = (try loadConfig(gpa, io, args[1], errw)) orelse return 1;
        defer c.deinit();
        try dev.show.write(out, interfaceName(args[1]), &c, null, null, 0);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "up") and (args.len == 2 or (test_tun_enabled and args.len == 4 and std.mem.eql(u8, args[2], "--tun")))) {
        const test_tun: ?u16 = if (test_tun_enabled and args.len == 4) wg.tun.UdpTun.parseSpec(args[3]) catch {
            try errw.writeAll("zwg: --tun expects udp:<port>\n");
            return 1;
        } else null;
        var c = (try loadConfig(gpa, io, args[1], errw)) orelse return 1;
        defer c.deinit();
        return up(gpa, io, interfaceName(args[1]), &c, test_tun, out, errw);
    }
    if (std.mem.eql(u8, cmd, "down") and args.len == 2) {
        const name = interfaceName(args[1]);
        dev.os.StopSignal.signalExisting(name) catch |err| switch (err) {
            error.NotRunning => {
                try errw.print("zwg: no running tunnel named '{s}'\n", .{name});
                return 1;
            },
            else => return err,
        };
        try out.print("stopping {s}\n", .{name});
        return 0;
    }
    try errw.writeAll(usage);
    return 1;
}

/// "C:\tunnels\laptop.conf" -> "laptop"; a bare name stays as it is.
fn interfaceName(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    return if (std.ascii.endsWithIgnoreCase(base, ".conf")) base[0 .. base.len - 5] else base;
}

fn loadConfig(gpa: std.mem.Allocator, io: std.Io, path: []const u8, errw: *std.Io.Writer) !?config.Config {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(config.max_config_bytes)) catch |err| {
        try errw.print("zwg: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };
    defer {
        std.crypto.secureZero(u8, text); // the file holds the private key
        gpa.free(text);
    }
    var diag: config.Diagnostic = .{};
    const c = config.parse(gpa, text, &diag) catch |err| switch (err) {
        error.InvalidConfig => {
            try errw.print("zwg: {s}: {f}\n", .{ path, diag });
            return null;
        },
        else => return err,
    };
    for (c.warnings) |w| try errw.print("zwg: {s}: line {d}: warning: {s}\n", .{ path, w.line, w.message });
    return c;
}

fn up(gpa: std.mem.Allocator, io: std.Io, name: []const u8, c: *const config.Config, test_tun_arg: ?u16, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    // Comptime-known null without -Dtest-tun: the UdpTun path is not compiled in.
    const test_tun: ?u16 = if (comptime test_tun_enabled) test_tun_arg else null;
    const builtin = @import("builtin");
    const tun = wg.tun;
    if (comptime builtin.os.tag == .ios) {
        try errw.writeAll("zwg: on iOS the tunnel runs inside the Network Extension, not from a CLI\n");
        return 1;
    }

    // Only one `zwg up` per interface name; `zwg down <name>` signals this.
    var stop = dev.os.StopSignal.create(name) catch |err| switch (err) {
        error.AlreadyRunning => {
            try errw.print("zwg: {s} is already up\n", .{name});
            return 1;
        },
        else => return err,
    };
    defer stop.close();

    // Resolve endpoints first: a typo should fail before an adapter appears.
    const peers = try gpa.alloc(dev.device.PeerConfig, c.peers.len);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(peers)); // preshared keys
        gpa.free(peers);
    }
    for (c.peers, peers) |*p, *pc| {
        pc.* = .{
            .public_key = p.public_key,
            .preshared_key = p.preshared_key,
            .allowed_ips = p.allowed_ips,
            .persistent_keepalive = p.persistent_keepalive,
            .endpoint = if (p.endpoint) |e| resolveEndpoint(io, e) catch |err| {
                try errw.print("zwg: cannot resolve endpoint {f}: {s}\n", .{ e, @errorName(err) });
                return 1;
            } else null,
        };
    }

    const mtu = c.interface.mtu orelse tun.default_mtu;
    // Test mode (tests/interop): a UdpTun on 127.0.0.1 instead of an OS
    // adapter; no privileges needed, addresses and routes are no-ops.
    var udp_tun: tun.UdpTun = undefined;
    var native: tun.Native = undefined;
    var tun_open = false;
    defer if (tun_open) {
        if (test_tun != null) udp_tun.close() else native.close();
    };
    const t: tun.Tun = if (test_tun) |port| blk: {
        udp_tun = tun.UdpTun.open(port, mtu) catch |err| {
            try errw.print("zwg: --tun udp:{d}: {s}\n", .{ port, @errorName(err) });
            return 1;
        };
        tun_open = true;
        break :blk udp_tun.tun();
    } else blk: {
        native = tun.Native.open(name, .{ .mtu = mtu }) catch |err| {
            switch (err) {
                error.AccessDenied => if (comptime builtin.os.tag == .windows)
                    try errw.print("zwg: {s}\n", .{tun.windows.elevation_hint})
                else
                    try errw.writeAll("zwg: creating a TUN interface needs root / CAP_NET_ADMIN\n"),
                else => if (comptime builtin.os.tag == .windows and @hasDecl(tun.windows, "wintun_hint")) {
                    if (err == error.WintunNotFound) {
                        try errw.print("zwg: {s}\n", .{tun.windows.wintun_hint});
                    } else if (err == error.WintunUntrusted) {
                        try errw.print("zwg: {s}\n", .{tun.windows.untrusted_hint});
                    } else try errw.print("zwg: cannot create the TUN interface: {s}\n", .{@errorName(err)});
                } else try errw.print("zwg: cannot create the TUN interface: {s}\n", .{@errorName(err)}),
            }
            return 1;
        };
        tun_open = true;
        break :blk native.tun();
    };
    for (c.interface.addresses) |a| try t.setAddress(toTunCidr(a));
    for (c.peers) |*p| for (p.allowed_ips) |a| t.addRoute(toTunCidr(a)) catch |err| {
        try errw.print("zwg: warning: route {f}: {s}\n", .{ a, @errorName(err) });
    };
    if (c.interface.dns.len + c.interface.dns_search.len != 0)
        try errw.writeAll("zwg: warning: DNS is not configured by zwg yet; set it on the interface yourself\n");

    var clock: dev.device.Clock = .{ .io = io };
    var options: dev.device.Options = .{
        .private_key = c.interface.private_key,
        .listen_port = c.interface.listen_port,
        .peers = peers,
        .loopback_only = test_tun != null,
    };
    defer std.crypto.secureZero(u8, &options.private_key);
    const d = try dev.Device.create(gpa, &clock, t, options);
    defer d.destroy();
    d.external_stop = stop.waitHandle();
    dev.os.stopOnInterrupt(&stop);

    try out.print("interface {s} up, listening on UDP port {d} (Ctrl+C or `zwg down {s}` to stop)\n", .{ name, d.listen_port, name });
    try out.flush();
    d.run() catch |err| {
        try errw.print("zwg: {s}: {s}\n", .{ name, @errorName(err) });
        return 1;
    };

    // Final status, like `wg show`, then down.
    const status = try gpa.alloc(dev.show.PeerStatus, c.peers.len);
    defer gpa.free(status);
    for (status, 0..) |*s, i| s.* = d.peerStatus(@intCast(i));
    const now_unix: i64 = @intCast(@divFloor(clock.wall(), std.time.ns_per_s));
    try dev.show.write(out, name, c, .{ .listen_port = d.listen_port }, status, now_unix);
    try out.print("\ninterface {s} down\n", .{name});
    return 0;
}

fn toTunCidr(c: dev.ip.Cidr) wg.tun.Cidr {
    return switch (c.addr) {
        .v4 => |b| wg.tun.Cidr.ip4(b, c.prefix),
        .v6 => |b| wg.tun.Cidr.ip6(b, c.prefix),
    };
}

/// IP literal, or a DNS lookup (IPv4 preferred: the device always has an
/// IPv4 socket, IPv6 only when the host supports it).
fn resolveEndpoint(io: std.Io, e: config.Endpoint) !std.Io.net.IpAddress {
    if (e.literal()) |a| return a;
    const host = try std.Io.net.HostName.init(e.host);
    var buf: [32]std.Io.net.HostName.LookupResult = undefined;
    var q: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&buf);
    try host.lookup(io, &q, .{ .port = e.port });
    var got: [32]std.Io.net.HostName.LookupResult = undefined;
    const n = q.get(io, &got, 0) catch 0;
    var v6: ?std.Io.net.IpAddress = null;
    for (got[0..n]) |r| switch (r) {
        .address => |a| switch (a) {
            .ip4 => return a,
            .ip6 => if (v6 == null) {
                v6 = a;
            },
        },
        else => {},
    };
    return v6 orelse error.UnknownHostName;
}
