//! Linux side of the live tests (run as root; WSL2 or any Linux host with
//! kernel WireGuard, wireguard-tools and iproute2).
//!
//!   zwg-live-linux netns-test --zwg <zwg> [--quick] [--out <file>]
//!       Self-contained real-OS test: the official kernel WireGuard and zwg
//!       (Linux backend, real /dev/net/tun) in two network namespaces joined
//!       by a veth pair. Handshakes initiated from both sides, UDP + ping both
//!       ways, MTU-sized packets, a forced re-handshake, endpoint roaming in
//!       both directions and (without --quick) zwg's own time-based rekey
//!       after REKEY_AFTER_TIME. Everything is torn down on exit.
//!
//!   zwg-live-linux serve --zwg <zwg>
//!       Line-oriented control channel for the elevated Windows driver
//!       (live_wsl.zig): it brings up / resets / moves / stops a kernel
//!       WireGuard peer and a zwg peer in the root namespace and runs probes.
//!       Tears everything down on `quit` or end of input.
//!
//!   zwg-live-linux cleanup        remove anything a crashed run left behind
//!   zwg-live-linux echo <port>    UDP echo server (used inside namespaces)
//!   zwg-live-linux probe <ipv4> <port> <payload bytes> <timeout ms>
//!                                 one UDP round trip; exit 0 on an exact echo
//!
//! Test tooling only. External programs: ip, wg, ping.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const wg = @import("WireGuard");
const drive = @import("drive.zig");
const os = wg.device.os;
const net = std.Io.net;

comptime {
    if (builtin.os.tag != .linux) @compileError("live_linux.zig is the Linux side of the live tests");
}

pub const run_dir = "/run/zwg-live";
pub const echo_port: u16 = 7777;
pub const mtu: u16 = 1420;
/// UDP payload that makes an IPv4 packet of exactly `mtu` bytes.
pub const mtu_payload: usize = mtu - 28;
/// ICMP echo payload that makes an IPv4 packet of exactly `mtu` bytes.
pub const mtu_ping: usize = mtu - 28;

const ns_kernel = "zwg-live-k";
const ns_zwg = "zwg-live-z";
const veth_k = "zwgvk";
const veth_z = "zwgvz";

// ---------------------------------------------------------------- plumbing

const Env = struct {
    gpa: std.mem.Allocator, // an arena: the helper is short-lived
    io: Io,
    self_exe: []const u8,
    ip: []const u8,
    wg_tool: []const u8,
    ping: ?[]const u8,
    zwg: ?[]const u8 = null,

    fn init(gpa: std.mem.Allocator, io: Io) !Env {
        return .{
            .gpa = gpa,
            .io = io,
            .self_exe = try std.process.executablePathAlloc(io, gpa),
            .ip = try findTool(io, "ip") orelse return drive.fail("`ip` (iproute2) not found", .{}),
            .wg_tool = try findTool(io, "wg") orelse return drive.fail("`wg` not found: apt-get install wireguard-tools", .{}),
            .ping = try findTool(io, "ping"),
        };
    }

    /// argv, prefixed with `ip netns exec <ns>` when ns is set.
    fn argv(e: *Env, ns: ?[]const u8, args: []const []const u8) ![]const []const u8 {
        var full: std.ArrayList([]const u8) = .empty;
        if (ns) |n| try full.appendSlice(e.gpa, &.{ e.ip, "netns", "exec", n });
        try full.appendSlice(e.gpa, args);
        return full.items;
    }

    fn run(e: *Env, ns: ?[]const u8, args: []const []const u8) !drive.RunOutput {
        return drive.run(e.gpa, e.io, try e.argv(ns, args));
    }

    fn must(e: *Env, ns: ?[]const u8, args: []const []const u8) !void {
        const r = try e.run(ns, args);
        if (!r.ok) return error.CommandFailed;
    }

    /// Quiet best-effort command (teardown): no echo, errors ignored.
    fn quiet(e: *Env, ns: ?[]const u8, args: []const []const u8) void {
        const full = e.argv(ns, args) catch return;
        _ = std.process.run(e.gpa, e.io, .{ .argv = full, .stdout_limit = .limited(1 << 16), .stderr_limit = .limited(1 << 16) }) catch {};
    }

    fn print(e: *Env, comptime fmt: []const u8, args: anytype) []const u8 {
        return std.fmt.allocPrint(e.gpa, fmt, args) catch "?";
    }
};

/// /proc files report size 0, so read them as a stream.
fn readProc(e: *Env, path: []const u8, buf: []u8) ?[]const u8 {
    var f = Io.Dir.cwd().openFile(e.io, path, .{}) catch return null;
    defer f.close(e.io);
    var r = f.readerStreaming(e.io, &.{});
    const n = r.interface.readSliceShort(buf) catch return null;
    return buf[0..n];
}

fn findTool(io: Io, name: []const u8) !?[]const u8 {
    const dirs = [_][]const u8{ "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/" };
    var buf: [64]u8 = undefined;
    for (dirs) |d| {
        const p = try std.fmt.bufPrint(&buf, "{s}{s}", .{ d, name });
        Io.Dir.cwd().access(io, p, .{}) catch continue;
        return try std.heap.page_allocator.dupe(u8, p);
    }
    return null;
}

const Report = drive.Report;
const okText = drive.okText;
const nowS = drive.nowS;
const monoMs = drive.monoMs;

fn sleepMs(io: Io, ms: i64) void {
    drive.sleepMs(io, ms);
}

/// Private-key files live in a root-only directory and are overwritten
/// before deletion.
fn writeSecret(e: *Env, name: []const u8, data: []const u8) ![]const u8 {
    const path = e.print("{s}/{s}", .{ run_dir, name });
    try Io.Dir.cwd().writeFile(e.io, .{ .sub_path = path, .data = data });
    return path;
}

fn makeRunDir(e: *Env) !void {
    Io.Dir.cwd().createDir(e.io, run_dir, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn removeRunDir(e: *Env) void {
    var dir = Io.Dir.cwd().openDir(e.io, run_dir, .{ .iterate = true }) catch return;
    var it = dir.iterate();
    while (it.next(e.io) catch null) |ent| {
        if (ent.kind != .file) continue;
        var zeros: [4096]u8 = @splat(0);
        dir.writeFile(e.io, .{ .sub_path = ent.name, .data = &zeros }) catch {};
    }
    dir.close(e.io);
    Io.Dir.cwd().deleteTree(e.io, run_dir) catch {};
}

// ------------------------------------------------------------ the peers

/// The official implementation: a kernel WireGuard interface set up with
/// `ip` and `wg`.
pub const Kernel = struct {
    ns: ?[]const u8,
    ifname: []const u8,
    port: u16,
    addr: []const u8,
    peer_pub: []const u8,
    allowed: []const u8,
    endpoint: ?[]const u8,
    key_path: []const u8 = "",

    pub fn up(k: *Kernel, e: *Env, private_b64: []const u8) !void {
        k.key_path = try writeSecret(e, e.print("{s}.key", .{k.ifname}), e.print("{s}\n", .{private_b64}));
        try e.must(k.ns, &.{ e.ip, "link", "add", k.ifname, "type", "wireguard" });
        try e.must(k.ns, &.{ e.wg_tool, "set", k.ifname, "listen-port", e.print("{d}", .{k.port}), "private-key", k.key_path });
        try k.addPeer(e);
        try e.must(k.ns, &.{ e.ip, "address", "add", k.addr, "dev", k.ifname });
        try e.must(k.ns, &.{ e.ip, "link", "set", k.ifname, "mtu", e.print("{d}", .{mtu}), "up" });
    }

    fn addPeer(k: *Kernel, e: *Env) !void {
        if (k.endpoint) |ep|
            try e.must(k.ns, &.{ e.wg_tool, "set", k.ifname, "peer", k.peer_pub, "allowed-ips", k.allowed, "endpoint", ep })
        else
            try e.must(k.ns, &.{ e.wg_tool, "set", k.ifname, "peer", k.peer_pub, "allowed-ips", k.allowed });
    }

    /// Remove and re-add the peer: the kernel forgets every session, so the
    /// next packet it sends starts a handshake (forced re-handshake).
    pub fn resetPeer(k: *Kernel, e: *Env) !void {
        try e.must(k.ns, &.{ e.wg_tool, "set", k.ifname, "peer", k.peer_pub, "remove" });
        try k.addPeer(e);
    }

    /// Move the kernel's UDP socket to another port (roaming, as seen by the
    /// other side).
    pub fn setPort(k: *Kernel, e: *Env, port: u16) !void {
        k.port = port;
        try e.must(k.ns, &.{ e.wg_tool, "set", k.ifname, "listen-port", e.print("{d}", .{port}) });
    }

    fn field(k: *Kernel, e: *Env, what: []const u8) ![]const u8 {
        const r = try e.run(k.ns, &.{ e.wg_tool, "show", k.ifname, what });
        if (!r.ok) return error.CommandFailed;
        const line = std.mem.trim(u8, r.stdout, " \r\n");
        const tab = std.mem.findScalarLast(u8, line, '\t') orelse return error.UnexpectedOutput;
        return line[tab + 1 ..];
    }

    /// Unix time of the latest handshake (0 = none).
    pub fn handshake(k: *Kernel, e: *Env) !i64 {
        return std.fmt.parseInt(i64, try k.field(e, "latest-handshakes"), 10) catch error.UnexpectedOutput;
    }

    pub fn currentEndpoint(k: *Kernel, e: *Env) ![]const u8 {
        return k.field(e, "endpoints");
    }

    pub fn show(k: *Kernel, e: *Env) []const u8 {
        const r = e.run(k.ns, &.{ e.wg_tool, "show", k.ifname }) catch return "";
        return r.stdout;
    }

    pub fn down(k: *Kernel, e: *Env) void {
        e.quiet(k.ns, &.{ e.ip, "link", "del", k.ifname });
    }
};

/// zwg built for Linux, on a real /dev/net/tun interface named after its
/// .conf file.
pub const Zwg = struct {
    ns: ?[]const u8,
    name: []const u8,
    port: u16,
    addr: []const u8,
    peer_pub: []const u8,
    allowed: []const u8,
    endpoint: []const u8,
    private_b64: []const u8,
    child: ?std.process.Child = null,
    log_path: []const u8 = "",
    starts: u32 = 0,

    pub fn start(z: *Zwg, e: *Env) !void {
        const bin = e.zwg orelse return drive.fail("--zwg <path to the Linux zwg binary> is required", .{});
        const conf = e.print(
            \\[Interface]
            \\PrivateKey = {s}
            \\ListenPort = {d}
            \\Address = {s}
            \\MTU = {d}
            \\
            \\[Peer]
            \\PublicKey = {s}
            \\AllowedIPs = {s}
            \\Endpoint = {s}
            \\
        , .{ z.private_b64, z.port, z.addr, mtu, z.peer_pub, z.allowed, z.endpoint });
        const conf_path = try writeSecret(e, e.print("{s}.conf", .{z.name}), conf);
        z.starts += 1;
        z.log_path = e.print("{s}/{s}-{d}.log", .{ run_dir, z.name, z.starts });
        var log = try Io.Dir.cwd().createFile(e.io, z.log_path, .{});
        defer log.close(e.io);
        const args = try e.argv(z.ns, &.{ bin, "up", conf_path });
        std.debug.print("  $ {s} up {s} (in {s})\n", .{ bin, conf_path, z.ns orelse "root namespace" });
        z.child = try std.process.spawn(e.io, .{ .argv = args, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log } });
        // Up when the interface carries its address (bounded wait).
        const want = z.addr[0 .. std.mem.findScalar(u8, z.addr, '/') orelse z.addr.len];
        var tries: usize = 0;
        while (tries < 100) : (tries += 1) {
            const r = std.process.run(e.gpa, e.io, .{ .argv = try e.argv(z.ns, &.{ e.ip, "-4", "-o", "address", "show", "dev", z.name }) }) catch null;
            if (r) |out| if (std.mem.find(u8, out.stdout, want) != null) {
                // The configuration file holds the private key: gone once read.
                drive.shredFile(e.io, conf_path, conf.len);
                return;
            };
            if (z.exited(e)) break;
            sleepMs(e.io, 100);
        }
        drive.shredFile(e.io, conf_path, conf.len);
        const log_text = Io.Dir.cwd().readFileAlloc(e.io, z.log_path, e.gpa, .limited(1 << 16)) catch "";
        return drive.fail("zwg did not bring {s} up:\n{s}", .{ z.name, log_text });
    }

    /// True once the process is a zombie (exited, not yet reaped).
    fn exited(z: *Zwg, e: *Env) bool {
        const c = z.child orelse return true;
        const pid = c.id orelse return true;
        var buf: [64]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "/proc/{d}/stat", .{pid}) catch return true;
        var sbuf: [1024]u8 = undefined;
        const stat = readProc(e, p, &sbuf) orelse return true;
        const close = std.mem.findScalarLast(u8, stat, ')') orelse return true;
        return stat.len > close + 2 and (stat[close + 2] == 'Z' or stat[close + 2] == 'X');
    }

    /// SIGTERM (zwg prints its final `wg show`-style status and removes the
    /// interface), SIGKILL after 5 s. Returns the process output.
    pub fn stop(z: *Zwg, e: *Env) []const u8 {
        var c = z.child orelse return "";
        z.child = null;
        if (c.id) |pid| std.posix.kill(pid, .TERM) catch {};
        var waited: usize = 0;
        while (waited < 50 and !(blk: {
            z.child = c;
            defer z.child = null;
            break :blk z.exited(e);
        })) : (waited += 1) sleepMs(e.io, 100);
        if (waited == 50) c.kill(e.io) else _ = c.wait(e.io) catch {};
        return Io.Dir.cwd().readFileAlloc(e.io, z.log_path, e.gpa, .limited(1 << 16)) catch "";
    }
};

/// "latest handshake: ..." and "transfer: ..." lines from zwg's final status.
fn statusSummary(e: *Env, log: []const u8) []const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, log, '\n');
    while (it.next()) |line| {
        const t = std.mem.trim(u8, line, " \r");
        if (std.mem.startsWith(u8, t, "latest handshake") or std.mem.startsWith(u8, t, "transfer") or std.mem.startsWith(u8, t, "endpoint")) {
            if (out.items.len != 0) out.appendSlice(e.gpa, "; ") catch {};
            out.appendSlice(e.gpa, t) catch {};
        }
    }
    return out.items;
}

const Probe = struct { ok: bool, ms: i64 };

/// One UDP round trip through the tunnel, run inside `ns`.
fn probe(e: *Env, ns: ?[]const u8, dst: []const u8, len: usize, timeout_ms: u32) Probe {
    const t0 = monoMs(e.io);
    const r = e.run(ns, &.{ e.self_exe, "probe", dst, e.print("{d}", .{echo_port}), e.print("{d}", .{len}), e.print("{d}", .{timeout_ms}) }) catch return .{ .ok = false, .ms = 0 };
    return .{ .ok = r.ok, .ms = monoMs(e.io) - t0 };
}

/// ICMP echo with DF set; `size` is the ICMP payload.
fn ping(e: *Env, ns: ?[]const u8, dst: []const u8, size: usize) bool {
    const bin = e.ping orelse return false;
    const r = e.run(ns, &.{ bin, "-c", "3", "-i", "0.2", "-W", "2", "-M", "do", "-s", e.print("{d}", .{size}), dst }) catch return false;
    return r.ok;
}

// ------------------------------------------------------------ subcommands

fn echoMain(port: u16) !void {
    return drive.echoServe(port, null);
}

/// Sends `len` tagged bytes to dst:port, waits for the identical echo;
/// resends every second until `timeout_ms` (a handshake may be under way).
fn probeMain(io: Io, dst_text: []const u8, port: u16, len: usize, timeout_ms: u32) !bool {
    const dst = try net.Ip4Address.parse(dst_text, port);
    return (try drive.udpProbe(io, dst.bytes, port, len, timeout_ms)) != null;
}

fn cleanupMain(e: *Env) void {
    // zwg processes we may have left behind (their interfaces go with them).
    var dir = Io.Dir.cwd().openDir(e.io, "/proc", .{ .iterate = true }) catch null;
    if (dir) |*d| {
        defer d.close(e.io);
        var it = d.iterate();
        while (it.next(e.io) catch null) |ent| {
            const pid = std.fmt.parseInt(std.posix.pid_t, ent.name, 10) catch continue;
            var pbuf: [64]u8 = undefined;
            const p = std.fmt.bufPrint(&pbuf, "/proc/{d}/cmdline", .{pid}) catch continue;
            var cbuf: [4096]u8 = undefined;
            const cmdline = readProc(e, p, &cbuf) orelse continue;
            // Our zwg instances run `<zwg> up /run/zwg-live/<name>.conf`; our
            // helpers run `<this> echo|serve ...`.
            if (std.mem.find(u8, cmdline, run_dir ++ "/") != null or
                (std.mem.find(u8, cmdline, "zwg-live-linux") != null and pid != std.os.linux.getpid() and
                    (std.mem.find(u8, cmdline, "\x00echo\x00") != null or std.mem.find(u8, cmdline, "\x00serve") != null)))
            {
                std.debug.print("  killing leftover process {d}\n", .{pid});
                std.posix.kill(pid, .KILL) catch {};
            }
        }
    }
    e.quiet(null, &.{ e.ip, "netns", "del", ns_kernel });
    e.quiet(null, &.{ e.ip, "netns", "del", ns_zwg });
    e.quiet(null, &.{ e.ip, "link", "del", veth_k });
    for ([_][]const u8{ "zwgk0", "zwgk1", "zwgz0", "zwgz1" }) |ifn| e.quiet(null, &.{ e.ip, "link", "del", ifn });
    removeRunDir(e);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    _ = args.skip();
    const cmd = args.next() orelse return usage();

    if (std.mem.eql(u8, cmd, "echo")) {
        return echoMain(try std.fmt.parseInt(u16, args.next() orelse return usage(), 10));
    }
    if (std.mem.eql(u8, cmd, "probe")) {
        const dst = args.next() orelse return usage();
        const port = try std.fmt.parseInt(u16, args.next() orelse return usage(), 10);
        const len = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        const timeout = try std.fmt.parseInt(u32, args.next() orelse return usage(), 10);
        std.process.exit(if (try probeMain(io, dst, port, len, timeout)) 0 else 1);
    }

    if (std.os.linux.geteuid() != 0) {
        std.debug.print("zwg-live-linux {s} needs root (network namespaces, WireGuard interfaces, TUN)\n", .{cmd});
        std.process.exit(2);
    }
    var e = try Env.init(gpa, io);
    var out_path: ?[]const u8 = null;
    var quick = false;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--zwg")) e.zwg = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--out")) out_path = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--quick")) quick = true;
    }

    if (std.mem.eql(u8, cmd, "cleanup")) return cleanupMain(&e);
    if (std.mem.eql(u8, cmd, "netns-test")) {
        const ok = try netnsTest(&e, quick, out_path orelse "zwg-live-netns-results.txt");
        std.process.exit(if (ok) 0 else 1);
    }
    if (std.mem.eql(u8, cmd, "serve")) return serve(&e);
    return usage();
}

fn usage() error{InteropFailed} {
    return drive.fail(
        \\usage: zwg-live-linux netns-test --zwg <zwg> [--quick] [--out <file>]
        \\       zwg-live-linux serve --zwg <zwg>
        \\       zwg-live-linux cleanup
        \\       zwg-live-linux echo <port>
        \\       zwg-live-linux probe <ipv4> <port> <bytes> <timeout ms>
    , .{});
}

// ------------------------------------------------------------ netns test

fn netnsTest(e: *Env, quick: bool, out_path: []const u8) !bool {
    var report: Report = .{ .gpa = e.gpa };
    const started = nowS(e.io);
    drive.step("cleanup of earlier runs", .{});
    cleanupMain(e);
    try makeRunDir(e);

    var kk = drive.KeyPair.generate(e.io);
    defer kk.wipe();
    var zk = drive.KeyPair.generate(e.io);
    defer zk.wipe();
    var k_priv = drive.b64(kk.private);
    defer std.crypto.secureZero(u8, &k_priv);
    var z_priv = drive.b64(zk.private);
    defer std.crypto.secureZero(u8, &z_priv);
    const k_pub = drive.b64(kk.public);
    const z_pub = drive.b64(zk.public);

    var kernel: Kernel = .{
        .ns = ns_kernel,
        .ifname = "zwgk0",
        .port = 51820,
        .addr = "10.88.0.1/24",
        .peer_pub = &z_pub,
        .allowed = "10.88.0.2/32",
        .endpoint = "10.99.0.2:51821",
    };
    var zwg: Zwg = .{
        .ns = ns_zwg,
        .name = "zwgz0",
        .port = 51821,
        .addr = "10.88.0.2/24",
        .peer_pub = &k_pub,
        .allowed = "10.88.0.1/32",
        .endpoint = "10.99.0.1:51820",
        .private_b64 = &z_priv,
    };
    var echo_k: ?std.process.Child = null;
    var echo_z: ?std.process.Child = null;
    var final_log: []const u8 = "";
    var kernel_show: []const u8 = "";

    run: {
        drive.step("topology: netns {s} (kernel WireGuard) <-veth-> netns {s} (zwg)", .{ ns_kernel, ns_zwg });
        e.must(null, &.{ e.ip, "netns", "add", ns_kernel }) catch break :run report.add("setup", false, "ip netns add failed", .{});
        e.must(null, &.{ e.ip, "netns", "add", ns_zwg }) catch break :run report.add("setup", false, "ip netns add failed", .{});
        e.must(null, &.{ e.ip, "link", "add", veth_k, "netns", ns_kernel, "type", "veth", "peer", "name", veth_z, "netns", ns_zwg }) catch
            break :run report.add("setup", false, "veth pair failed", .{});
        for ([_][2][]const u8{ .{ ns_kernel, veth_k }, .{ ns_zwg, veth_z } }, [_][]const u8{ "10.99.0.1/24", "10.99.0.2/24" }) |nv, a| {
            e.must(nv[0], &.{ e.ip, "link", "set", "lo", "up" }) catch break :run report.add("setup", false, "lo up", .{});
            e.must(nv[0], &.{ e.ip, "address", "add", a, "dev", nv[1] }) catch break :run report.add("setup", false, "veth address", .{});
            e.must(nv[0], &.{ e.ip, "link", "set", nv[1], "up" }) catch break :run report.add("setup", false, "veth up", .{});
        }
        drive.step("kernel WireGuard up in {s}", .{ns_kernel});
        kernel.up(e, &k_priv) catch break :run report.add("kernel WireGuard interface up", false, "", .{});
        report.add("kernel WireGuard interface up", true, "{s} 10.88.0.1/24, UDP 51820", .{kernel.ifname});
        drive.step("zwg (Linux /dev/net/tun backend) up in {s}", .{ns_zwg});
        zwg.start(e) catch break :run report.add("zwg Linux TUN interface up", false, "", .{});
        report.add("zwg Linux TUN interface up", true, "{s} 10.88.0.2/24, UDP 51821, MTU {d}", .{ zwg.name, mtu });

        echo_k = std.process.spawn(e.io, .{ .argv = try e.argv(ns_kernel, &.{ e.self_exe, "echo", "7777" }), .stdin = .ignore, .stdout = .ignore }) catch null;
        echo_z = std.process.spawn(e.io, .{ .argv = try e.argv(ns_zwg, &.{ e.self_exe, "echo", "7777" }), .stdin = .ignore, .stdout = .ignore }) catch null;
        sleepMs(e.io, 200);

        drive.step("1. kernel initiates (first packet from the kernel side)", .{});
        const hs_none = kernel.handshake(e) catch -1;
        var p = probe(e, ns_kernel, "10.88.0.2", 64, 10_000);
        const hs1 = kernel.handshake(e) catch 0;
        report.add("handshake initiated by kernel WG, answered by zwg", p.ok and hs_none == 0 and hs1 > 0, "UDP echo kernel->zwg {s} in {d} ms; kernel latest-handshake {d}", .{ okText(p.ok), p.ms, hs1 });

        drive.step("2. data zwg -> kernel on that session", .{});
        p = probe(e, ns_zwg, "10.88.0.1", 64, 5_000);
        report.add("UDP echo zwg->kernel", p.ok, "{d} ms", .{p.ms});

        drive.step("3. ping both ways", .{});
        if (e.ping == null) {
            report.add("ping", false, "ping not installed", .{});
        } else {
            report.add("ping kernel->zwg (ICMP through the tunnel)", ping(e, ns_kernel, "10.88.0.2", 56), "", .{});
            report.add("ping zwg->kernel", ping(e, ns_zwg, "10.88.0.1", 56), "", .{});
        }

        drive.step("4. MTU-sized packets ({d}-byte IPv4 packets, DF)", .{mtu});
        p = probe(e, ns_kernel, "10.88.0.2", mtu_payload, 5_000);
        report.add("MTU-sized UDP kernel->zwg->kernel", p.ok, "{d}-byte payload = {d}-byte IP packet", .{ mtu_payload, mtu });
        p = probe(e, ns_zwg, "10.88.0.1", mtu_payload, 5_000);
        report.add("MTU-sized UDP zwg->kernel->zwg", p.ok, "{d}-byte payload", .{mtu_payload});
        if (e.ping != null) {
            report.add("MTU-sized ping kernel->zwg (DF)", ping(e, ns_kernel, "10.88.0.2", mtu_ping), "-s {d} -M do", .{mtu_ping});
            report.add("MTU-sized ping zwg->kernel (DF)", ping(e, ns_zwg, "10.88.0.1", mtu_ping), "-s {d} -M do", .{mtu_ping});
        }

        drive.step("5. forced re-handshake: the kernel forgets its sessions", .{});
        sleepMs(e.io, 1100); // latest-handshake has 1 s resolution
        kernel.resetPeer(e) catch report.add("kernel peer reset", false, "", .{});
        p = probe(e, ns_kernel, "10.88.0.2", 64, 10_000);
        const hs2 = kernel.handshake(e) catch 0;
        report.add("re-handshake initiated by kernel while zwg holds a live session", p.ok and hs2 > hs1, "echo {s}; latest-handshake {d} -> {d}", .{ okText(p.ok), hs1, hs2 });

        drive.step("6. roaming: the kernel moves to UDP port 51830", .{});
        kernel.setPort(e, 51830) catch report.add("kernel listen-port change", false, "", .{});
        p = probe(e, ns_kernel, "10.88.0.2", 64, 5_000);
        report.add("zwg follows the kernel's new port (endpoint roaming in zwg)", p.ok, "echo kernel->zwg after the move {s}", .{okText(p.ok)});
        p = probe(e, ns_zwg, "10.88.0.1", 64, 5_000);
        report.add("zwg->kernel after the move", p.ok, "", .{});

        drive.step("7. zwg initiates: restart zwg (fresh state), first packet from zwg", .{});
        final_log = zwg.stop(e);
        const st1 = statusSummary(e, final_log);
        report.add("zwg exits cleanly on SIGTERM with a status", std.mem.find(u8, st1, "latest handshake") != null, "{s}", .{st1});
        sleepMs(e.io, 1100);
        zwg.endpoint = "10.99.0.1:51830";
        zwg.start(e) catch break :run report.add("zwg restart", false, "", .{});
        p = probe(e, ns_zwg, "10.88.0.1", 64, 10_000);
        const hs3 = kernel.handshake(e) catch 0;
        report.add("handshake initiated by zwg, answered by kernel WG", p.ok and hs3 > hs2, "echo zwg->kernel {s} in {d} ms; latest-handshake {d} -> {d}", .{ okText(p.ok), p.ms, hs2, hs3 });
        p = probe(e, ns_kernel, "10.88.0.2", 64, 5_000);
        report.add("kernel->zwg on the zwg-initiated session", p.ok, "", .{});

        drive.step("8. roaming: zwg's source address moves 10.99.0.2 -> 10.99.0.3", .{});
        e.must(ns_zwg, &.{ e.ip, "address", "add", "10.99.0.3/24", "dev", veth_z }) catch {};
        e.must(ns_zwg, &.{ e.ip, "route", "replace", "10.99.0.0/24", "dev", veth_z, "src", "10.99.0.3" }) catch {};
        p = probe(e, ns_zwg, "10.88.0.1", 64, 5_000);
        const ep = kernel.currentEndpoint(e) catch "?";
        report.add("kernel follows zwg's new address (zwg packets authenticate the roam)", p.ok and std.mem.startsWith(u8, ep, "10.99.0.3:"), "kernel endpoint for zwg = {s}", .{ep});
        p = probe(e, ns_kernel, "10.88.0.2", 64, 5_000);
        report.add("kernel->zwg at the new address", p.ok, "", .{});

        if (!quick) {
            drive.step("9. time-based rekey: zwg initiated this session; after REKEY_AFTER_TIME (120 s) zwg must rekey on send", .{});
            const t0 = nowS(e.io);
            var hs_rekey: i64 = hs3;
            var probes_ok = true;
            while (nowS(e.io) - t0 < 150) {
                const q = probe(e, ns_zwg, "10.88.0.1", 64, 5_000);
                probes_ok = probes_ok and q.ok;
                hs_rekey = kernel.handshake(e) catch hs_rekey;
                if (hs_rekey > hs3) break;
                sleepMs(e.io, 5000);
            }
            const age = hs_rekey - hs3;
            report.add("zwg rekeys after REKEY_AFTER_TIME (kernel as responder)", hs_rekey > hs3 and age >= 115 and age <= 140, "new handshake {d} s after the previous one (expected ~120 s); traffic during rekey {s}", .{ age, if (probes_ok) "uninterrupted" else "had losses" });
            const q = probe(e, ns_kernel, "10.88.0.2", 64, 5_000);
            report.add("traffic on the rekeyed session", q.ok, "", .{});
        }
        kernel_show = kernel.show(e);
    }

    drive.step("teardown", .{});
    if (zwg.child != null) final_log = zwg.stop(e);
    const st = statusSummary(e, final_log);
    if (final_log.len != 0) report.add("zwg final status (wg show style)", std.mem.find(u8, st, "latest handshake") != null and std.mem.find(u8, st, "transfer") != null, "{s}", .{st});
    if (echo_k) |*c| c.kill(e.io);
    if (echo_z) |*c| c.kill(e.io);
    kernel.down(e);
    cleanupMain(e);
    const left = e.run(null, &.{ e.ip, "netns", "list" }) catch null;
    const clean = if (left) |l| std.mem.find(u8, l.stdout, "zwg-live") == null else false;
    report.add("teardown: namespaces, interfaces, keys removed", clean, "", .{});

    // Results file.
    var text: std.Io.Writer.Allocating = .init(e.gpa);
    const w = &text.writer;
    const uname = e.run(null, &.{ "/usr/bin/uname", "-sr" }) catch null;
    const wgv = e.run(null, &.{ e.wg_tool, "--version" }) catch null;
    try w.print("zwg live test, WSL/Linux internal (netns), started {d} (unix), {d} s\n", .{ started, nowS(e.io) - started });
    try w.print("host: {s}", .{if (uname) |u| u.stdout else "?\n"});
    try w.print("official peer: Linux kernel WireGuard ({s})\n", .{if (wgv) |v| std.mem.trim(u8, v.stdout, " \r\n") else "?"});
    try w.print("our peer: {s} (Linux /dev/net/tun backend)\n", .{e.zwg orelse "?"});
    try w.print("topology: netns {s} [{s} 10.99.0.1, zwgk0 10.88.0.1] <-veth-> netns {s} [{s} 10.99.0.2, zwgz0 10.88.0.2], MTU {d}\n\n", .{ ns_kernel, veth_k, ns_zwg, veth_z, mtu });
    try report.write(w, "RESULT", if (kernel_show.len != 0) e.print("kernel `wg show` before teardown (keys are throwaway):\n{s}", .{kernel_show}) else "");
    Io.Dir.cwd().writeFile(e.io, .{ .sub_path = out_path, .data = text.written() }) catch |err| std.debug.print("cannot write {s}: {t}\n", .{ out_path, err });
    std.debug.print("\n{s}\nresults written to {s}\n", .{ text.written(), out_path });
    return report.passed();
}

// ------------------------------------------------------------ serve

/// Control channel for the Windows driver: one command per line on stdin,
/// one reply line ("OK ..." / "ERR ...") on stdout. Private keys arrive on
/// stdin, never on a command line.
fn serve(e: *Env) !void {
    var in_buf: [4096]u8 = undefined;
    var in = Io.File.stdin().readerStreaming(e.io, &in_buf);
    var out_buf: [8192]u8 = undefined;
    var out_w = Io.File.stdout().writer(e.io, &out_buf);
    const out = &out_w.interface;

    cleanupMain(e);
    try makeRunDir(e);
    var kernel: ?Kernel = null;
    var zwg: ?Zwg = null;
    var echo: ?std.process.Child = null;
    defer {
        if (zwg) |*z| _ = z.stop(e);
        if (kernel) |*k| k.down(e);
        if (echo) |*c| c.kill(e.io);
        cleanupMain(e);
    }

    try out.print("READY {s}\n", .{info(e)});
    try out.flush();
    while (true) {
        const line_opt = in.interface.takeDelimiter('\n') catch null;
        const line = std.mem.trim(u8, line_opt orelse break, " \r\n");
        var words: [12][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        while (it.next()) |wd| : (n += 1) {
            if (n == words.len) break;
            words[n] = try e.gpa.dupe(u8, wd);
        }
        if (n == 0) continue;
        const reply = handle(e, words[0..n], &kernel, &zwg, &echo) catch |err| e.print("ERR {t}", .{err});
        try out.print("{s}\n", .{reply});
        try out.flush();
        if (std.mem.eql(u8, words[0], "quit")) break;
    }
}

fn info(e: *Env) []const u8 {
    const a = e.run(null, &.{ e.ip, "-4", "-o", "address", "show", "dev", "eth0" }) catch return "eth0=? gw=?";
    const r = e.run(null, &.{ e.ip, "-4", "route", "show", "default" }) catch return "eth0=? gw=?";
    // "2: eth0    inet 172.22.146.194/20 brd ..." / "default via 172.22.144.1 dev eth0 ..."
    var addr: []const u8 = "?";
    if (std.mem.find(u8, a.stdout, "inet ")) |i| {
        const rest = a.stdout[i + 5 ..];
        addr = rest[0 .. std.mem.findAny(u8, rest, "/ ") orelse rest.len];
    }
    var gw: []const u8 = "?";
    if (std.mem.find(u8, r.stdout, "via ")) |i| {
        const rest = r.stdout[i + 4 ..];
        gw = rest[0 .. std.mem.findScalar(u8, rest, ' ') orelse rest.len];
    }
    return e.print("eth0={s} gw={s}", .{ addr, gw });
}

fn handle(e: *Env, w: []const []const u8, kernel: *?Kernel, zwg: *?Zwg, echo: *?std.process.Child) ![]const u8 {
    const c = w[0];
    if (std.mem.eql(u8, c, "quit")) return "OK bye";
    if (std.mem.eql(u8, c, "info")) return e.print("OK {s}", .{info(e)});
    if (std.mem.eql(u8, c, "echo-start")) {
        if (echo.* == null) echo.* = try std.process.spawn(e.io, .{ .argv = &.{ e.self_exe, "echo", "7777" }, .stdin = .ignore, .stdout = .ignore });
        return "OK";
    }
    // kernel-up <if> <port> <addr/len> <peer pub> <allowed> <endpoint|-> <private key>
    if (std.mem.eql(u8, c, "kernel-up") and w.len == 8) {
        if (kernel.*) |*k| k.down(e);
        kernel.* = .{
            .ns = null,
            .ifname = w[1],
            .port = try std.fmt.parseInt(u16, w[2], 10),
            .addr = w[3],
            .peer_pub = w[4],
            .allowed = w[5],
            .endpoint = if (std.mem.eql(u8, w[6], "-")) null else w[6],
        };
        try kernel.*.?.up(e, w[7]);
        return "OK";
    }
    if (std.mem.eql(u8, c, "kernel-reset")) {
        try (kernel.* orelse return error.NoKernelPeer).resetPeer(e);
        return "OK";
    }
    if (std.mem.eql(u8, c, "kernel-port") and w.len == 2) {
        try (if (kernel.*) |*k| k else return error.NoKernelPeer).setPort(e, try std.fmt.parseInt(u16, w[1], 10));
        return "OK";
    }
    if (std.mem.eql(u8, c, "kernel-hs")) {
        return e.print("OK {d}", .{try (if (kernel.*) |*k| k else return error.NoKernelPeer).handshake(e)});
    }
    if (std.mem.eql(u8, c, "kernel-endpoint")) {
        return e.print("OK {s}", .{try (if (kernel.*) |*k| k else return error.NoKernelPeer).currentEndpoint(e)});
    }
    if (std.mem.eql(u8, c, "kernel-show")) {
        const s = (if (kernel.*) |*k| k else return error.NoKernelPeer).show(e);
        return e.print("OK {s}", .{oneLine(e, s)});
    }
    if (std.mem.eql(u8, c, "kernel-down")) {
        if (kernel.*) |*k| k.down(e);
        kernel.* = null;
        return "OK";
    }
    // zwg-up <name> <port> <addr/len> <peer pub> <allowed> <endpoint> <private key>
    if (std.mem.eql(u8, c, "zwg-up") and w.len == 8) {
        if (zwg.*) |*z| _ = z.stop(e);
        zwg.* = .{
            .ns = null,
            .name = w[1],
            .port = try std.fmt.parseInt(u16, w[2], 10),
            .addr = w[3],
            .peer_pub = w[4],
            .allowed = w[5],
            .endpoint = w[6],
            .private_b64 = w[7],
        };
        try zwg.*.?.start(e);
        return "OK";
    }
    // zwg-restart [new listen port]
    if (std.mem.eql(u8, c, "zwg-restart")) {
        const z = if (zwg.*) |*z| z else return error.NoZwgPeer;
        const st = statusSummary(e, z.stop(e));
        if (w.len == 2) z.port = try std.fmt.parseInt(u16, w[1], 10);
        sleepMs(e.io, 1100);
        try z.start(e);
        return e.print("OK {s}", .{st});
    }
    if (std.mem.eql(u8, c, "zwg-down")) {
        const z = if (zwg.*) |*z| z else return error.NoZwgPeer;
        const st = statusSummary(e, z.stop(e));
        zwg.* = null;
        return e.print("OK {s}", .{st});
    }
    // probe <dst> <bytes> <timeout ms>
    if (std.mem.eql(u8, c, "probe") and w.len == 4) {
        const p = probe(e, null, w[1], try std.fmt.parseInt(usize, w[2], 10), try std.fmt.parseInt(u32, w[3], 10));
        return if (p.ok) e.print("OK {d}", .{p.ms}) else "ERR timeout";
    }
    // ping <dst> <icmp payload bytes>
    if (std.mem.eql(u8, c, "ping") and w.len == 3) {
        if (e.ping == null) return "ERR ping not installed";
        return if (ping(e, null, w[1], try std.fmt.parseInt(usize, w[2], 10))) "OK" else "ERR no reply";
    }
    return "ERR unknown command";
}

fn oneLine(e: *Env, s: []const u8) []const u8 {
    const out = e.gpa.dupe(u8, std.mem.trim(u8, s, " \r\n")) catch return "";
    for (out) |*ch| if (ch.* == '\n') {
        ch.* = '|';
    };
    return out;
}
