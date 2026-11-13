//! Live test across two real hosts: zwg on Windows with a REAL Wintun
//! adapter <-> WSL2, first against the official Linux kernel WireGuard,
//! then against zwg built for Linux (real /dev/net/tun).
//!
//! Run ONCE from an elevated prompt (after `zig build interop-live-wsl
//! -Dwintun=<unzipped wintun release>` as your normal user):
//!
//!     zig-out\bin\zwg-live-wsl.exe [--quick] [--out <file>]
//!
//! What it does (tests/interop/README.md, "Live test: Windows (Wintun) <->
//! WSL"), and what it removes again on success and on failure:
//!   * throwaway keys for three peers (Windows, kernel WG, zwg for Linux);
//!   * %TEMP%\zwgtest.conf (overwritten + deleted) and zwg.exe's log;
//!   * three inbound Windows Firewall rules named zwg-live-wsl-* (zwg's UDP
//!     port, the echo port on 10.88.0.1, ICMP echo on 10.88.0.1);
//!   * the Wintun adapter "zwgtest" (10.88.0.1/24), created by `zwg up` and
//!     removed by `zwg down`;
//!   * inside WSL, as root, through `zwg-live-linux serve`: a kernel
//!     WireGuard interface zwgk0 (10.88.0.2), then a zwg TUN zwgz0
//!     (10.88.0.3), a UDP echo server, key files under /run/zwg-live.
//! Checks: handshakes initiated from each side with each WSL peer, UDP echo
//! and ping both ways, MTU-sized packets (DF), a forced re-handshake, a
//! re-handshake after a dead session (Windows-side timers), endpoint roaming
//! (the WSL peer changes port; zwg on Windows must follow), and without
//! --quick zwg's time-based rekey after REKEY_AFTER_TIME. Results are printed
//! and written to a file (default zig-out\zwg-live-wsl-results.txt).
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const wg = @import("WireGuard");
const drive = @import("drive.zig");
const tun = wg.tun;

comptime {
    if (builtin.os.tag != .windows) @compileError("live_wsl.zig drives Windows + WSL");
}

const adapter = "zwgtest";
const win_ip = [4]u8{ 10, 88, 0, 1 };
const kernel_ip = [4]u8{ 10, 88, 0, 2 };
const zlinux_ip = [4]u8{ 10, 88, 0, 3 };
const echo_port: u16 = 7777;
const mtu: u16 = 1420;
const mtu_payload: usize = mtu - 28;
const fw_rules = [_][]const u8{ "zwg-live-wsl-wg", "zwg-live-wsl-echo", "zwg-live-wsl-icmp" };

const Options = struct {
    zwg: ?[]const u8 = null,
    linux_dir: ?[]const u8 = null,
    out: ?[]const u8 = null,
    quick: bool = false,
};

/// The WSL side: `wsl.exe -u root -e zwg-live-linux serve`, one command line
/// in, one reply line out. Its own log goes to our stderr.
const Wsl = struct {
    child: std.process.Child,
    in_buf: [1024]u8 = undefined,
    out_buf: [8192]u8 = undefined,
    writer: Io.File.Writer = undefined,
    reader: Io.File.Reader = undefined,
    io: Io,
    gpa: std.mem.Allocator,

    fn start(w: *Wsl) void {
        w.writer = w.child.stdin.?.writerStreaming(w.io, &w.in_buf);
        w.reader = w.child.stdout.?.readerStreaming(w.io, &w.out_buf);
    }

    fn line(w: *Wsl) ![]const u8 {
        const l = (try w.reader.interface.takeDelimiter('\n')) orelse return error.WslHelperGone;
        return w.gpa.dupe(u8, std.mem.trim(u8, l, " \r\n"));
    }

    /// Sends one command; returns the text after "OK" or error.Remote.
    /// `secret` (a private key) is appended without being echoed.
    fn call(w: *Wsl, comptime fmt: []const u8, args: anytype, secret: ?[]const u8) ![]const u8 {
        const cmd = try std.fmt.allocPrint(w.gpa, fmt, args);
        std.debug.print("  wsl> {s}{s}\n", .{ cmd, if (secret != null) " <private key>" else "" });
        try w.writer.interface.writeAll(cmd);
        if (secret) |s| try w.writer.interface.print(" {s}", .{s});
        try w.writer.interface.writeAll("\n");
        try w.writer.interface.flush();
        const reply = try w.line();
        std.debug.print("  wsl< {s}\n", .{reply});
        if (std.mem.startsWith(u8, reply, "OK")) return std.mem.trim(u8, reply[2..], " ");
        return error.Remote;
    }

    fn ok(w: *Wsl, comptime fmt: []const u8, args: anytype) bool {
        _ = w.call(fmt, args, null) catch return false;
        return true;
    }

    fn handshake(w: *Wsl) i64 {
        const r = w.call("kernel-hs", .{}, null) catch return -1;
        return std.fmt.parseInt(i64, r, 10) catch -1;
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    var opts: Options = .{};
    var args = try init.minimal.args.iterateAllocator(gpa);
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--zwg")) opts.zwg = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--linux")) opts.linux_dir = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--out")) opts.out = args.next() orelse return usage();
        if (std.mem.eql(u8, a, "--quick")) opts.quick = true;
    }

    if (!tun.windows.isElevated()) {
        std.debug.print(
            \\This test creates a Wintun adapter and temporary firewall rules, so it must
            \\run elevated. Open "Terminal (Admin)" and run it again. Nothing was changed.
            \\
        , .{});
        std.process.exit(2);
    }

    const exe_dir = try std.process.executableDirPathAlloc(io, gpa);
    const zwg = opts.zwg orelse try std.fs.path.join(gpa, &.{ exe_dir, "zwg.exe" });
    const linux_dir = opts.linux_dir orelse try std.fs.path.join(gpa, &.{ exe_dir, "..", "linux" });
    const out_path = opts.out orelse try std.fs.path.join(gpa, &.{ exe_dir, "..", "zwg-live-wsl-results.txt" });
    const zwg_dir = std.fs.path.dirname(zwg) orelse ".";
    const wintun_dll = try std.fs.path.join(gpa, &.{ zwg_dir, "wintun.dll" });
    for ([_][]const u8{ zwg, wintun_dll, try std.fs.path.join(gpa, &.{ linux_dir, "zwg" }), try std.fs.path.join(gpa, &.{ linux_dir, "zwg-live-linux" }) }) |p| {
        Io.Dir.cwd().access(io, p, .{}) catch {
            std.debug.print("missing {s}\nBuild first (unelevated): zig build interop-live-wsl -Dwintun=<folder with the unzipped wintun release>\nNothing was changed.\n", .{p});
            std.process.exit(2);
        };
    }

    const temp = init.environ_map.get("TEMP") orelse return drive.fail("TEMP not set", .{});
    const ok = run(gpa, io, temp, zwg, linux_dir, out_path, opts.quick) catch |err| blk: {
        std.debug.print("driver error: {t}\n", .{err});
        break :blk false;
    };
    std.process.exit(if (ok) 0 else 1);
}

fn usage() error{InteropFailed} {
    return drive.fail("usage: zwg-live-wsl [--quick] [--out <file>] [--zwg <zwg.exe>] [--linux <dir with zwg + zwg-live-linux for Linux>]", .{});
}

/// C:\a\b -> /mnt/c/a/b (the WSL view of a Windows path).
fn wslPath(gpa: std.mem.Allocator, io: Io, win: []const u8) ![]const u8 {
    const r = try drive.run(gpa, io, &.{ "wsl.exe", "-e", "wslpath", "-a", win });
    if (!r.ok) return error.WslPath;
    return std.mem.trim(u8, r.stdout, " \r\n");
}

fn fmtIp(gpa: std.mem.Allocator, a: [4]u8) []const u8 {
    return std.fmt.allocPrint(gpa, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch "?";
}

/// Windows ping with DF; true only if real echo replies came back.
fn winPing(gpa: std.mem.Allocator, io: Io, dst: [4]u8, size: usize) bool {
    const r = drive.run(gpa, io, &.{ "ping.exe", "-n", "3", "-w", "2000", "-f", "-l", std.fmt.allocPrint(gpa, "{d}", .{size}) catch return false, fmtIp(gpa, dst) }) catch return false;
    return r.ok and std.mem.find(u8, r.stdout, "TTL=") != null;
}

fn probe(io: Io, dst: [4]u8, len: usize, timeout_ms: u32) ?i64 {
    return drive.udpProbe(io, dst, echo_port, len, timeout_ms) catch null;
}

fn sleepMs(io: Io, ms: i64) void {
    drive.sleepMs(io, ms);
}

/// zwg.exe running `up` with its output in a log file.
const WinZwg = struct {
    child: ?std.process.Child = null,
    log_path: []const u8,

    /// `zwg down`, then wait (TerminateProcess after 15 s); returns the log
    /// (zwg's final status lists both peers).
    fn stop(z: *WinZwg, gpa: std.mem.Allocator, io: Io, zwg: []const u8) []const u8 {
        if (z.child) |*c| {
            _ = drive.run(gpa, io, &.{ zwg, "down", adapter }) catch {};
            const handle = c.id.?;
            if (k32.WaitForSingleObject(handle, 15_000) != 0) {
                std.debug.print("  zwg.exe did not stop within 15 s; terminating it\n", .{});
                _ = k32.TerminateProcess(handle, 1);
            }
            _ = c.wait(io) catch {};
            z.child = null;
        }
        return Io.Dir.cwd().readFileAlloc(io, z.log_path, gpa, .limited(1 << 20)) catch "";
    }
};

const k32 = struct {
    extern "kernel32" fn WaitForSingleObject(h: std.os.windows.HANDLE, ms: u32) callconv(.winapi) u32;
    extern "kernel32" fn TerminateProcess(h: std.os.windows.HANDLE, code: u32) callconv(.winapi) c_int;
};

fn run(gpa: std.mem.Allocator, io: Io, temp: []const u8, zwg: []const u8, linux_dir: []const u8, out_path: []const u8, quick: bool) !bool {
    var report: drive.Report = .{ .gpa = gpa };
    const started = drive.nowS(io);
    const conf_path = try std.fmt.allocPrint(gpa, "{s}\\{s}.conf", .{ temp, adapter });
    var win_zwg: WinZwg = .{ .log_path = try std.fmt.allocPrint(gpa, "{s}\\{s}.log", .{ temp, adapter }) };

    const helper = try wslPath(gpa, io, try std.fs.path.join(gpa, &.{ linux_dir, "zwg-live-linux" }));
    const zwg_linux = try wslPath(gpa, io, try std.fs.path.join(gpa, &.{ linux_dir, "zwg" }));

    drive.step("cleanup of earlier runs", .{});
    _ = drive.run(gpa, io, &.{ "wsl.exe", "-u", "root", "-e", helper, "cleanup" }) catch {};
    for (fw_rules) |r| _ = drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "delete", "rule", try std.fmt.allocPrint(gpa, "name={s}", .{r}) }) catch {};
    _ = drive.run(gpa, io, &.{ zwg, "down", adapter }) catch {};

    // Keys (throwaway) and our UDP port.
    var wk = drive.KeyPair.generate(io);
    defer wk.wipe();
    var kk = drive.KeyPair.generate(io);
    defer kk.wipe();
    var zk = drive.KeyPair.generate(io);
    defer zk.wipe();
    var w_priv = drive.b64(wk.private);
    defer std.crypto.secureZero(u8, &w_priv);
    var k_priv = drive.b64(kk.private);
    defer std.crypto.secureZero(u8, &k_priv);
    var z_priv = drive.b64(zk.private);
    defer std.crypto.secureZero(u8, &z_priv);
    const w_pub = drive.b64(wk.public);
    const k_pub = drive.b64(kk.public);
    const z_pub = drive.b64(zk.public);
    const wport = blk: {
        var u = try wg.device.os.Udp.open(.v4, 0);
        defer u.close();
        break :blk u.localPort();
    };

    // ---- WSL side ---------------------------------------------------------
    drive.step("start the WSL side (root): {s} serve", .{helper});
    var wsl: Wsl = .{
        .child = try std.process.spawn(io, .{
            .argv = &.{ "wsl.exe", "-u", "root", "-e", helper, "serve", "--zwg", zwg_linux },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        }),
        .io = io,
        .gpa = gpa,
    };
    wsl.start();
    var wsl_running = true;
    defer if (wsl_running) {
        _ = wsl.call("quit", .{}, null) catch {};
        wsl.child.kill(io);
    };
    const ready = try wsl.line();
    if (!std.mem.startsWith(u8, ready, "READY ")) return drive.fail("WSL helper did not start: {s}", .{ready});
    const wsl_ip = field(ready, "eth0=") orelse return drive.fail("no WSL eth0 address: {s}", .{ready});
    const gw = field(ready, "gw=") orelse return drive.fail("no WSL default gateway: {s}", .{ready});
    report.add("WSL reachable, root helper running", true, "WSL eth0 {s}, Windows host as seen from WSL {s}", .{ wsl_ip, gw });

    // ---- Windows side -------------------------------------------------------
    var conf_buf: [2048]u8 = undefined;
    const conf = try std.fmt.bufPrint(&conf_buf,
        \\[Interface]
        \\PrivateKey = {s}
        \\ListenPort = {d}
        \\Address = 10.88.0.1/24
        \\MTU = {d}
        \\
        \\[Peer]
        \\PublicKey = {s}
        \\AllowedIPs = 10.88.0.2/32
        \\Endpoint = {s}:51820
        \\
        \\[Peer]
        \\PublicKey = {s}
        \\AllowedIPs = 10.88.0.3/32
        \\Endpoint = {s}:51821
        \\
    , .{ &w_priv, wport, mtu, &k_pub, wsl_ip, &z_pub, wsl_ip });
    try drive.writeFile(io, conf_path, conf);
    defer drive.shredFile(io, conf_path, conf.len);

    drive.step("Windows Firewall: temporary inbound rules", .{});
    _ = try drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "add", "rule", "name=zwg-live-wsl-wg", "dir=in", "action=allow", "protocol=UDP", try std.fmt.allocPrint(gpa, "localport={d}", .{wport}) });
    _ = try drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "add", "rule", "name=zwg-live-wsl-echo", "dir=in", "action=allow", "protocol=UDP", "localip=10.88.0.1", "localport=7777" });
    _ = try drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "add", "rule", "name=zwg-live-wsl-icmp", "dir=in", "action=allow", "protocol=icmpv4:8,any", "localip=10.88.0.1" });
    defer for (fw_rules) |r| {
        _ = drive.run(gpa, io, &.{ "netsh", "advfirewall", "firewall", "delete", "rule", std.fmt.allocPrint(gpa, "name={s}", .{r}) catch continue }) catch {};
    };

    drive.step("zwg up with a real Wintun adapter '{s}'", .{adapter});
    {
        var log = try Io.Dir.cwd().createFile(io, win_zwg.log_path, .{});
        defer log.close(io);
        win_zwg.child = try std.process.spawn(io, .{ .argv = &.{ zwg, "up", conf_path }, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log } });
    }
    var final_log: []const u8 = "";
    defer if (win_zwg.child != null) {
        _ = win_zwg.stop(gpa, io, zwg);
    };
    // The adapter is up when it carries 10.88.0.1 (bounded wait: the first
    // Wintun use installs the driver).
    var up = false;
    for (0..60) |_| {
        const r = drive.run(gpa, io, &.{ "netsh", "interface", "ipv4", "show", "addresses", adapter }) catch null;
        if (r) |o| if (std.mem.find(u8, o.stdout, "10.88.0.1") != null) {
            up = true;
            break;
        };
        sleepMs(io, 500);
    }
    if (!up) {
        final_log = win_zwg.stop(gpa, io, zwg);
        report.add("Wintun adapter up", false, "zwg output:\n{s}", .{final_log});
        return finish(gpa, io, &report, out_path, started, wsl_ip, final_log);
    }
    const mtu_out = drive.run(gpa, io, &.{ "netsh", "interface", "ipv4", "show", "subinterface", adapter }) catch null;
    report.add("Wintun adapter up", true, "{s} 10.88.0.1/24, zwg UDP {d}; {s}", .{ adapter, wport, if (mtu_out) |m| oneLine(gpa, m.stdout) else "" });

    // Echo on Windows (answers through the tunnel).
    var stop_echo = try tun.queue.Waker.init();
    defer stop_echo.deinit();
    const echo_thread = try std.Thread.spawn(.{}, echoThread, .{&stop_echo});
    defer {
        stop_echo.signal();
        echo_thread.join();
    }
    _ = wsl.call("echo-start", .{}, null) catch {};

    // ---- Phase K: kernel WireGuard -----------------------------------------
    drive.step("phase K: Windows zwg (Wintun) <-> Linux kernel WireGuard", .{});
    const ep_win = try std.fmt.allocPrint(gpa, "{s}:{d}", .{ gw, wport });
    phase_k: {
        _ = wsl.call("kernel-up zwgk0 51820 10.88.0.2/24 {s} 10.88.0.1/32 {s}", .{ &w_pub, ep_win }, &k_priv) catch
            break :phase_k report.add("kernel WireGuard up in WSL", false, "", .{});
        report.add("kernel WireGuard up in WSL", true, "zwgk0 10.88.0.2/24 UDP 51820", .{});

        drive.step("K1. Windows initiates", .{});
        var p = probe(io, kernel_ip, 64, 10_000);
        const hs1 = wsl.handshake();
        report.add("K1 handshake initiated by zwg/Windows, answered by kernel WG", p != null and hs1 > 0, "UDP echo Windows->WSL {s}; kernel latest-handshake {d}", .{ msText(gpa, p), hs1 });
        drive.step("K2. WSL -> Windows on that session", .{});
        report.add("K2 UDP echo kernel->Windows", wsl.ok("probe 10.88.0.1 64 5000", .{}), "", .{});
        drive.step("K3. ping both ways", .{});
        report.add("K3 ping Windows->kernel", winPing(gpa, io, kernel_ip, 56), "", .{});
        report.add("K3 ping kernel->Windows", wsl.ok("ping 10.88.0.1 56", .{}), "", .{});
        drive.step("K4. MTU-sized packets ({d}-byte IPv4, DF)", .{mtu});
        p = probe(io, kernel_ip, mtu_payload, 5_000);
        report.add("K4 MTU-sized UDP Windows->kernel->Windows", p != null, "{d}-byte payload = {d}-byte IP packet", .{ mtu_payload, mtu });
        report.add("K4 MTU-sized UDP kernel->Windows->kernel", wsl.ok("probe 10.88.0.1 {d} 5000", .{mtu_payload}), "", .{});
        report.add("K4 MTU-sized ping Windows->kernel (DF)", winPing(gpa, io, kernel_ip, mtu_payload), "-f -l {d}", .{mtu_payload});
        report.add("K4 MTU-sized ping kernel->Windows (DF)", wsl.ok("ping 10.88.0.1 {d}", .{mtu_payload}), "-M do -s {d}", .{mtu_payload});

        drive.step("K5. kernel initiates (forced: the kernel forgets its sessions)", .{});
        sleepMs(io, 1100);
        _ = wsl.call("kernel-reset", .{}, null) catch {};
        const k5 = wsl.ok("probe 10.88.0.1 64 10000", .{});
        const hs2 = wsl.handshake();
        report.add("K5 handshake initiated by kernel WG, answered by zwg/Windows", k5 and hs2 > hs1, "latest-handshake {d} -> {d}", .{ hs1, hs2 });

        drive.step("K6. roaming: the kernel moves to UDP 51830; zwg on Windows must follow", .{});
        _ = wsl.call("kernel-port 51830", .{}, null) catch {};
        report.add("K6 zwg/Windows follows the kernel's new port", wsl.ok("probe 10.88.0.1 64 5000", .{}), "echo WSL->Windows after the move", .{});
        p = probe(io, kernel_ip, 64, 5_000);
        report.add("K6 Windows->kernel at the new port", p != null, "", .{});

        if (!quick) {
            drive.step("K7. dead session: the kernel forgets, only Windows sends; zwg must re-handshake (~15 s)", .{});
            sleepMs(io, 1100);
            const hs_before = wsl.handshake();
            _ = wsl.call("kernel-reset", .{}, null) catch {};
            p = probe(io, kernel_ip, 64, 40_000);
            const hs3 = wsl.handshake();
            report.add("K7 zwg/Windows re-handshakes after KEEPALIVE+REKEY_TIMEOUT without replies", p != null and hs3 > hs_before, "echo after {s} (expected ~15 s); latest-handshake {d} -> {d}", .{ msText(gpa, p), hs_before, hs3 });

            drive.step("K8. time-based rekey: zwg/Windows initiated this session; it must rekey after 120 s", .{});
            const t0 = drive.nowS(io);
            var hs4 = hs3;
            var lost: usize = 0;
            while (drive.nowS(io) - t0 < 150) {
                if (probe(io, kernel_ip, 64, 5_000) == null) lost += 1;
                hs4 = wsl.handshake();
                if (hs4 > hs3) break;
                sleepMs(io, 5000);
            }
            const age = hs4 - hs3;
            report.add("K8 zwg/Windows rekeys after REKEY_AFTER_TIME", hs4 > hs3 and age >= 115 and age <= 140, "new handshake {d} s after the previous one (expected ~120 s); {d} probes lost", .{ age, lost });
        }
        const show = wsl.call("kernel-show", .{}, null) catch "";
        report.add("kernel `wg show`", true, "{s}", .{show});
        _ = wsl.call("kernel-down", .{}, null) catch {};
    }

    // ---- Phase Z: zwg for Linux --------------------------------------------
    drive.step("phase Z: Windows zwg (Wintun) <-> zwg for Linux (/dev/net/tun) in WSL", .{});
    phase_z: {
        _ = wsl.call("zwg-up zwgz0 51821 10.88.0.3/24 {s} 10.88.0.1/32 {s}", .{ &w_pub, ep_win }, &z_priv) catch
            break :phase_z report.add("zwg for Linux up in WSL", false, "", .{});
        report.add("zwg for Linux up in WSL", true, "zwgz0 10.88.0.3/24 UDP 51821", .{});

        drive.step("Z1. Windows initiates", .{});
        var p = probe(io, zlinux_ip, 64, 10_000);
        report.add("Z1 handshake initiated by zwg/Windows, answered by zwg/Linux", p != null, "UDP echo Windows->WSL {s}", .{msText(gpa, p)});
        report.add("Z2 UDP echo zwg/Linux->Windows", wsl.ok("probe 10.88.0.1 64 5000", .{}), "", .{});
        report.add("Z3 ping Windows->zwg/Linux", winPing(gpa, io, zlinux_ip, 56), "", .{});
        report.add("Z3 ping zwg/Linux->Windows", wsl.ok("ping 10.88.0.1 56", .{}), "", .{});
        p = probe(io, zlinux_ip, mtu_payload, 5_000);
        report.add("Z4 MTU-sized UDP Windows->zwg/Linux->Windows", p != null, "{d}-byte payload", .{mtu_payload});
        report.add("Z4 MTU-sized UDP zwg/Linux->Windows->zwg/Linux", wsl.ok("probe 10.88.0.1 {d} 5000", .{mtu_payload}), "", .{});
        report.add("Z4 MTU-sized ping Windows->zwg/Linux (DF)", winPing(gpa, io, zlinux_ip, mtu_payload), "", .{});
        report.add("Z4 MTU-sized ping zwg/Linux->Windows (DF)", wsl.ok("ping 10.88.0.1 {d}", .{mtu_payload}), "", .{});

        drive.step("Z5. zwg/Linux initiates (restarted: fresh state)", .{});
        const st = wsl.call("zwg-restart", .{}, null) catch "";
        report.add("Z5 zwg/Linux final status before restart", std.mem.find(u8, st, "latest handshake") != null, "{s}", .{st});
        report.add("Z5 handshake initiated by zwg/Linux, answered by zwg/Windows", wsl.ok("probe 10.88.0.1 64 10000", .{}), "", .{});

        drive.step("Z6. roaming: zwg/Linux restarts on UDP 51831; zwg on Windows must follow", .{});
        _ = wsl.call("zwg-restart 51831", .{}, null) catch {};
        report.add("Z6 zwg/Windows follows zwg/Linux to its new port", wsl.ok("probe 10.88.0.1 64 10000", .{}), "", .{});
        p = probe(io, zlinux_ip, 64, 5_000);
        report.add("Z6 Windows->zwg/Linux at the new port", p != null, "", .{});

        const st2 = wsl.call("zwg-down", .{}, null) catch "";
        report.add("Z7 zwg/Linux final status", std.mem.find(u8, st2, "latest handshake") != null, "{s}", .{st2});
    }

    // ---- teardown -------------------------------------------------------------
    drive.step("teardown", .{});
    final_log = win_zwg.stop(gpa, io, zwg);
    var hs_lines: usize = 0;
    var it = std.mem.splitScalar(u8, final_log, '\n');
    while (it.next()) |l| hs_lines += @intFromBool(std.mem.find(u8, l, "latest handshake") != null);
    report.add("zwg/Windows final status lists handshakes with both WSL peers", hs_lines == 2, "{d} peers with a handshake", .{hs_lines});
    _ = wsl.call("quit", .{}, null) catch {};
    _ = wsl.child.wait(io) catch {};
    wsl_running = false;
    _ = drive.run(gpa, io, &.{ "wsl.exe", "-u", "root", "-e", helper, "cleanup" }) catch {};
    const gone = drive.run(gpa, io, &.{ "netsh", "interface", "ipv4", "show", "addresses", adapter }) catch null;
    report.add("Wintun adapter removed", if (gone) |g| std.mem.find(u8, g.stdout, "10.88.0.1") == null else true, "", .{});
    return finish(gpa, io, &report, out_path, started, wsl_ip, final_log);
}

fn echoThread(stop: *tun.queue.Waker) void {
    drive.echoServe(echo_port, stop.handle) catch |err| std.debug.print("echo server: {t}\n", .{err});
}

fn finish(gpa: std.mem.Allocator, io: Io, report: *drive.Report, out_path: []const u8, started: i64, wsl_ip: []const u8, zwg_log: []const u8) !bool {
    var text: std.Io.Writer.Allocating = .init(gpa);
    const w = &text.writer;
    const ver = drive.run(gpa, io, &.{ "cmd.exe", "/c", "ver" }) catch null;
    const kernel = drive.run(gpa, io, &.{ "wsl.exe", "-e", "uname", "-sr" }) catch null;
    try w.print("zwg live test, Windows (real Wintun adapter) <-> WSL2, started {d} (unix), {d} s\n", .{ started, drive.nowS(io) - started });
    try w.print("Windows: {s}\n", .{if (ver) |v| std.mem.trim(u8, v.stdout, " \r\n") else "?"});
    try w.print("WSL: {s} at {s}\n", .{ if (kernel) |k| std.mem.trim(u8, k.stdout, " \r\n") else "?", wsl_ip });
    try w.print("tunnel: 10.88.0.1 (Windows, zwg + Wintun) <-> 10.88.0.2 (kernel WireGuard) / 10.88.0.3 (zwg for Linux), MTU {d}\n\n", .{mtu});
    try report.write(w, "RESULT", try std.fmt.allocPrint(gpa, "zwg.exe output (throwaway keys):\n{s}", .{zwg_log}));
    Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = text.written() }) catch |err| std.debug.print("cannot write {s}: {t}\n", .{ out_path, err });
    std.debug.print("\n{s}\nresults written to {s}\n", .{ text.written(), out_path });
    return report.passed();
}

fn field(line: []const u8, key: []const u8) ?[]const u8 {
    const i = std.mem.find(u8, line, key) orelse return null;
    const rest = line[i + key.len ..];
    const v = rest[0 .. std.mem.findScalar(u8, rest, ' ') orelse rest.len];
    return if (v.len == 0 or std.mem.eql(u8, v, "?")) null else v;
}

fn msText(gpa: std.mem.Allocator, p: ?i64) []const u8 {
    return if (p) |ms| std.fmt.allocPrint(gpa, "OK in {d} ms", .{ms}) catch "OK" else "FAILED";
}

fn oneLine(gpa: std.mem.Allocator, s: []const u8) []const u8 {
    const out = gpa.dupe(u8, std.mem.trim(u8, s, " \r\n")) catch return "";
    var n: usize = 0;
    var prev_space = false;
    for (out) |ch| {
        const c: u8 = if (ch == '\r' or ch == '\n' or ch == '\t') ' ' else ch;
        if (c == ' ' and prev_space) continue;
        prev_space = c == ' ';
        out[n] = c;
        n += 1;
    }
    return out[0..n];
}
