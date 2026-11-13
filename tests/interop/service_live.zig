//! End-to-end check of `zwg installtunnel` (the Windows tunnel service),
//! run ONCE by the owner from an elevated prompt:
//!
//!   zig build interop-service
//!   zig-out\bin\zwg-service-live.exe --zwg zig-out\bin\zwg.exe
//!
//! What it does (and undoes, on success and on failure):
//!  1. refuses unless elevated (changes nothing);
//!  2. writes two throwaway .conf files to %TEMP% (zwgsvctest.conf: the
//!     tunnel, 10.79.0.1/24, peer 10.79.0.2 at 127.0.0.1:<port>, keepalive
//!     25 s; zwgsvcpeer.conf: the peer) and starts the peer as an ordinary
//!     `zwg up --tun udp:<port>` process (no adapter, no privileges);
//!  3. `zwg installtunnel zwgsvctest.conf`: service zwgTunnel$zwgsvctest,
//!     %ProgramData%\zwg\tunnels\zwgsvctest\{zwg.exe,wintun.dll,tunnel.conf.dpapi},
//!     %ProgramData%\zwg\logs\zwgsvctest.log, a Wintun adapter "zwgsvctest"
//!     with 10.79.0.1/24 and a route to 10.79.0.2/32;
//!  4. checks the store: protected directory DACL (SYSTEM + Administrators),
//!     the stored file is ciphertext, and an ordinary-user token cannot open it;
//!  5. AS AN ORDINARY USER (impersonating this user's token with
//!     Administrators deny-only, medium integrity): reads the status over
//!     the control pipe until the handshake with the peer shows;
//!  6. data both ways through the real Wintun adapter: a UDP datagram from
//!     this host to 10.79.0.2 comes out of the peer's TUN, and the reply
//!     pushed into the peer's TUN arrives at the sending socket;
//!  7. as "another user" (the same token with this user's SID deny-only too):
//!     the pipe refuses;
//!  8. as the ordinary user: `down` (service stops), `up` (starts again,
//!     handshake again);
//!  9. `zwg uninstalltunnel zwgsvctest`, then checks the service, the files
//!     and the adapter are gone. Teardown on any failure: uninstall, kill
//!     the peer, overwrite and delete both .conf files.
//!
//! Kept separate from tests/interop/live.zig (WireGuard for Windows interop),
//! so the two can be folded into one live run later.

const std = @import("std");
const Io = std.Io;
const wg = @import("WireGuard");
const drive = @import("drive.zig");
const ip = @import("ip.zig");

const svc = wg.service;
const win = svc.win32;
const tun = wg.tun;

const name = "zwgsvctest";
const addr_svc = [4]u8{ 10, 79, 0, 1 };
const addr_peer = [4]u8{ 10, 79, 0, 2 };

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    var zwg: ?[]const u8 = null;
    var args = try init.minimal.args.iterateAllocator(arena);
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--zwg")) zwg = args.next();
    }
    const zwg_path = zwg orelse {
        std.debug.print("usage: zwg-service-live --zwg <path to zwg.exe>\n", .{});
        std.process.exit(2);
    };
    if (!win.isElevated()) {
        std.debug.print(
            \\This driver installs and removes a temporary zwg tunnel service, so it
            \\must run elevated. Open "Terminal (Admin)" and run it again.
            \\Nothing was changed.
            \\
        , .{});
        std.process.exit(2);
    }
    {
        var m = try svc.scm.Manager.open(win.SC_MANAGER_CONNECT);
        defer m.close();
        if (svc.scm.Service.open(&m, name, win.SERVICE_QUERY_STATUS)) |s_| {
            var s = s_;
            s.close();
            return drive.fail("a tunnel named {s} is already installed; remove it first (zwg uninstalltunnel {s})", .{ name, name });
        } else |_| {}
    }

    const temp = init.environ_map.get("TEMP") orelse return drive.fail("TEMP not set", .{});
    const conf_path = try std.fmt.allocPrint(arena, "{s}\\{s}.conf", .{ temp, name });
    const peer_path = try std.fmt.allocPrint(arena, "{s}\\zwgsvcpeer.conf", .{temp});

    var tunnel_keys = drive.KeyPair.generate(io);
    defer tunnel_keys.wipe();
    var peer_keys = drive.KeyPair.generate(io);
    defer peer_keys.wipe();
    const peer_port = try drive.freePort();
    const peer_tun_port = try drive.freePort();

    var conf_buf: [1024]u8 = undefined;
    const conf = try (drive.Conf{
        .private = tunnel_keys.private,
        .address = "10.79.0.1/24",
        .peer_public = peer_keys.public,
        .allowed_ips = "10.79.0.2/32",
        .endpoint_port = peer_port,
        .persistent_keepalive = 25,
    }).render(&conf_buf);
    try drive.writeFile(io, conf_path, conf);
    defer drive.shredFile(io, conf_path, conf.len);
    var peer_buf: [1024]u8 = undefined;
    const peer_conf = try (drive.Conf{
        .private = peer_keys.private,
        .listen_port = peer_port,
        .peer_public = tunnel_keys.public,
        .allowed_ips = "10.79.0.1/32",
    }).render(&peer_buf);
    try drive.writeFile(io, peer_path, peer_conf);
    defer drive.shredFile(io, peer_path, peer_conf.len);

    drive.step("start the peer: zwg up --tun udp:{d} (UDP {d})", .{ peer_tun_port, peer_port });
    const tun_arg = try std.fmt.allocPrint(arena, "udp:{d}", .{peer_tun_port});
    var peer = try std.process.spawn(io, .{ .argv = &.{ zwg_path, "up", peer_path, "--tun", tun_arg } });
    defer peer.kill(io);
    var peer_tun = try tun.UdpTun.open(0, 1500);
    defer peer_tun.close();
    peer_tun.setPeerPort(peer_tun_port);
    peer_tun.hello();

    drive.step("zwg installtunnel {s}", .{conf_path});
    var installed = false;
    defer if (installed) {
        drive.step("teardown: uninstall", .{});
        _ = svc.cli.elevatedUninstall(name);
    };
    {
        const r = try drive.run(arena, io, &.{ zwg_path, "installtunnel", conf_path });
        installed = true; // even a failed install may have left something: uninstall is idempotent
        std.debug.print("{s}{s}", .{ r.stdout, r.stderr });
        if (!r.ok) return drive.fail("installtunnel failed", .{});
    }
    drive.shredFile(io, conf_path, conf.len); // the service has its own (encrypted) copy now

    try checkStore(gpa);

    drive.step("as an ordinary user: status over the control pipe until the handshake shows", .{});
    try waitForHandshake(gpa, io, peer_keys.public);

    drive.step("data through the Wintun adapter, both directions", .{});
    try dataBothWays(io, &peer_tun);

    drive.step("as another user: the control pipe refuses", .{});
    {
        const t = try asUser(true);
        defer revert(t);
        if (svc.pipe.query(gpa, name)) |raw| {
            gpa.free(raw);
            return drive.fail("the pipe answered a token without the installing user's SID", .{});
        } else |err| if (err != error.AccessDenied) return drive.fail("expected AccessDenied, got {s}", .{@errorName(err)});
    }

    // As the ordinary user would: zwg down / up as its own process whose
    // primary token is the restricted one (not by impersonating it on one of
    // our threads, which the SCM's state notification refuses).
    drive.step("as an ordinary user (own process): zwg down {s}, zwg up {s}", .{ name, name });
    {
        const t = win.restrictedToken(false) catch return drive.fail("cannot build a restricted token", .{});
        defer _ = win.CloseHandle(t);
        const steps = [_]struct { verb: []const u8, want: u32 }{
            .{ .verb = "down", .want = win.SERVICE_STOPPED },
            .{ .verb = "up", .want = win.SERVICE_RUNNING },
        };
        for (steps) |c| {
            var cmd_buf: [1024]u8 = undefined;
            const cmd = std.fmt.bufPrint(&cmd_buf, "\"{s}\" {s} {s}", .{ zwg_path, c.verb, name }) catch return drive.fail("command line too long", .{});
            var out: [2048]u8 = undefined;
            const r = win.runAsToken(t, cmd, &out, 60_000) catch |err| return drive.fail("zwg {s} as the ordinary user: {s}", .{ c.verb, @errorName(err) });
            std.debug.print("{s}", .{r.output});
            if (r.exit_code != 0) return drive.fail("{s} failed for the installing user (exit {d})", .{ c.verb, r.exit_code });
            try expectState(c.want);
        }
    }
    try waitForHandshake(gpa, io, peer_keys.public);

    drive.step("zwg show / zwg show {s} (CLI output)", .{name});
    {
        const r = try drive.run(arena, io, &.{ zwg_path, "show" });
        std.debug.print("{s}", .{r.stdout});
        if (!r.ok or std.mem.indexOf(u8, r.stdout, name) == null) return drive.fail("`zwg show` does not list {s}", .{name});
        const r2 = try drive.run(arena, io, &.{ zwg_path, "show", name });
        std.debug.print("{s}", .{r2.stdout});
        if (!r2.ok or std.mem.indexOf(u8, r2.stdout, "latest handshake") == null) return drive.fail("`zwg show {s}` shows no handshake", .{name});
        if (std.mem.indexOf(u8, r2.stdout, &drive.b64(tunnel_keys.private)) != null) return drive.fail("`zwg show` printed the private key", .{});
    }

    drive.step("zwg uninstalltunnel {s}", .{name});
    {
        const r = try drive.run(arena, io, &.{ zwg_path, "uninstalltunnel", name });
        std.debug.print("{s}{s}", .{ r.stdout, r.stderr });
        if (!r.ok) return drive.fail("uninstalltunnel failed", .{});
        installed = false;
    }
    try checkGone(arena, io);
    drive.step("service end-to-end test passed", .{});
}

fn asUser(deny_user: bool) !win.HANDLE {
    const t = win.restrictedToken(deny_user) catch return drive.fail("cannot build a restricted token", .{});
    if (win.ImpersonateLoggedOnUser(t) == 0) {
        _ = win.CloseHandle(t);
        return drive.fail("cannot impersonate the restricted token", .{});
    }
    return t;
}

fn revert(t: win.HANDLE) void {
    _ = win.RevertToSelf();
    _ = win.CloseHandle(t);
}

fn expectState(want: u32) !void {
    var m = try svc.scm.Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    var s = try svc.scm.Service.open(&m, name, win.SERVICE_QUERY_STATUS);
    defer s.close();
    const st = try s.status();
    if (st.status.current_state != want)
        return drive.fail("service state {s}, expected {s}", .{ svc.scm.stateName(st.status.current_state), svc.scm.stateName(want) });
}

/// Bounded wait (test tooling): ask the service at growing intervals,
/// ~15 s in total, as an ordinary user.
fn waitForHandshake(gpa: std.mem.Allocator, io: Io, peer_public: [32]u8) !void {
    var delay: i64 = 200;
    var waited: i64 = 0;
    while (waited < 15_000) : (waited += delay) {
        {
            const t = try asUser(false);
            defer revert(t);
            var st = svc.cli.queryStatus(gpa, name) catch |err| return drive.fail("status over the pipe as the installing user: {s}", .{@errorName(err)});
            defer st.deinit();
            if (st.peers.len != 1 or !std.mem.eql(u8, &st.peers[0].public_key, &peer_public))
                return drive.fail("the status does not list the peer", .{});
            if (st.peers[0].last_handshake_sec != 0) {
                std.debug.print("  handshake at {d}, tx {d} B, rx {d} B\n", .{ st.peers[0].last_handshake_sec, st.peers[0].tx_bytes, st.peers[0].rx_bytes });
                return;
            }
        }
        drive.sleepMs(io, delay);
        delay = @min(delay * 2, 2000);
    }
    return drive.fail("no handshake with the peer within 15 s (see %ProgramData%\\zwg\\logs\\{s}.log)", .{name});
}

/// 10.79.0.1:<p> -> 10.79.0.2:6000 leaves through the Wintun adapter, is
/// encrypted by the service and pops out of the peer's TUN; the reply
/// pushed into the peer's TUN goes back through the service and Wintun to
/// the socket (as a reply, so no firewall rule is needed).
fn dataBothWays(io: Io, peer_tun: *tun.UdpTun) !void {
    _ = io;
    var sock = try wg.device.os.Udp.open(.v4, 0);
    defer sock.close();
    const local_port = sock.localPort();
    const to: Io.net.IpAddress = .{ .ip4 = .{ .bytes = addr_peer, .port = 6000 } };
    const t = peer_tun.tun();
    var rbuf: [2048]u8 = undefined;
    const out_ok = blk: for (0..10) |_| {
        peer_tun.hello();
        sock.send(to, "to the peer") catch {};
        while (try drive.recvWithin(t, &rbuf, 1000)) |p| {
            const u = ip.parseUdp4(p) orelse continue;
            if (std.mem.eql(u8, u.payload, "to the peer") and std.mem.eql(u8, &u.src, &addr_svc) and u.dport == 6000) break :blk true;
        }
    } else false;
    if (!out_ok) return drive.fail("a datagram sent to 10.79.0.2 never came out of the peer's TUN", .{});
    std.debug.print("  out: 10.79.0.1:{d} -> 10.79.0.2:6000 arrived at the peer\n", .{local_port});

    var pbuf: [256]u8 = undefined;
    const reply = ip.buildUdp4(&pbuf, addr_peer, 6000, addr_svc, local_port, "back from the peer", 9);
    for (0..10) |_| {
        try t.write(reply);
        if (try wg.device.os.wait(&.{sock.waitHandle()}, std.time.ns_per_s)) |_| {
            var buf: [256]u8 = undefined;
            while (try sock.recv(&buf)) |dg| {
                if (std.mem.eql(u8, buf[0..dg.len], "back from the peer")) {
                    std.debug.print("  in: 10.79.0.2:6000 -> 10.79.0.1:{d} arrived at the socket\n", .{local_port});
                    return;
                }
            }
        }
    }
    return drive.fail("the reply pushed into the peer's TUN never reached the socket", .{});
}

fn checkStore(gpa: std.mem.Allocator) !void {
    drive.step("the store: protected directory, encrypted file, closed to ordinary users", .{});
    const p = try svc.store.Paths.init(name);
    var wbuf: [300]u16 = undefined;
    {
        const w = try win.W(&wbuf, p.root());
        var dacl: ?*win.ACL = null;
        var owner: ?win.PSID = null;
        var sd: ?win.PSECURITY_DESCRIPTOR = null;
        if (win.GetNamedSecurityInfoW(w.ptr, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION | win.DACL_SECURITY_INFORMATION, &owner, null, &dacl, null, &sd) != 0)
            return drive.fail("cannot read the store's security", .{});
        defer _ = win.LocalFree(sd);
        var control: u16 = 0;
        var rev: u32 = 0;
        _ = win.GetSecurityDescriptorControl(sd.?, &control, &rev);
        if (control & win.SE_DACL_PROTECTED == 0) return drive.fail("store DACL is not protected", .{});
        if (dacl.?.ace_count != 2) return drive.fail("store DACL has {d} ACEs, expected 2 (SYSTEM, Administrators)", .{dacl.?.ace_count});
        if (win.IsWellKnownSid(owner.?, win.WinBuiltinAdministratorsSid) == 0) return drive.fail("store owner is not Administrators", .{});
    }
    const blob = try svc.store.readAll(gpa, p.conf(), 1 << 20);
    defer gpa.free(blob);
    if (std.mem.indexOf(u8, blob, "PrivateKey") != null or std.mem.indexOf(u8, blob, "[Interface]") != null)
        return drive.fail("the stored configuration is plaintext", .{});
    {
        const t = try asUser(false);
        defer revert(t);
        if (svc.store.readAll(gpa, p.conf(), 1 << 20)) |b| {
            gpa.free(b);
            return drive.fail("an ordinary-user token could read the stored configuration", .{});
        } else |err| if (err != error.AccessDenied) return drive.fail("expected AccessDenied reading the store, got {s}", .{@errorName(err)});
    }
    std.debug.print("  {s}: protected, {d} bytes of DPAPI ciphertext, ordinary user denied\n", .{ p.conf(), blob.len });
}

fn checkGone(arena: std.mem.Allocator, io: Io) !void {
    drive.step("everything is gone: service, files, adapter", .{});
    var m = try svc.scm.Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    if (svc.scm.Service.open(&m, name, win.SERVICE_QUERY_STATUS)) |s_| {
        var s = s_;
        s.close();
        return drive.fail("the service still exists", .{});
    } else |_| {}
    const p = try svc.store.Paths.init(name);
    if (svc.store.exists(p.dir())) return drive.fail("{s} still exists", .{p.dir()});
    if (svc.store.exists(p.log())) return drive.fail("{s} still exists", .{p.log()});
    const r = try drive.run(arena, io, &.{ "netsh", "interface", "show", "interface" });
    if (std.mem.indexOf(u8, r.stdout, name) != null) return drive.fail("the adapter {s} still exists", .{name});
}
