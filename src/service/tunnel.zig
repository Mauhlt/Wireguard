//! The service process: `zwg.exe /tunnelservice <name> <user SID>`, started
//! only by the service control manager (Windows only).
//!
//! ServiceMain: register the control handler, report START_PENDING, then
//! load the DPAPI-protected configuration, resolve endpoints, create the
//! Wintun adapter (tun.Native), set addresses and routes, create the
//! device, open the control pipe, report RUNNING and run the device loop
//! until SERVICE_CONTROL_STOP / SHUTDOWN sets the stop event (the device's
//! `external_stop`). Then STOP_PENDING, tear down (closing the adapter
//! removes it with its addresses and routes), STOPPED with an exit code
//! from `state.Exit`. Everything is logged to the tunnel's bounded log;
//! no key ever is.

const std = @import("std");
const win = @import("win32.zig");
const names = @import("names.zig");
const state = @import("state.zig");
const store = @import("store.zig");
const log = @import("log.zig");
const pipe = @import("pipe.zig");
const device = @import("../device/root.zig");
const tun = @import("../tun/root.zig");
const config = device.config;

const Globals = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    user_sid: []const u8,
    status_handle: ?win.SERVICE_STATUS_HANDLE = null,
    lock: win.SRWLOCK = .{},
    machine: state.Machine,
    stop_event: win.HANDLE,
};

var g: Globals = undefined;

/// Entry for `/tunnelservice`: hands the thread to the SCM dispatcher,
/// which calls `serviceMain` on a new thread and returns when it stopped.
pub fn serviceProcess(gpa: std.mem.Allocator, io: std.Io, name: []const u8, user_sid: []const u8, errw: *std.Io.Writer) !u8 {
    if (!names.isValid(name) or !names.isAccountSidString(user_sid)) {
        try errw.writeAll("zwg: /tunnelservice: bad arguments\n");
        return 2;
    }
    g = .{
        .gpa = gpa,
        .io = io,
        .name = name,
        .user_sid = user_sid,
        .machine = state.Machine.init(.{ .ctx = &g, .report = report }),
        .stop_event = win.CreateEventW(null, 1, 0, null) orelse return error.SystemResources,
    };
    const table = [_]win.SERVICE_TABLE_ENTRYW{
        .{ .name = std.unicode.utf8ToUtf16LeStringLiteral(""), .proc = serviceMain },
        .{ .name = null, .proc = null },
    };
    if (win.StartServiceCtrlDispatcherW(&table) == 0) {
        if (win.GetLastError() == win.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            try errw.writeAll("zwg: /tunnelservice is started by the service control manager (use `zwg installtunnel`)\n");
        } else try errw.print("zwg: StartServiceCtrlDispatcher failed: Win32 error {d}\n", .{win.GetLastError()});
        return 1;
    }
    return 0;
}

fn report(ctx: *anyopaque, r: state.Report) void {
    const gl: *Globals = @ptrCast(@alignCast(ctx));
    const h = gl.status_handle orelse return;
    const st: win.SERVICE_STATUS = .{
        .service_type = win.SERVICE_WIN32_OWN_PROCESS,
        .current_state = @intFromEnum(r.state),
        .controls_accepted = r.controls_accepted,
        .win32_exit_code = r.win32_exit_code,
        .service_specific_exit_code = r.service_exit_code,
        .check_point = r.checkpoint,
        .wait_hint = r.wait_hint_ms,
    };
    _ = win.SetServiceStatus(h, &st);
}

fn locked(comptime f: anytype, args: anytype) void {
    win.AcquireSRWLockExclusive(&g.lock);
    defer win.ReleaseSRWLockExclusive(&g.lock);
    @call(.auto, f, .{&g.machine} ++ args);
}

fn handler(control: u32, event_type: u32, event_data: ?*anyopaque, context: ?*anyopaque) callconv(.winapi) u32 {
    _ = event_type;
    _ = event_data;
    _ = context;
    win.AcquireSRWLockExclusive(&g.lock);
    const r = g.machine.control(@enumFromInt(control));
    win.ReleaseSRWLockExclusive(&g.lock);
    switch (r) {
        .handled_stop => {
            log.print("stop requested (control {d})", .{control});
            _ = win.SetEvent(g.stop_event);
            return win.ERROR_SUCCESS;
        },
        .handled => return win.ERROR_SUCCESS,
        .not_implemented => return win.ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn serviceMain(argc: u32, argv: ?[*]?win.LPWSTR) callconv(.winapi) void {
    _ = argc;
    _ = argv;
    var nb: [names.max_service_name]u8 = undefined;
    var wb: [names.max_service_name + 1]u16 = undefined;
    const svc = win.W(&wb, names.serviceName(&nb, g.name)) catch return;
    g.status_handle = win.RegisterServiceCtrlHandlerExW(svc.ptr, handler, null) orelse return;
    locked(state.Machine.starting, .{});

    const paths = store.Paths.init(g.name) catch null;
    if (paths) |*p| log.open(p.log()) catch {};
    defer log.close();
    log.print("tunnel {s}: service starting (pid {d})", .{ g.name, win.GetCurrentProcessId() });

    const exit = runTunnel(if (paths) |*p| p else null);
    log.print("tunnel {s}: service stopped: {s}", .{ g.name, exit.message() });
    locked(state.Machine.stopped, .{exit});
}

fn runTunnel(paths: ?*const store.Paths) state.Exit {
    const gpa = g.gpa;
    const p = paths orelse return .config_unreadable;

    // The configuration: decrypt, parse, wipe the text.
    var c = blk: {
        const text = store.loadConfig(gpa, p) catch |err| {
            log.print("cannot read the stored configuration: {s}", .{@errorName(err)});
            return .config_unreadable;
        };
        defer {
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }
        var diag: config.Diagnostic = .{};
        break :blk config.parse(gpa, text, &diag) catch |err| {
            // Diagnostic messages never contain key material.
            if (err == error.InvalidConfig) log.print("invalid configuration: {f}", .{diag}) else log.print("configuration: {s}", .{@errorName(err)});
            return .config_invalid;
        };
    };
    defer c.deinit();
    locked(state.Machine.starting, .{});

    // Endpoint names: one that does not resolve yet (at boot the network
    // may not be up) is looked up again by the device, with backoff, rather
    // than failing the service; so is one whose peer stops answering
    // (dynamic DNS).
    const peers = gpa.alloc(device.device.PeerConfig, c.peers.len) catch return .device_failed;
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(peers)); // preshared keys
        gpa.free(peers);
    }
    for (c.peers, peers) |*cp, *pc| {
        pc.* = .{
            .public_key = cp.public_key,
            .preshared_key = cp.preshared_key,
            .allowed_ips = cp.allowed_ips,
            .persistent_keepalive = cp.persistent_keepalive,
            .endpoint_name = endpointName(cp.endpoint),
            .endpoint = if (cp.endpoint) |e| e.literal() orelse device.device.resolver.systemLookup(null, g.io, e.host, e.port) catch |err| blk: {
                log.print("cannot resolve endpoint {f} yet: {s}; retrying in the background", .{ e, @errorName(err) });
                break :blk null;
            } else null,
        };
    }
    locked(state.Machine.starting, .{});

    const mtu = c.interface.mtu orelse tun.default_mtu;
    var native = tun.Native.open(g.name, .{ .mtu = mtu }) catch |err| {
        log.print("cannot create the Wintun adapter: {s}", .{@errorName(err)});
        return if (err == error.WintunNotFound or err == error.WintunUntrusted) .wintun_missing else .adapter_failed;
    };
    defer native.close();
    const t = native.tun();
    for (c.interface.addresses) |a| t.setAddress(toTunCidr(a)) catch |err| {
        log.print("cannot set address {f}: {s}", .{ a, @errorName(err) });
        return .address_failed;
    };
    for (c.peers) |*cp| for (cp.allowed_ips) |a| t.addRoute(toTunCidr(a)) catch |err| {
        log.print("warning: route {f}: {s}", .{ a, @errorName(err) });
    };
    if (c.interface.dns.len + c.interface.dns_search.len != 0)
        log.print("warning: DNS is not configured by zwg yet; set it on the interface yourself", .{});
    locked(state.Machine.starting, .{});

    var clock: device.device.Clock = .{ .io = g.io };
    var options: device.device.Options = .{
        .private_key = c.interface.private_key,
        .listen_port = c.interface.listen_port,
        .peers = peers,
    };
    defer std.crypto.secureZero(u8, &options.private_key);
    const d = device.Device.create(gpa, &clock, t, options) catch |err| {
        log.print("cannot create the device: {s}", .{@errorName(err)});
        return .device_failed;
    };
    defer d.destroy();

    const server = pipe.Server.init(gpa, g.name, g.user_sid, &c) catch |err| {
        log.print("cannot create the control pipe: {s}", .{@errorName(err)});
        return .control_pipe_failed;
    };
    defer server.deinit();
    server.start() catch return .control_pipe_failed;
    d.external_stop = g.stop_event;
    d.control = server.control();

    log.print("tunnel {s} up: {d} peer(s), UDP port {d}", .{ g.name, c.peers.len, d.listen_port });
    locked(state.Machine.running, .{});
    d.run() catch |err| {
        log.print("device loop failed: {s}", .{@errorName(err)});
        locked(state.Machine.stopping, .{});
        return .device_failed;
    };
    locked(state.Machine.stopping, .{});
    log.print("tunnel {s} going down", .{g.name});
    return .ok;
}

fn toTunCidr(c: device.ip.Cidr) tun.Cidr {
    return switch (c.addr) {
        .v4 => |b| tun.Cidr.ip4(b, c.prefix),
        .v6 => |b| tun.Cidr.ip6(b, c.prefix),
    };
}

/// The endpoint's DNS name (null for an IP literal or none), as `zwg up`.
fn endpointName(endpoint: ?config.Endpoint) ?device.device.EndpointName {
    const e = endpoint orelse return null;
    if (e.literal() != null) return null;
    return .{ .host = e.host, .port = e.port };
}
