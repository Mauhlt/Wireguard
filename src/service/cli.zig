//! `zwg` verbs for installed tunnels (Windows only). main.zig calls
//! `dispatch` first; null means "not mine" and main carries on.
//!
//!   zwg installtunnel <file.conf> [--auto]   one UAC prompt; install + start
//!   zwg uninstalltunnel <name>               one UAC prompt; stop + remove everything
//!   zwg show                                 list installed tunnels (unelevated)
//!   zwg show <name>                          live status over the pipe (unelevated)
//!   zwg down <name>                          stop the tunnel's service (unelevated, installing user)
//!   zwg up <name>                            start it again (unelevated, installing user)
//!
//! The two elevated steps re-launch zwg.exe through ShellExecuteEx "runas"
//! with a narrow internal verb and wait for its exit code (the elevated
//! child has no console of its own: SW_HIDE). Run from an elevated prompt,
//! they do the work in-process without a prompt.
//!
//! Internal verbs (not in the usage text):
//!   /installtunnel-elevated <abs path.conf> <user SID> <0|1 auto>
//!   /uninstalltunnel-elevated <name>
//!   /tunnelservice <name> <user SID>         (the service binary path)

const std = @import("std");
const win = @import("win32.zig");
const names = @import("names.zig");
const state = @import("state.zig");
const store = @import("store.zig");
const scm = @import("scm.zig");
const pipe = @import("pipe.zig");
const uapi = @import("uapi.zig");
const log = @import("log.zig");
const tunnel = @import("tunnel.zig");
const config = @import("../device/config.zig");
const tun = @import("../tun/root.zig");

pub const usage =
    \\  installtunnel <file.conf> [--auto]
    \\                         install the tunnel as a Windows service and start it (one UAC
    \\                         prompt; --auto: start at boot). Then, unelevated:
    \\  show                   list installed tunnels
    \\  show <name>            live status of an installed tunnel
    \\  down <name> / up <name>  stop / start an installed tunnel
    \\  uninstalltunnel <name> stop and remove an installed tunnel (one UAC prompt)
    \\
;

const start_timeout_ms = 45_000;
const stop_timeout_ms = 30_000;

/// Exit codes of the elevated child (and of the in-process path).
pub const Result = enum(u8) {
    ok = 0,
    failed = 1,
    bad_args = 2,
    not_elevated = 3,
    invalid_name = 4,
    config_unreadable = 5,
    config_invalid = 6,
    already_installed = 7,
    not_installed = 8,
    wintun_missing = 9,
    untrusted_dir = 10,
    store_failed = 11,
    service_failed = 12,
    start_timeout = 13,
    stop_timeout = 14,
    marked_for_delete = 15,
    cancelled = 16,
    /// 32 + state.Exit: the service started but stopped with that reason.
    service_exit_base = 32,
    _,

    fn fromExit(e: state.Exit) Result {
        return @enumFromInt(32 + @as(u8, @intCast(@intFromEnum(e))));
    }

    pub fn message(r: Result) []const u8 {
        return switch (r) {
            .ok => "done",
            .failed => "failed (see %ProgramData%\\zwg\\logs, readable by administrators)",
            .bad_args => "bad internal arguments",
            .not_elevated => "the elevated step is not elevated",
            .invalid_name => "invalid tunnel name: 1-32 of A-Z a-z 0-9 _ = + . - (the file name without .conf)",
            .config_unreadable => "cannot read the configuration file",
            .config_invalid => "the configuration file is invalid",
            .already_installed => "a tunnel with that name is already installed (zwg uninstalltunnel <name> first)",
            .not_installed => "no tunnel with that name is installed",
            .wintun_missing => tun.windows.wintun_hint,
            .untrusted_dir => "%ProgramData%\\zwg exists but is a link or not owned by Administrators/SYSTEM; remove it and retry",
            .store_failed => "cannot write the protected store under %ProgramData%\\zwg",
            .service_failed => "the service could not be created or configured",
            .start_timeout => "the service did not reach RUNNING in time (it was removed again)",
            .stop_timeout => "the service did not stop in time (it is marked for deletion)",
            .marked_for_delete => "a previous service of that name is still being deleted; close Services/sc and retry",
            .cancelled => "the UAC prompt was declined; nothing changed",
            else => if (@intFromEnum(r) >= 32 and @intFromEnum(r) - 32 <= @intFromEnum(state.Exit.bad_arguments))
                @as(state.Exit, @enumFromInt(@intFromEnum(r) - 32)).message()
            else
                "failed",
        };
    }
};

pub fn dispatch(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, errw: *std.Io.Writer) !?u8 {
    if (args.len == 0) return null;
    const cmd = args[0];
    const eql = std.mem.eql;

    if (eql(u8, cmd, "installtunnel") and (args.len == 2 or (args.len == 3 and eql(u8, args[2], "--auto"))))
        return try installTunnel(gpa, io, args[1], args.len == 3, out, errw);
    if (eql(u8, cmd, "uninstalltunnel") and args.len == 2)
        return try uninstallTunnel(gpa, io, args[1], out, errw);
    if (eql(u8, cmd, "show") and args.len == 1)
        return try listTunnels(gpa, out, errw);
    if (eql(u8, cmd, "show") and args.len == 2 and !names.looksLikeFile(args[1]))
        return try showTunnel(gpa, io, args[1], out, errw);
    if (eql(u8, cmd, "down") and args.len == 2 and !names.looksLikeFile(args[1]) and names.isValid(args[1]))
        return try controlTunnel(args[1], .stop, out, errw);
    if (eql(u8, cmd, "up") and args.len == 2 and !names.looksLikeFile(args[1]) and names.isValid(args[1]))
        return try controlTunnel(args[1], .start, out, errw);

    if (eql(u8, cmd, "/installtunnel-elevated") and args.len == 4)
        return @intFromEnum(elevatedInstall(gpa, io, args[1], args[2], eql(u8, args[3], "1")));
    if (eql(u8, cmd, "/uninstalltunnel-elevated") and args.len == 2)
        return @intFromEnum(elevatedUninstall(args[1]));
    if (eql(u8, cmd, "/tunnelservice") and args.len == 3)
        return try tunnel.serviceProcess(gpa, io, args[1], args[2], errw);
    return null;
}

// ---- install / uninstall (unelevated side) -----------------------------------------

fn installTunnel(gpa: std.mem.Allocator, io: std.Io, conf_path: []const u8, auto: bool, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    const name = names.fromPath(conf_path);
    if (!names.isValid(name)) return fail(errw, .invalid_name);
    // Validate before any UAC prompt: typos are reported right here.
    if (!try validateFile(gpa, io, conf_path, errw)) return 1;

    var in_w: [600]u16 = undefined;
    var abs_w: [600]u16 = undefined;
    const in = try win.W(&in_w, conf_path);
    const abs_len = win.GetFullPathNameW(in.ptr, abs_w.len, &abs_w, null);
    if (abs_len == 0 or abs_len >= abs_w.len) return fail(errw, .config_unreadable);
    var abs_buf: [1800]u8 = undefined;
    const abs_n = try std.unicode.utf16LeToUtf8(&abs_buf, abs_w[0..abs_len]);
    const abs = abs_buf[0..abs_n];
    if (std.mem.findScalar(u8, abs, '"') != null) return fail(errw, .config_unreadable);

    var sid_buf: [184]u8 = undefined;
    const sid = try win.currentUserSid(&sid_buf);

    try out.print("installing tunnel {s} (zwgTunnel${s}){s}...\n", .{ name, name, if (win.isElevated()) "" else ", asking for elevation once" });
    try out.flush();
    const r: Result = if (win.isElevated())
        elevatedInstall(gpa, io, abs, sid, auto)
    else blk: {
        var params: [2048]u8 = undefined;
        break :blk try runElevated(try std.fmt.bufPrint(&params, "/installtunnel-elevated \"{s}\" {s} {d}", .{ abs, sid, @intFromBool(auto) }));
    };
    if (r != .ok) return fail(errw, r);
    try out.print("tunnel {s} installed and running. `zwg show {s}` for status, `zwg down {s}` / `zwg up {s}` to stop / start, `zwg uninstalltunnel {s}` to remove.\n", .{ name, name, name, name, name });
    return 0;
}

fn uninstallTunnel(gpa: std.mem.Allocator, io: std.Io, arg: []const u8, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    _ = gpa;
    _ = io;
    const name = names.fromPath(arg);
    if (!names.isValid(name)) return fail(errw, .invalid_name);
    try out.print("removing tunnel {s}{s}...\n", .{ name, if (win.isElevated()) "" else ", asking for elevation once" });
    try out.flush();
    const r: Result = if (win.isElevated()) elevatedUninstall(name) else blk: {
        var params: [128]u8 = undefined;
        break :blk try runElevated(try std.fmt.bufPrint(&params, "/uninstalltunnel-elevated {s}", .{name}));
    };
    if (r != .ok) return fail(errw, r);
    try out.print("tunnel {s} removed (service, stored configuration, adapter)\n", .{name});
    return 0;
}

fn fail(errw: *std.Io.Writer, r: Result) !u8 {
    try errw.print("zwg: {s}\n", .{r.message()});
    return 1;
}

fn validateFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, errw: *std.Io.Writer) !bool {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(config.max_config_bytes)) catch |err| {
        try errw.print("zwg: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return false;
    };
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    var diag: config.Diagnostic = .{};
    var c = config.parse(gpa, text, &diag) catch |err| switch (err) {
        error.InvalidConfig => {
            try errw.print("zwg: {s}: {f}\n", .{ path, diag });
            return false;
        },
        else => return err,
    };
    defer c.deinit();
    for (c.warnings) |w| try errw.print("zwg: {s}: line {d}: warning: {s}\n", .{ path, w.line, w.message });
    return true;
}

/// Re-launch this executable elevated ("runas": the UAC prompt) with
/// `params`, wait for it (blocking on its process handle) and return its
/// exit code.
fn runElevated(params: []const u8) !Result {
    var exe_w: [600]u16 = undefined;
    const exe = try win.selfExePath(&exe_w);
    var params_w: [2048]u16 = undefined;
    const p = try win.W(&params_w, params);
    var info: win.SHELLEXECUTEINFOW = .{
        .mask = win.SEE_MASK_NOCLOSEPROCESS | win.SEE_MASK_NOASYNC | win.SEE_MASK_FLAG_NO_UI,
        .verb = std.unicode.utf8ToUtf16LeStringLiteral("runas"),
        .file = exe.ptr,
        .parameters = p.ptr,
        .show = win.SW_HIDE,
    };
    if (win.ShellExecuteExW(&info) == 0)
        return if (win.GetLastError() == win.ERROR_CANCELLED) .cancelled else .failed;
    const h = info.process orelse return .failed;
    defer _ = win.CloseHandle(h);
    if (win.WaitForSingleObject(h, win.INFINITE) != win.WAIT_OBJECT_0) return .failed;
    var code: u32 = 1;
    if (win.GetExitCodeProcess(h, &code) == 0) return .failed;
    return @enumFromInt(@as(u8, @truncate(code)));
}

// ---- the elevated steps --------------------------------------------------------

pub fn elevatedInstall(gpa: std.mem.Allocator, io: std.Io, conf_path: []const u8, user_sid: []const u8, auto: bool) Result {
    if (!win.isElevated()) return .not_elevated;
    const name = names.fromPath(conf_path);
    if (!names.isValid(name)) return .invalid_name;
    if (!names.isValidSidString(user_sid)) return .bad_args;

    // Read and validate again: this process trusts nothing it was handed.
    const text = std.Io.Dir.cwd().readFileAlloc(io, conf_path, gpa, .limited(config.max_config_bytes)) catch return .config_unreadable;
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    {
        var diag: config.Diagnostic = .{};
        var c = config.parse(gpa, text, &diag) catch return .config_invalid;
        c.deinit();
    }

    const paths = store.Paths.init(name) catch |err| return storeFail("store paths", err);
    var m = scm.Manager.open(win.SC_MANAGER_CONNECT | win.SC_MANAGER_CREATE_SERVICE) catch return .not_elevated;
    defer m.close();
    if (scm.Service.open(&m, name, win.SERVICE_QUERY_STATUS)) |s_| {
        var s = s_;
        s.close();
        return .already_installed;
    } else |err| switch (err) {
        error.NotInstalled => {},
        else => return .service_failed,
    }
    // Wintun must be loadable from where the service will look (its own
    // directory, where we copy the DLL from next to us, or System32).
    _ = tun.windows.probe() catch return .wintun_missing;

    store.prepare(&paths) catch |err| return if (err == error.UntrustedDirectory) .untrusted_dir else storeFail("create the store directories", err);
    log.open(paths.log) catch {};
    defer log.close();
    log.print("installtunnel {s}: for user {s}, start {s}", .{ name, user_sid, if (auto) "automatic" else "on demand" });

    var installed = false;
    defer if (!installed) {
        log.print("installtunnel {s}: rolled back", .{name});
        removeFiles(&paths);
    };

    // What the service runs: copies in the protected tree.
    var self_w: [600]u16 = undefined;
    const self = win.selfExePath(&self_w) catch return .failed;
    var self_buf: [1800]u8 = undefined;
    const self_n = std.unicode.utf16LeToUtf8(&self_buf, self) catch return .failed;
    const self_path = self_buf[0..self_n];
    var exe_buf: [400]u8 = undefined;
    const exe_path = paths.inDir(&exe_buf, store.exe_file) catch return .store_failed;
    store.copyInto(gpa, self_path, exe_path) catch |err| {
        log.print("copy zwg.exe: {s}", .{@errorName(err)});
        return storeFail("copy zwg.exe", err);
    };
    var dll_src_buf: [1800]u8 = undefined;
    const dll_src = std.fmt.bufPrint(&dll_src_buf, "{s}\\" ++ store.wintun_file, .{std.fs.path.dirname(self_path) orelse "."}) catch return .store_failed;
    if (store.exists(dll_src)) {
        var dll_buf: [400]u8 = undefined;
        store.copyInto(gpa, dll_src, paths.inDir(&dll_buf, store.wintun_file) catch return .store_failed) catch |err| {
            log.print("copy wintun.dll: {s}", .{@errorName(err)});
            return storeFail("copy wintun.dll", err);
        };
    }
    store.storeConfig(gpa, &paths, text) catch |err| {
        log.print("store configuration: {s}", .{@errorName(err)});
        return storeFail("store the encrypted configuration", err);
    };

    var s = scm.create(&m, .{ .tunnel = name, .exe_path = exe_path, .user_sid = user_sid, .auto_start = auto }) catch |err| {
        log.print("create service: {s}", .{@errorName(err)});
        return switch (err) {
            error.AlreadyInstalled => .already_installed,
            error.MarkedForDelete => .marked_for_delete,
            else => .service_failed,
        };
    };
    defer s.close();
    var keep_service = false;
    defer if (!keep_service) {
        s.stop() catch {};
        _ = s.waitFor(win.SERVICE_STOPPED, stop_timeout_ms) catch {};
        s.delete() catch {};
    };

    s.start() catch |err| {
        log.print("start service: {s}", .{@errorName(err)});
        return .service_failed;
    };
    const st = s.waitFor(win.SERVICE_RUNNING, start_timeout_ms) catch |err| {
        log.print("wait for RUNNING: {s}", .{@errorName(err)});
        return .start_timeout;
    };
    if (st.status.current_state != win.SERVICE_RUNNING) {
        const code = st.status.service_specific_exit_code;
        log.print("service stopped while starting: exit {d}", .{code});
        if (code >= 1 and code <= @intFromEnum(state.Exit.bad_arguments)) return .fromExit(@enumFromInt(code));
        return .service_failed;
    }
    keep_service = true;
    installed = true;
    log.print("installtunnel {s}: running", .{name});
    return .ok;
}

pub fn elevatedUninstall(name: []const u8) Result {
    if (!win.isElevated()) return .not_elevated;
    if (!names.isValid(name)) return .invalid_name;
    const paths = store.Paths.init(name) catch return .store_failed;
    var result: Result = .ok;

    var m = scm.Manager.open(win.SC_MANAGER_CONNECT) catch return .not_elevated;
    defer m.close();
    const had_service = blk: {
        var s = scm.Service.open(&m, name, win.SERVICE_STOP | win.SERVICE_QUERY_STATUS | win.DELETE) catch |err| switch (err) {
            error.NotInstalled => break :blk false,
            error.AccessDenied => return .not_elevated,
            else => return .service_failed,
        };
        defer s.close();
        const st = s.status() catch return .service_failed;
        if (st.status.current_state != win.SERVICE_STOPPED) {
            // Wait for the process too, so its files (zwg.exe, wintun.dll,
            // the log) are closed before we delete them.
            const proc = if (st.process_id != 0) win.OpenProcess(win.PROCESS_SYNCHRONIZE, 0, st.process_id) else null;
            defer if (proc) |p| {
                _ = win.CloseHandle(p);
            };
            s.stop() catch {};
            _ = s.waitFor(win.SERVICE_STOPPED, stop_timeout_ms) catch {
                result = .stop_timeout;
            };
            if (proc) |p| _ = win.WaitForSingleObject(p, 10_000);
        }
        s.delete() catch return .service_failed;
        break :blk true;
    };
    const had_files = store.exists(paths.dir);
    removeFiles(&paths);
    var old_buf: [300]u8 = undefined;
    store.delete(paths.log) catch {};
    store.delete(std.fmt.bufPrint(&old_buf, "{s}.old", .{paths.log}) catch paths.log) catch {};
    store.removeDirs(&paths);
    if (!had_service and !had_files) return .not_installed;
    return result;
}

/// Stored configuration (wiped), the binaries, the tunnel directory.
/// Says which install step failed and why on stderr (the log under the store
/// is rolled back with it), then reports the generic store failure.
fn storeFail(step: []const u8, err: anyerror) Result {
    const last = win.GetLastError();
    std.debug.print("zwg: {s} failed: {s} (last Windows error {d})\n", .{ step, @errorName(err), last });
    return .store_failed;
}

fn removeFiles(paths: *const store.Paths) void {
    store.wipe(paths.conf) catch {};
    var buf: [400]u8 = undefined;
    if (paths.inDir(&buf, store.exe_file)) |p| store.delete(p) catch {} else |_| {}
    if (paths.inDir(&buf, store.wintun_file)) |p| store.delete(p) catch {} else |_| {}
    store.removeDirs(paths);
}

// ---- unelevated: list, show, down, up ----------------------------------------------

fn listTunnels(gpa: std.mem.Allocator, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    var l = scm.list(gpa) catch |err| {
        try errw.print("zwg: cannot list services: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer l.deinit();
    if (l.items.len == 0) {
        try out.writeAll("no tunnels installed (zwg installtunnel <file.conf>)\n");
        return 0;
    }
    for (l.items) |e| try out.print("{s}\t{s}\n", .{ e.name, scm.stateName(e.state) });
    return 0;
}

fn showTunnel(gpa: std.mem.Allocator, io: std.Io, name: []const u8, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    if (!names.isValid(name)) return fail(errw, .invalid_name);
    var m = try scm.Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    var s = scm.Service.open(&m, name, win.SERVICE_QUERY_STATUS) catch |err| switch (err) {
        error.NotInstalled => {
            try errw.print("zwg: no tunnel named {s} is installed (`zwg show` lists them; for a file use `zwg show {s}.conf`)\n", .{ name, name });
            return 1;
        },
        else => return err,
    };
    defer s.close();
    const st = try s.status();
    const state_name = scm.stateName(st.status.current_state);
    if (st.status.current_state != win.SERVICE_RUNNING) {
        try out.print("interface: {s}\n  service: {s}\n", .{ name, state_name });
        return 0;
    }
    const raw = pipe.query(gpa, name) catch |err| {
        switch (err) {
            error.AccessDenied => try errw.print("zwg: {s}: access denied (installed by another user; run elevated)\n", .{name}),
            error.NotRunning => try out.print("interface: {s}\n  service: {s} (control pipe not up yet)\n", .{ name, state_name }),
            else => try errw.print("zwg: {s}: control pipe: {s}\n", .{ name, @errorName(err) }),
        }
        return if (err == error.NotRunning) 0 else 1;
    };
    defer gpa.free(raw);
    var errno: i32 = 0;
    var status = uapi.decode(gpa, raw, &errno) catch |err| {
        try errw.print("zwg: {s}: bad response from the service: {s} (errno {d})\n", .{ name, @errorName(err), errno });
        return 1;
    };
    defer status.deinit();
    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    try uapi.writeShow(out, name, state_name, &status, now);
    return 0;
}

/// The tunnel's status as the CLI and the end-to-end driver read it.
pub fn queryStatus(gpa: std.mem.Allocator, name: []const u8) !uapi.Status {
    const raw = try pipe.query(gpa, name);
    defer gpa.free(raw);
    return uapi.decode(gpa, raw, null);
}

pub const Action = enum { stop, start };

/// `zwg down <name>` / `zwg up <name>` for an installed tunnel: null if no
/// such service (main then treats the name as a foreground `zwg up`).
pub fn controlTunnel(name: []const u8, action: Action, out: *std.Io.Writer, errw: *std.Io.Writer) !?u8 {
    var m = try scm.Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    const access = win.SERVICE_QUERY_STATUS | if (action == .stop) win.SERVICE_STOP else win.SERVICE_START;
    var s = scm.Service.open(&m, name, access) catch |err| switch (err) {
        error.NotInstalled => return null,
        error.AccessDenied => {
            try errw.print("zwg: {s}: access denied (installed by another user; run elevated)\n", .{name});
            return 1;
        },
        else => return err,
    };
    defer s.close();
    switch (action) {
        .stop => {
            s.stop() catch |err| switch (err) {
                error.NotRunning => {
                    try out.print("{s} is not running\n", .{name});
                    return 0;
                },
                else => return err,
            };
            const st = s.waitFor(win.SERVICE_STOPPED, stop_timeout_ms) catch |err| {
                try errw.print("zwg: {s}: waiting for the service to stop: {s}\n", .{ name, @errorName(err) });
                return 1;
            };
            _ = st;
            try out.print("{s} stopped\n", .{name});
        },
        .start => {
            s.start() catch |err| {
                try errw.print("zwg: {s}: cannot start the service: {s}\n", .{ name, @errorName(err) });
                return 1;
            };
            const st = s.waitFor(win.SERVICE_RUNNING, start_timeout_ms) catch |err| {
                try errw.print("zwg: {s}: waiting for the service to start: {s}\n", .{ name, @errorName(err) });
                return 1;
            };
            if (st.status.current_state != win.SERVICE_RUNNING) {
                const code = st.status.service_specific_exit_code;
                const msg = if (code >= 1 and code <= @intFromEnum(state.Exit.bad_arguments)) @as(state.Exit, @enumFromInt(code)).message() else "stopped";
                try errw.print("zwg: {s}: the service stopped: {s}\n", .{ name, msg });
                return 1;
            }
            try out.print("{s} running\n", .{name});
        },
    }
    return 0;
}

test "result messages" {
    try std.testing.expectEqualStrings(state.Exit.wintun_missing.message(), Result.fromExit(.wintun_missing).message());
    try std.testing.expect(std.mem.indexOf(u8, Result.cancelled.message(), "nothing changed") != null);
    try std.testing.expectEqualStrings("failed", @as(Result, @enumFromInt(200)).message());
}
