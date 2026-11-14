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
    wintun_untrusted = 17,
    image_changed = 18,
    /// 32 + state.Exit: the service started but stopped with that reason.
    service_exit_base = 32,
    _,

    /// The elevated child's process exit code. Anything that does not fit
    /// a u8 (a crash's NTSTATUS such as 0xC0000005, or 256, whose low byte
    /// is 0 = ok) is a failure, never truncated into another result.
    pub fn fromExitCode(code: u32) Result {
        if (code > std.math.maxInt(u8)) return .failed;
        return @fromBackingInt(@intCast(@as(u8, @intCast(code))));
    }

    fn fromExit(e: state.Exit) Result {
        return @fromBackingInt(@intCast(32 + @as(u8, @intCast(@backingInt(e)))));
    }

    pub fn message(r: Result) []const u8 {
        return switch (r) {
            .ok => "done",
            .failed => "failed (see %ProgramFiles%\\zwg\\logs, readable by administrators)",
            .bad_args => "bad internal arguments",
            .not_elevated => "the elevated step is not elevated",
            .invalid_name => "invalid tunnel name: 1-32 of A-Z a-z 0-9 _ = + . - (the file name without .conf)",
            .config_unreadable => "cannot read the configuration file",
            .config_invalid => "the configuration file is invalid",
            .already_installed => "a tunnel with that name is already installed (zwg uninstalltunnel <name> first)",
            .not_installed => "no tunnel with that name is installed",
            .wintun_missing => tun.windows.wintun_hint,
            .untrusted_dir => "a directory under %ProgramFiles%\\zwg is a link, not a directory, or not owned by Administrators/SYSTEM; remove it and retry",
            .store_failed => "cannot write the protected store under %ProgramFiles%\\zwg",
            .service_failed => "the service could not be created or configured",
            .start_timeout => "the service did not reach RUNNING in time (it was removed again)",
            .stop_timeout => "the service did not stop in time (it is marked for deletion)",
            .marked_for_delete => "a previous service of that name is still being deleted; close Services/sc and retry",
            .cancelled => "the UAC prompt was declined; nothing changed",
            .wintun_untrusted => tun.windows.untrusted_hint,
            .image_changed => "zwg.exe on disk is no longer the program that is running (replaced during the install?); nothing installed",
            else => if (@backingInt(r) >= 32 and @backingInt(r) - 32 <= @backingInt(state.Exit.bad_arguments))
                @as(state.Exit, @fromBackingInt(@intCast(@backingInt(r) - 32))).message()
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
        return @backingInt(elevatedInstall(gpa, io, args[1], args[2], eql(u8, args[3], "1")));
    if (eql(u8, cmd, "/uninstalltunnel-elevated") and args.len == 2)
        return @backingInt(elevatedUninstall(args[1]));
    if (eql(u8, cmd, "/tunnelservice") and args.len == 3)
        return try tunnel.serviceProcess(gpa, io, args[1], args[2], errw);
    return null;
}

// ---- install / uninstall (unelevated side) -----------------------------------------

fn installTunnel(gpa: std.mem.Allocator, io: std.Io, conf_path: []const u8, auto: bool, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    const name = names.fromPath(conf_path);
    if (!names.isValid(name)) return fail(errw, .invalid_name);
    // Validate before any UAC prompt: typos are reported right here.
    {
        var c = (try config.load(gpa, io, conf_path, errw)) orelse return 1;
        c.deinit();
    }

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
    return .fromExitCode(code);
}

// ---- the elevated steps --------------------------------------------------------

pub fn elevatedInstall(gpa: std.mem.Allocator, io: std.Io, conf_path: []const u8, user_sid: []const u8, auto: bool) Result {
    if (!win.isElevated()) return .not_elevated;
    const name = names.fromPath(conf_path);
    if (!names.isValid(name)) return .invalid_name;
    // Only a user account may be granted the pipe and the service, never
    // a group or well-known principal (Everyone, Users, ...).
    if (!names.isAccountSidString(user_sid) or !win.isUserAccountSid(user_sid)) return .bad_args;

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
    // What the service will run, opened now and held, denying writes and
    // deletes, until copied from these very handles: this process's own
    // image (the file on disk must still be the one it was started from)
    // and wintun.dll from where the service will look (next to us: copied
    // along; else System32's), Authenticode-signed by WireGuard LLC. The
    // DLL is never loaded here: this process is elevated, and the
    // directory it came from may be user-writable.
    const self_file = win.openRunningImage() catch |err| {
        _ = storeFail("open zwg.exe", err);
        return if (err == error.NotRunningImage) .image_changed else .failed;
    };
    defer _ = win.CloseHandle(self_file);
    var dll_w: [tun.windows.path_max]u16 = undefined;
    var dll_from: tun.windows.Location = undefined;
    const dll_path = tun.windows.locate(&dll_w, &dll_from) orelse return .wintun_missing;
    const dll_file = tun.windows.openTrusted(dll_path) catch |err| return switch (err) {
        error.WintunUntrusted => .wintun_untrusted,
        error.WintunNotFound => .wintun_missing,
    };
    defer _ = win.CloseHandle(dll_file);

    // Each store directory is opened and verified once, and stays open
    // (not deletable, not renamable) until this function returns; every
    // file below is written relative to those handles.
    var dirs = store.Dirs.prepare(&paths) catch |err| return if (err == error.UntrustedDirectory) .untrusted_dir else storeFail("create the store directories", err);
    defer dirs.close();
    log.open(paths.log()) catch {};
    defer log.close();
    log.print("installtunnel {s}: for user {s}, start {s}", .{ name, user_sid, if (auto) "automatic" else "on demand" });

    var installed = false;
    defer if (!installed) {
        log.print("installtunnel {s}: rolled back", .{name});
        removeFiles(&dirs, &paths);
    };

    // What the service runs: copies in the protected tree, from the held
    // and verified handles above.
    var exe_buf: [400]u8 = undefined;
    const exe_path = paths.inDir(&exe_buf, store.exe_file) catch return .store_failed;
    store.copyInto(gpa, self_file, dirs.dir.?, store.exe_file) catch |err| {
        log.print("copy zwg.exe: {s}", .{@errorName(err)});
        return storeFail("copy zwg.exe", err);
    };
    if (dll_from == .app_dir) {
        store.copyInto(gpa, dll_file, dirs.dir.?, store.wintun_file) catch |err| {
            log.print("copy wintun.dll: {s}", .{@errorName(err)});
            return storeFail("copy wintun.dll", err);
        };
    }
    store.storeConfig(gpa, &dirs, text) catch |err| {
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
        if (code >= 1 and code <= @backingInt(state.Exit.bad_arguments)) return .fromExit(@fromBackingInt(@intCast(code)));
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
    // The store, verified and held as at install (never through a link).
    var dirs = store.Dirs.openExisting(&paths) catch |err| {
        _ = storeFail("open the store directories", err);
        return if (err == error.UntrustedDirectory) .untrusted_dir else .store_failed;
    };
    defer dirs.close();
    const had_files = dirs.dir != null;
    if (dirs.logs) |l| {
        var log_buf: [64]u8 = undefined;
        if (std.fmt.bufPrint(&log_buf, "{s}.log", .{name})) |f| store.deleteAt(l, f) catch {} else |_| {}
        if (std.fmt.bufPrint(&log_buf, "{s}.log.old", .{name})) |f| store.deleteAt(l, f) catch {} else |_| {}
    }
    removeFiles(&dirs, &paths);
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

fn removeFiles(dirs: *store.Dirs, paths: *const store.Paths) void {
    if (dirs.dir) |d| {
        store.wipeAt(d, store.conf_file) catch {};
        store.deleteAt(d, store.exe_file) catch {};
        store.deleteAt(d, store.wintun_file) catch {};
    }
    dirs.remove(paths);
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
            var watch_code: u32 = 0;
            _ = s.waitForCode(win.SERVICE_STOPPED, stop_timeout_ms, &watch_code) catch |err|
                return try waitFailed(&s, name, .stop, err, watch_code, out, errw);
            try out.print("{s} stopped\n", .{name});
        },
        .start => {
            s.start() catch |err| {
                try errw.print("zwg: {s}: cannot start the service: {s}\n", .{ name, @errorName(err) });
                return 1;
            };
            var watch_code: u32 = 0;
            const st = s.waitForCode(win.SERVICE_RUNNING, start_timeout_ms, &watch_code) catch |err|
                return try waitFailed(&s, name, .start, err, watch_code, out, errw);
            if (st.status.current_state != win.SERVICE_RUNNING) {
                const code = st.status.service_specific_exit_code;
                const msg = if (code >= 1 and code <= @backingInt(state.Exit.bad_arguments)) @as(state.Exit, @fromBackingInt(@intCast(code))).message() else "stopped";
                try errw.print("zwg: {s}: the service stopped: {s}\n", .{ name, msg });
                return 1;
            }
            try out.print("{s} running\n", .{name});
        },
    }
    return 0;
}

/// The wait after a stop / start failed. If it could not watch at all
/// (error.CannotWatch), one status query decides: on its way (or there)
/// counts as done, with a note on stderr. Anything else fails, with the raw
/// Windows error when there is one.
fn waitFailed(s: *const scm.Service, name: []const u8, action: Action, err: scm.Error, code: u32, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    if (err == error.CannotWatch) {
        const now: ?u32 = if (s.status()) |st| st.status.current_state else |_| null;
        try writeUnwatched(errw, name, action, code, now);
        if (now) |state_| if (requestTaken(action, state_)) {
            try out.print("{s} {s}\n", .{ name, scm.stateName(state_) });
            return 0;
        };
        return 1;
    }
    try writeWaitFailed(errw, name, action, err, code);
    return 1;
}

/// After a stop / start whose outcome cannot be watched: is the service on
/// its way (or already there)?
fn requestTaken(action: Action, current_state: u32) bool {
    return switch (action) {
        .stop => current_state == win.SERVICE_STOP_PENDING or current_state == win.SERVICE_STOPPED,
        .start => current_state == win.SERVICE_START_PENDING or current_state == win.SERVICE_RUNNING,
    };
}

fn writeUnwatched(errw: *std.Io.Writer, name: []const u8, action: Action, code: u32, current_state: ?u32) !void {
    try errw.print("zwg: {s}: {s} requested; cannot watch the service state: Windows error {d}", .{ name, @tagName(action), code });
    if (current_state) |st| {
        if (!requestTaken(action, st)) try errw.print("; the service is {s}", .{scm.stateName(st)});
    } else try errw.writeAll("; cannot query it either");
    try errw.writeAll("\n");
}

fn writeWaitFailed(errw: *std.Io.Writer, name: []const u8, action: Action, err: scm.Error, code: u32) !void {
    try errw.print("zwg: {s}: waiting for the service to {s}: {s}", .{ name, @tagName(action), @errorName(err) });
    if (code != 0) try errw.print(" (Windows error {d})", .{code});
    try errw.writeAll("\n");
}

test "down / up when the state change cannot be watched" {
    try std.testing.expect(requestTaken(.stop, win.SERVICE_STOP_PENDING));
    try std.testing.expect(requestTaken(.stop, win.SERVICE_STOPPED));
    try std.testing.expect(!requestTaken(.stop, win.SERVICE_RUNNING));
    try std.testing.expect(requestTaken(.start, win.SERVICE_START_PENDING));
    try std.testing.expect(requestTaken(.start, win.SERVICE_RUNNING));
    try std.testing.expect(!requestTaken(.start, win.SERVICE_STOPPED));

    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeUnwatched(&w, "home", .stop, 5, win.SERVICE_STOP_PENDING);
    try std.testing.expectEqualStrings("zwg: home: stop requested; cannot watch the service state: Windows error 5\n", w.buffered());
    w = .fixed(&buf);
    try writeUnwatched(&w, "home", .start, 5, win.SERVICE_STOPPED);
    try std.testing.expectEqualStrings("zwg: home: start requested; cannot watch the service state: Windows error 5; the service is stopped\n", w.buffered());
    w = .fixed(&buf);
    try writeUnwatched(&w, "home", .stop, 5, null);
    try std.testing.expectEqualStrings("zwg: home: stop requested; cannot watch the service state: Windows error 5; cannot query it either\n", w.buffered());
    w = .fixed(&buf);
    try writeWaitFailed(&w, "home", .stop, error.Unexpected, 1234);
    try std.testing.expectEqualStrings("zwg: home: waiting for the service to stop: Unexpected (Windows error 1234)\n", w.buffered());
    w = .fixed(&buf);
    try writeWaitFailed(&w, "home", .start, error.Timeout, 0);
    try std.testing.expectEqualStrings("zwg: home: waiting for the service to start: Timeout\n", w.buffered());
}

test "elevated child exit codes: never truncated into success" {
    try std.testing.expectEqual(Result.ok, Result.fromExitCode(0));
    try std.testing.expectEqual(Result.already_installed, Result.fromExitCode(7));
    try std.testing.expectEqual(Result.fromExit(.wintun_missing), Result.fromExitCode(32 + 4));
    for ([_]u32{ 256, 257, 0x1_0000, 0xC000_0005, 0xC000_0409, 0xFFFF_FFFF }) |c| {
        try std.testing.expectEqual(Result.failed, Result.fromExitCode(c));
    }
    // An unknown code that fits is kept (and reads as a failure).
    try std.testing.expectEqualStrings("failed", Result.fromExitCode(200).message());
}

test "result messages" {
    try std.testing.expectEqualStrings(state.Exit.wintun_missing.message(), Result.fromExit(.wintun_missing).message());
    try std.testing.expect(std.mem.indexOf(u8, Result.cancelled.message(), "nothing changed") != null);
    try std.testing.expectEqualStrings("failed", @as(Result, @fromBackingInt(@intCast(200))).message());
}
