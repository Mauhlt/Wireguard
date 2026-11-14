//! The service control manager side of a tunnel (Windows only): create the
//! per-tunnel service, query, start, stop, delete, list, and wait for a
//! state change without polling (NotifyServiceStatusChangeW: the SCM queues
//! an APC to this thread, which sleeps alertably until it arrives or the
//! deadline passes).
//!
//! NotifyServiceStatusChangeW can refuse with ERROR_ACCESS_DENIED from the
//! call itself on a thread that impersonates a token which may not open this
//! process's own threads (their DACL is the process token's default DACL),
//! however the service handle was opened and even when that token may query
//! the service. Seen: an elevated process impersonating its user with
//! Administrators deny-only (the end-to-end driver), and an unelevated one
//! impersonating its user with the user SID deny-only (the "waitFor while
//! impersonating" test below); an unelevated process impersonating its user
//! with Administrators deny-only, whose user SID still opens its threads,
//! is not refused. waitFor reports it as error.CannotWatch and never polls
//! instead: the caller decides from one final status query.
//!
//! Service configuration, as WireGuard for Windows' tunnel services:
//!   name           zwgTunnel$<name>, display "zwg tunnel: <name>"
//!   type           SERVICE_WIN32_OWN_PROCESS, LocalSystem
//!   start          demand (default) or automatic (`--auto`)
//!   binary         "<%ProgramFiles%\zwg\tunnels\<name>\zwg.exe>" /tunnelservice <name> <user SID>
//!   dependencies   Nsi, TcpIp (adapters and routes need both)
//!   SID type       unrestricted: the service gets its own SID
//!                  (NT SERVICE\zwgTunnel$<name>) for firewall rules, while
//!                  still able to use the network stack and Wintun
//!                  (a restricted SID would need write-restricted ACLs on
//!                  everything Wintun and NSI touch)
//!   failure        restart after 2 s, again after 5 s, then stay stopped;
//!                  counter resets after a day; also on a non-crash failure
//!                  exit (e.g. DNS not up yet at boot)
//!   DACL           default + the installing user may query/start/stop

const std = @import("std");
const win = @import("win32.zig");
const names = @import("names.zig");
const sddl = @import("sddl.zig");

pub const Error = error{
    AccessDenied,
    NotInstalled,
    AlreadyInstalled,
    MarkedForDelete,
    NotRunning,
    Timeout,
    /// The state change cannot be watched (the notification was refused);
    /// the service itself may be fine: query its status once.
    CannotWatch,
    NameTooLong,
    OutOfMemory,
    Unexpected,
};

pub const Manager = struct {
    h: win.SC_HANDLE,

    pub fn open(access: u32) Error!Manager {
        const h = win.OpenSCManagerW(null, null, access) orelse return mapErr(win.GetLastError());
        return .{ .h = h };
    }

    pub fn close(m: *Manager) void {
        _ = win.CloseServiceHandle(m.h);
    }
};

pub const Service = struct {
    h: win.SC_HANDLE,

    pub fn open(m: *const Manager, tunnel: []const u8, access: u32) Error!Service {
        var nb: [names.max_service_name]u8 = undefined;
        var wb: [names.max_service_name + 1]u16 = undefined;
        const w = win.W(&wb, names.serviceName(&nb, tunnel)) catch return error.NameTooLong;
        const h = win.OpenServiceW(m.h, w.ptr, access) orelse return mapErr(win.GetLastError());
        return .{ .h = h };
    }

    pub fn close(s: *Service) void {
        _ = win.CloseServiceHandle(s.h);
    }

    pub fn status(s: *const Service) Error!win.SERVICE_STATUS_PROCESS {
        var st: win.SERVICE_STATUS_PROCESS = .{};
        var needed: u32 = 0;
        if (win.QueryServiceStatusEx(s.h, win.SC_STATUS_PROCESS_INFO, @ptrCast(&st), @sizeOf(win.SERVICE_STATUS_PROCESS), &needed) == 0)
            return mapErr(win.GetLastError());
        return st;
    }

    /// Start; already running is fine.
    pub fn start(s: *const Service) Error!void {
        if (win.StartServiceW(s.h, 0, null) != 0) return;
        const e = win.GetLastError();
        if (e == win.ERROR_SERVICE_ALREADY_RUNNING) return;
        return mapErr(e);
    }

    /// Ask the service to stop; error.NotRunning if it is not running.
    pub fn stop(s: *const Service) Error!void {
        var st: win.SERVICE_STATUS = .{};
        if (win.ControlService(s.h, win.SERVICE_CONTROL_STOP, &st) != 0) return;
        const e = win.GetLastError();
        if (e == win.ERROR_SERVICE_NOT_ACTIVE) return error.NotRunning;
        // Still starting: the stop is refused until it runs; the caller waits.
        if (e == win.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) return;
        return mapErr(e);
    }

    pub fn delete(s: *const Service) Error!void {
        if (win.DeleteService(s.h) != 0) return;
        const e = win.GetLastError();
        if (e == win.ERROR_SERVICE_MARKED_FOR_DELETE) return;
        return mapErr(e);
    }

    /// Wait until the service reaches `target` (a SERVICE_* state), or
    /// stops (when waiting for RUNNING), or `timeout_ms` passes. Returns
    /// the last status seen. No polling: one SCM notification per change.
    pub fn waitFor(s: *const Service, target: u32, timeout_ms: u32) Error!win.SERVICE_STATUS_PROCESS {
        return s.waitForCode(target, timeout_ms, null);
    }

    /// waitFor, and on a failed notification the raw Windows error in
    /// `code` (0 otherwise), for the message.
    pub fn waitForCode(s: *const Service, target: u32, timeout_ms: u32, code: ?*u32) Error!win.SERVICE_STATUS_PROCESS {
        if (code) |c| c.* = 0;
        const deadline = win.GetTickCount64() + timeout_ms;
        var st = try s.status();
        while (st.status.current_state != target) {
            if (target == win.SERVICE_RUNNING and st.status.current_state == win.SERVICE_STOPPED) return st;
            // Allocated per registration and freed only once its APC ran:
            // on a timeout the SCM may still write it later.
            const n = std.heap.page_allocator.create(Notify) catch return error.OutOfMemory;
            n.* = .{};
            n.notify.callback = Notify.callback;
            n.notify.context = n;
            const mask = all_states & ~stateBit(st.status.current_state);
            const rc = win.NotifyServiceStatusChangeW(s.h, mask, &n.notify);
            if (rc != 0) {
                std.heap.page_allocator.destroy(n);
                if (code) |c| c.* = rc;
                return notifyErr(rc);
            }
            while (!n.fired) {
                const now = win.GetTickCount64();
                if (now >= deadline) return error.Timeout; // n leaks (tiny, bounded by timeouts)
                _ = win.SleepEx(@intCast(@min(deadline - now, win.INFINITE - 1)), 1);
            }
            defer std.heap.page_allocator.destroy(n);
            if (n.notify.notification_status != 0) {
                if (code) |c| c.* = n.notify.notification_status;
                return notifyErr(n.notify.notification_status);
            }
            st = n.notify.status;
        }
        return st;
    }

    const all_states = win.SERVICE_NOTIFY_STOPPED | win.SERVICE_NOTIFY_START_PENDING | win.SERVICE_NOTIFY_STOP_PENDING |
        win.SERVICE_NOTIFY_RUNNING | win.SERVICE_NOTIFY_CONTINUE_PENDING | win.SERVICE_NOTIFY_PAUSE_PENDING | win.SERVICE_NOTIFY_PAUSED;

    fn stateBit(state: u32) u32 {
        return if (state >= 1 and state <= 7) @as(u32, 1) << @intCast(state - 1) else 0;
    }

    const Notify = struct {
        notify: win.SERVICE_NOTIFYW = .{},
        fired: bool = false,

        fn callback(param: ?*anyopaque) callconv(.winapi) void {
            const sn: *win.SERVICE_NOTIFYW = @ptrCast(@alignCast(param.?));
            const self: *Notify = @fieldParentPtr("notify", sn);
            self.fired = true;
        }
    };
};

pub const CreateOptions = struct {
    tunnel: []const u8,
    /// Absolute path of the zwg.exe the service runs (in the protected tree).
    exe_path: []const u8,
    user_sid: []const u8,
    auto_start: bool = false,
};

/// Create and configure the service (not started). Needs an elevated process.
pub fn create(m: *const Manager, o: CreateOptions) Error!Service {
    std.debug.assert(names.isValid(o.tunnel));
    if (!names.isAccountSidString(o.user_sid)) return error.Unexpected;

    var nb: [names.max_service_name]u8 = undefined;
    var name_w: [names.max_service_name + 1]u16 = undefined;
    const svc_name = win.W(&name_w, names.serviceName(&nb, o.tunnel)) catch return error.NameTooLong;

    var text: [600]u8 = undefined;
    var display_w: [64]u16 = undefined;
    const display = win.W(&display_w, std.fmt.bufPrint(&text, "zwg tunnel: {s}", .{o.tunnel}) catch return error.NameTooLong) catch return error.NameTooLong;
    var bin_w: [600]u16 = undefined;
    const bin = win.W(&bin_w, std.fmt.bufPrint(&text, "\"{s}\" /tunnelservice {s} {s}", .{ o.exe_path, o.tunnel, o.user_sid }) catch return error.NameTooLong) catch return error.NameTooLong;
    const deps = std.unicode.utf8ToUtf16LeStringLiteral("Nsi\x00TcpIp\x00");

    const h = win.CreateServiceW(
        m.h,
        svc_name.ptr,
        display.ptr,
        win.SERVICE_ALL_ACCESS,
        win.SERVICE_WIN32_OWN_PROCESS,
        if (o.auto_start) win.SERVICE_AUTO_START else win.SERVICE_DEMAND_START,
        win.SERVICE_ERROR_NORMAL,
        bin.ptr,
        null,
        null,
        deps,
        null, // LocalSystem
        null,
    ) orelse {
        const e = win.GetLastError();
        return switch (e) {
            win.ERROR_SERVICE_EXISTS => error.AlreadyInstalled,
            win.ERROR_SERVICE_MARKED_FOR_DELETE => error.MarkedForDelete,
            else => mapErr(e),
        };
    };
    var s: Service = .{ .h = h };
    errdefer {
        _ = win.DeleteService(h);
        s.close();
    }

    var desc_w: [128]u16 = undefined;
    const desc: win.SERVICE_DESCRIPTIONW = .{ .description = (win.W(&desc_w, std.fmt.bufPrint(&text, "WireGuard tunnel {s} (zwg, pure Zig)", .{o.tunnel}) catch return error.NameTooLong) catch return error.NameTooLong).ptr };
    if (win.ChangeServiceConfig2W(h, win.SERVICE_CONFIG_DESCRIPTION, &desc) == 0) return mapErr(win.GetLastError());

    const sid_info: win.SERVICE_SID_INFO = .{ .sid_type = win.SERVICE_SID_TYPE_UNRESTRICTED };
    if (win.ChangeServiceConfig2W(h, win.SERVICE_CONFIG_SERVICE_SID_INFO, &sid_info) == 0) return mapErr(win.GetLastError());

    const actions = [_]win.SC_ACTION{
        .{ .kind = win.SC_ACTION_RESTART, .delay_ms = 2000 },
        .{ .kind = win.SC_ACTION_RESTART, .delay_ms = 5000 },
        .{ .kind = win.SC_ACTION_NONE, .delay_ms = 0 },
    };
    const fa: win.SERVICE_FAILURE_ACTIONSW = .{ .reset_period_s = 86400, .action_count = actions.len, .actions = &actions };
    if (win.ChangeServiceConfig2W(h, win.SERVICE_CONFIG_FAILURE_ACTIONS, &fa) == 0) return mapErr(win.GetLastError());
    const flag: win.SERVICE_FAILURE_ACTIONS_FLAG = .{ .on_non_crash_failures = 1 };
    if (win.ChangeServiceConfig2W(h, win.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag) == 0) return mapErr(win.GetLastError());

    var sd_text: [512]u8 = undefined;
    const sd_str = sddl.service(&sd_text, o.user_sid) catch return error.Unexpected;
    var sd = win.SecurityDescriptor.fromSddl(sd_str) catch return error.Unexpected;
    defer sd.deinit();
    if (win.SetServiceObjectSecurity(h, win.DACL_SECURITY_INFORMATION, sd.sd) == 0) return mapErr(win.GetLastError());
    return s;
}

pub const Entry = struct {
    /// Tunnel name (points into the list's arena).
    name: []const u8,
    state: u32,
};

pub const List = struct {
    arena: std.heap.ArenaAllocator,
    items: []Entry,

    pub fn deinit(l: *List) void {
        l.arena.deinit();
    }
};

/// Every installed zwg tunnel service (any user may enumerate).
pub fn list(gpa: std.mem.Allocator) Error!List {
    var m = try Manager.open(win.SC_MANAGER_CONNECT | win.SC_MANAGER_ENUMERATE_SERVICE);
    defer m.close();
    var l: List = .{ .arena = .init(gpa), .items = &.{} };
    errdefer l.deinit();
    const a = l.arena.allocator();
    var out: std.ArrayList(Entry) = .empty;
    var resume_handle: u32 = 0;
    var size: u32 = 64 << 10;
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const buf = gpa.alignedAlloc(u8, .of(win.ENUM_SERVICE_STATUS_PROCESSW), size) catch return error.OutOfMemory;
        defer gpa.free(buf);
        var needed: u32 = 0;
        var count: u32 = 0;
        const ok = win.EnumServicesStatusExW(m.h, win.SC_ENUM_PROCESS_INFO, win.SERVICE_WIN32, win.SERVICE_STATE_ALL, buf.ptr, size, &needed, &count, &resume_handle, null);
        const more = ok == 0 and win.GetLastError() == win.ERROR_MORE_DATA;
        if (ok == 0 and !more) return mapErr(win.GetLastError());
        const entries: [*]const win.ENUM_SERVICE_STATUS_PROCESSW = @ptrCast(buf.ptr);
        for (entries[0..count]) |e| {
            const svc = win.toUtf8(a, e.service_name) catch return error.OutOfMemory;
            const tunnel = names.fromServiceName(svc) orelse continue;
            out.append(a, .{ .name = tunnel, .state = e.status.status.current_state }) catch return error.OutOfMemory;
        }
        if (!more) break;
        if (count == 0) size = @max(size * 2, needed);
        if (size > 16 << 20) return error.Unexpected;
    }
    l.items = out.items;
    std.mem.sort(Entry, l.items, {}, struct {
        fn lt(_: void, x: Entry, y: Entry) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    return l;
}

pub fn stateName(state: u32) []const u8 {
    return switch (state) {
        win.SERVICE_STOPPED => "stopped",
        win.SERVICE_START_PENDING => "starting",
        win.SERVICE_STOP_PENDING => "stopping",
        win.SERVICE_RUNNING => "running",
        win.SERVICE_CONTINUE_PENDING => "continuing",
        win.SERVICE_PAUSE_PENDING => "pausing",
        win.SERVICE_PAUSED => "paused",
        else => "unknown",
    };
}

/// A NotifyServiceStatusChangeW failure, as its return code or as the
/// notification's status. ACCESS_DENIED there is not about the service (the
/// handle was opened and checked already) but about the watching itself.
fn notifyErr(e: u32) Error {
    return switch (e) {
        win.ERROR_ACCESS_DENIED => error.CannotWatch,
        else => mapErr(e),
    };
}

fn mapErr(e: u32) Error {
    return switch (e) {
        win.ERROR_ACCESS_DENIED => error.AccessDenied,
        win.ERROR_SERVICE_DOES_NOT_EXIST => error.NotInstalled,
        win.ERROR_SERVICE_EXISTS => error.AlreadyInstalled,
        win.ERROR_SERVICE_MARKED_FOR_DELETE => error.MarkedForDelete,
        win.ERROR_SERVICE_NOT_ACTIVE => error.NotRunning,
        win.ERROR_SERVICE_REQUEST_TIMEOUT => error.Timeout,
        else => error.Unexpected,
    };
}

test "list and query work unelevated" {
    var l = try list(std.testing.allocator);
    defer l.deinit();
    for (l.items) |e| try std.testing.expect(names.isValid(e.name));
    // A service every Windows has: query status (needs no rights beyond
    // what interactive users get), and the not-installed path.
    var m = try Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    try std.testing.expectError(error.NotInstalled, Service.open(&m, "zwg-test-nonexistent", win.SERVICE_QUERY_STATUS));
}

test "creating a service needs elevation" {
    if (win.isElevated()) return error.SkipZigTest;
    try std.testing.expectError(error.AccessDenied, Manager.open(win.SC_MANAGER_CREATE_SERVICE));
}

test "waitFor returns at once when the state is already reached" {
    // The Windows Event Log service is always running and queryable.
    var m = try Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    var wb: [16]u16 = undefined;
    const h = win.OpenServiceW(m.h, (try win.W(&wb, "EventLog")).ptr, win.SERVICE_QUERY_STATUS) orelse return error.SkipZigTest;
    var s: Service = .{ .h = h };
    defer s.close();
    const st = try s.waitFor(win.SERVICE_RUNNING, 1000);
    try std.testing.expectEqual(win.SERVICE_RUNNING, st.status.current_state);
    // Waiting for a state it will not reach: the deadline is honoured.
    const t0 = win.GetTickCount64();
    try std.testing.expectError(error.Timeout, s.waitFor(win.SERVICE_STOPPED, 200));
    try std.testing.expect(win.GetTickCount64() - t0 >= 150);
}

test "notification failures: access denied means cannot watch, the rest as usual" {
    try std.testing.expectEqual(error.CannotWatch, notifyErr(win.ERROR_ACCESS_DENIED));
    try std.testing.expectEqual(error.MarkedForDelete, notifyErr(win.ERROR_SERVICE_MARKED_FOR_DELETE));
    try std.testing.expectEqual(error.NotInstalled, notifyErr(win.ERROR_SERVICE_DOES_NOT_EXIST));
    try std.testing.expectEqual(error.Unexpected, notifyErr(win.ERROR_INVALID_HANDLE));
    // Everywhere else ACCESS_DENIED stays AccessDenied.
    try std.testing.expectEqual(error.AccessDenied, mapErr(win.ERROR_ACCESS_DENIED));
}

test "waitFor while impersonating another token: CannotWatch with the raw code, no polling" {
    // The user's SID deny-only: a token other than the process token that
    // may still query the Event Log service (Authenticated Users can).
    const t = win.restrictedToken(true) catch return error.SkipZigTest;
    defer _ = win.CloseHandle(t);
    if (win.ImpersonateLoggedOnUser(t) == 0) return error.SkipZigTest;
    defer _ = win.RevertToSelf();
    var m = try Manager.open(win.SC_MANAGER_CONNECT);
    defer m.close();
    var wb: [16]u16 = undefined;
    const h = win.OpenServiceW(m.h, (try win.W(&wb, "EventLog")).ptr, win.SERVICE_QUERY_STATUS) orelse return error.SkipZigTest;
    var s: Service = .{ .h = h };
    defer s.close();
    // Already there: no notification is needed, so none can fail.
    _ = try s.waitFor(win.SERVICE_RUNNING, 1000);
    var code: u32 = 0;
    const t0 = win.GetTickCount64();
    if (s.waitForCode(win.SERVICE_STOPPED, 2000, &code)) |_| {
        return error.TestUnexpectedResult; // the Event Log does not stop
    } else |err| switch (err) {
        error.CannotWatch => {
            try std.testing.expectEqual(win.ERROR_ACCESS_DENIED, code);
            try std.testing.expect(win.GetTickCount64() - t0 < 1000); // at once, not after the deadline
        },
        // A Windows that allows it: an ordinary wait until the deadline.
        error.Timeout => try std.testing.expectEqual(@as(u32, 0), code),
        else => return err,
    }
}
