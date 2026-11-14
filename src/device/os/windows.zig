//! Windows backend for the device's OS seam: Winsock UDP sockets whose
//! readiness is an event object (WSAEventSelect), and one
//! WaitForMultipleObjects over {sockets, TUN, wakers} with the next timer
//! deadline as the timeout. Nothing polls.
//!
//! std's Windows networking talks to AFD directly and has no readiness
//! primitive, so this declares the few Winsock calls it needs.

const std = @import("std");
const windows = std.os.windows;
const net = std.Io.net;
const common = @import("common.zig");

pub const HANDLE = windows.HANDLE;
pub const WaitHandle = HANDLE;
const SOCKET = usize;
const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
const SOCKET_ERROR: c_int = -1;

const AF_INET: c_int = 2;
const AF_INET6: c_int = 23;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_UDP: c_int = 17;
const IPPROTO_IPV6: c_int = 41;
const IPV6_V6ONLY: c_int = 27;
const SOL_SOCKET: c_int = 0xffff;
const SO_RCVBUF: c_int = 0x1002;
const SO_SNDBUF: c_int = 0x1001;
const SO_REUSEADDR: c_int = 0x0004;
/// ~SO_REUSEADDR: nobody else may bind this address and port, not even
/// with SO_REUSEADDR (which on Windows would let another, unprivileged
/// process steal the port's incoming datagrams).
const SO_EXCLUSIVEADDRUSE: c_int = ~SO_REUSEADDR;
const FD_READ: c_long = 1;
const SIO_UDP_CONNRESET: u32 = 0x9800000C;

const WSAEWOULDBLOCK = 10035;
const WSAEMSGSIZE = 10040;
const WSAECONNRESET = 10054;
const WSAENETRESET = 10052;
const WSAEADDRINUSE = 10048;
const WSAEACCES = 10013;
const WSAEAFNOSUPPORT = 10047;
const WSAEHOSTUNREACH = 10065;
const WSAENETUNREACH = 10051;
const WSAENOBUFS = 10055;
const WSAEADDRNOTAVAIL = 10049;

const sockaddr_in = extern struct {
    family: u16,
    port: u16, // network order
    addr: [4]u8,
    zero: [8]u8 = @splat(0),
};
const sockaddr_in6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32 = 0,
    addr: [16]u8,
    scope_id: u32 = 0,
};
const sockaddr_storage = extern struct {
    family: u16,
    data: [126]u8 align(8),
};

extern "ws2_32" fn WSAStartup(version: u16, data: *[512]u8) callconv(.winapi) c_int;
extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
extern "ws2_32" fn socket(af: c_int, kind: c_int, proto: c_int) callconv(.winapi) SOCKET;
extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
extern "ws2_32" fn bind(s: SOCKET, addr: *const anyopaque, len: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn getsockname(s: SOCKET, addr: *anyopaque, len: *c_int) callconv(.winapi) c_int;
extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, name: c_int, val: *const anyopaque, len: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn getsockopt(s: SOCKET, level: c_int, name: c_int, val: *anyopaque, len: *c_int) callconv(.winapi) c_int;
extern "ws2_32" fn recvfrom(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int, from: *anyopaque, fromlen: *c_int) callconv(.winapi) c_int;
extern "ws2_32" fn sendto(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int, to: *const anyopaque, tolen: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn WSAEventSelect(s: SOCKET, event: HANDLE, mask: c_long) callconv(.winapi) c_int;
extern "ws2_32" fn WSAIoctl(s: SOCKET, code: u32, in: ?*const anyopaque, in_len: u32, out: ?*anyopaque, out_len: u32, returned: *u32, overlapped: ?*anyopaque, completion: ?*anyopaque) callconv(.winapi) c_int;
extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual_reset: c_int, initial: c_int, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
extern "kernel32" fn OpenEventW(access: u32, inherit: c_int, name: [*:0]const u16) callconv(.winapi) ?HANDLE;
extern "kernel32" fn SetEvent(h: HANDLE) callconv(.winapi) c_int;
extern "kernel32" fn ResetEvent(h: HANDLE) callconv(.winapi) c_int;
extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) c_int;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "kernel32" fn WaitForMultipleObjects(n: u32, handles: [*]const HANDLE, wait_all: c_int, ms: u32) callconv(.winapi) u32;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?*const fn (u32) callconv(.winapi) c_int, add: c_int) callconv(.winapi) c_int;
extern "kernel32" fn CreateWaitableTimerExW(attrs: ?*anyopaque, name: ?[*:0]const u16, flags: u32, access: u32) callconv(.winapi) ?HANDLE;
extern "kernel32" fn SetWaitableTimer(h: HANDLE, due: *const i64, period: i32, routine: ?*anyopaque, arg: ?*anyopaque, wake: c_int) callconv(.winapi) c_int;
extern "kernel32" fn CancelWaitableTimer(h: HANDLE) callconv(.winapi) c_int;
extern "kernel32" fn GetSystemTimePreciseAsFileTime(ft: *i64) callconv(.winapi) void;
const TIMER_ALL_ACCESS: u32 = 0x1F0003;

// The stop event's security descriptor.
const SECURITY_ATTRIBUTES = extern struct { length: u32 = @sizeOf(SECURITY_ATTRIBUTES), descriptor: ?*anyopaque, inherit: c_int = 0 };
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
extern "kernel32" fn LocalFree(mem: ?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "advapi32" fn OpenProcessToken(process: HANDLE, access: u32, token: *HANDLE) callconv(.winapi) c_int;
extern "advapi32" fn GetTokenInformation(token: HANDLE, class: c_int, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) c_int;
extern "advapi32" fn ConvertSidToStringSidW(sid: *anyopaque, out: *?[*:0]u16) callconv(.winapi) c_int;
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: [*:0]const u16, revision: u32, sd: *?*anyopaque, size: ?*u32) callconv(.winapi) c_int;
const TOKEN_QUERY: u32 = 0x0008;
const TokenUser: c_int = 1;

/// "D:P(A;;GA;;;SY)(A;;GA;;;<this user's SID>)": the stop event of a
/// `zwg up` is this user's (elevated or not; SYSTEM for the service) and
/// nobody else's: no other account in the session can signal it, open it
/// or hold it. Caller LocalFrees the descriptor.
fn userOnlyDescriptor() common.StopError!*anyopaque {
    var token: HANDLE = undefined;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return error.Unexpected;
    defer _ = CloseHandle(token);
    var info: [256]u8 align(8) = undefined;
    var len: u32 = 0;
    if (GetTokenInformation(token, TokenUser, &info, info.len, &len) == 0) return error.Unexpected;
    const sid: *anyopaque = @as(*const ?*anyopaque, @ptrCast(&info)).* orelse return error.Unexpected;
    var sid_str: ?[*:0]u16 = null;
    if (ConvertSidToStringSidW(sid, &sid_str) == 0) return error.Unexpected;
    defer _ = LocalFree(sid_str);
    const prefix = std.unicode.utf8ToUtf16LeStringLiteral("D:P(A;;GA;;;SY)(A;;GA;;;");
    const s = std.mem.span(sid_str.?);
    var buf: [prefix.len + 200]u16 = undefined;
    if (s.len + 2 > buf.len - prefix.len) return error.Unexpected;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..s.len], s);
    buf[prefix.len + s.len] = ')';
    buf[prefix.len + s.len + 1] = 0;
    var sd: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(buf[0 .. prefix.len + s.len + 1 :0].ptr, 1, &sd, null) == 0) return error.Unexpected;
    return sd.?;
}

const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const ERROR_ALREADY_EXISTS: u32 = 183;

var wsa_started = std.atomic.Value(bool).init(false);

pub fn initNetworking() common.OpenError!void {
    if (wsa_started.load(.acquire)) return;
    var data: [512]u8 align(8) = undefined;
    if (WSAStartup(0x0202, &data) != 0) return error.Unexpected;
    wsa_started.store(true, .release);
}

/// The addresses the device's sockets listen on (common.Scope): every
/// interface, as a real endpoint must, or loopback only (unit tests, the
/// `--tun` test mode), which never opens the machine to the network nor
/// raises a Windows Firewall prompt for a freshly built executable.
fn bindAddr4(scope: common.Scope) [4]u8 {
    return if (scope == .loopback) .{ 127, 0, 0, 1 } else @splat(0);
}
fn bindAddr6(scope: common.Scope) [16]u8 {
    return if (scope == .loopback) .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } else @splat(0);
}

pub const Udp = struct {
    sock: SOCKET,
    event: HANDLE,
    family: common.Family,

    pub fn open(family: common.Family, port: u16) common.OpenError!Udp {
        return openScoped(family, port, .default);
    }

    pub fn openScoped(family: common.Family, port: u16, scope: common.Scope) common.OpenError!Udp {
        try initNetworking();
        const af = if (family == .v4) AF_INET else AF_INET6;
        const s = socket(af, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return mapOpen(WSAGetLastError());
        errdefer _ = closesocket(s);
        if (family == .v6) {
            const one: u32 = 1;
            _ = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, 4);
        }
        {
            // Before bind (it only applies to the bind that follows).
            const one: u32 = 1;
            if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, 4) == SOCKET_ERROR) return error.Unexpected;
        }
        // Larger buffers absorb bursts (wireguard-go asks for 7 MiB; the
        // OS clamps). Failure is harmless.
        const bufsz: u32 = 4 << 20;
        _ = setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsz, 4);
        _ = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsz, 4);
        // An ICMP port-unreachable must not make the next recvfrom fail
        // (wireguard-go does the same).
        var off: u32 = 0;
        var ret: u32 = 0;
        _ = WSAIoctl(s, SIO_UDP_CONNRESET, &off, 4, null, 0, &ret, null, null);

        const rc = switch (family) {
            .v4 => blk: {
                const sa: sockaddr_in = .{ .family = AF_INET, .port = std.mem.nativeToBig(u16, port), .addr = bindAddr4(scope) };
                break :blk bind(s, &sa, @sizeOf(sockaddr_in));
            },
            .v6 => blk: {
                const sa: sockaddr_in6 = .{ .family = AF_INET6, .port = std.mem.nativeToBig(u16, port), .addr = bindAddr6(scope) };
                break :blk bind(s, &sa, @sizeOf(sockaddr_in6));
            },
        };
        if (rc == SOCKET_ERROR) return mapOpen(WSAGetLastError());

        const ev = CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
        errdefer _ = CloseHandle(ev);
        // Also makes the socket non-blocking.
        if (WSAEventSelect(s, ev, FD_READ) == SOCKET_ERROR) return error.Unexpected;
        return .{ .sock = s, .event = ev, .family = family };
    }

    pub fn close(u: *Udp) void {
        _ = closesocket(u.sock);
        _ = CloseHandle(u.event);
        u.* = undefined;
    }

    pub fn localPort(u: *const Udp) u16 {
        var ss: sockaddr_storage = undefined;
        var len: c_int = @sizeOf(sockaddr_storage);
        if (getsockname(u.sock, &ss, &len) == SOCKET_ERROR) return 0;
        const p: *const sockaddr_in = @ptrCast(&ss);
        return std.mem.bigToNative(u16, p.port);
    }

    pub fn waitHandle(u: *const Udp) WaitHandle {
        return u.event;
    }

    /// Kept for API symmetry with other backends; `recv` handles the event.
    pub fn beginDrain(u: *Udp) void {
        _ = u;
    }

    /// Next datagram, or null when none is queued. Never blocks.
    ///
    /// Event protocol: when the queue is empty (WSAEWOULDBLOCK, which also
    /// re-arms FD_READ), reset the event and look once more, so a datagram
    /// that raced in between is returned now rather than lost; after that
    /// second WSAEWOULDBLOCK any new datagram sets the event again. So the
    /// event is clear exactly when the caller has drained everything.
    pub fn recv(u: *Udp, buf: []u8) common.RecvError!?common.Datagram {
        var reset = false;
        while (true) {
            var ss: sockaddr_storage = undefined;
            var len: c_int = @sizeOf(sockaddr_storage);
            const n = recvfrom(u.sock, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(c_int))), 0, &ss, &len);
            if (n == SOCKET_ERROR) switch (WSAGetLastError()) {
                WSAEWOULDBLOCK => {
                    if (reset) return null;
                    _ = ResetEvent(u.event);
                    reset = true;
                    continue;
                },
                // Oversized datagram (truncated) or a stale ICMP report:
                // drop it and keep draining.
                WSAEMSGSIZE, WSAECONNRESET, WSAENETRESET => continue,
                else => return error.Unexpected,
            };
            const from = fromSockaddr(&ss) orelse continue;
            return .{ .len = @intCast(n), .from = from };
        }
    }

    pub fn send(u: *Udp, to: net.IpAddress, data: []const u8) common.SendError!void {
        var rc: c_int = undefined;
        switch (to) {
            .ip4 => |a| {
                if (u.family != .v4) return error.AddressFamilyMismatch;
                const sa: sockaddr_in = .{ .family = AF_INET, .port = std.mem.nativeToBig(u16, a.port), .addr = a.bytes };
                rc = sendto(u.sock, data.ptr, @intCast(data.len), 0, &sa, @sizeOf(sockaddr_in));
            },
            .ip6 => |a| {
                if (u.family != .v6) return error.AddressFamilyMismatch;
                const sa: sockaddr_in6 = .{
                    .family = AF_INET6,
                    .port = std.mem.nativeToBig(u16, a.port),
                    .addr = a.bytes,
                    .scope_id = if (a.interface.isNone()) 0 else a.interface.index,
                };
                rc = sendto(u.sock, data.ptr, @intCast(data.len), 0, &sa, @sizeOf(sockaddr_in6));
            },
        }
        if (rc == SOCKET_ERROR) return switch (WSAGetLastError()) {
            WSAEWOULDBLOCK, WSAENOBUFS => error.WouldBlock,
            WSAEHOSTUNREACH, WSAENETUNREACH, WSAEADDRNOTAVAIL => error.Unreachable,
            WSAEMSGSIZE => error.MessageTooBig,
            else => error.Unexpected,
        };
    }

    fn fromSockaddr(ss: *const sockaddr_storage) ?net.IpAddress {
        switch (ss.family) {
            AF_INET => {
                const p: *const sockaddr_in = @ptrCast(ss);
                return .{ .ip4 = .{ .bytes = p.addr, .port = std.mem.bigToNative(u16, p.port) } };
            },
            AF_INET6 => {
                const p: *const sockaddr_in6 = @ptrCast(@alignCast(ss));
                return .{ .ip6 = .{
                    .bytes = p.addr,
                    .port = std.mem.bigToNative(u16, p.port),
                    .interface = if (p.scope_id == 0) .none else .{ .index = p.scope_id },
                } };
            },
            else => return null,
        }
    }

    fn mapOpen(code: c_int) common.OpenError {
        return switch (code) {
            WSAEADDRINUSE => error.AddressInUse,
            WSAEACCES => error.AccessDenied,
            WSAEAFNOSUPPORT => error.AddressFamilyUnsupported,
            WSAEADDRNOTAVAIL => error.AddressFamilyUnsupported,
            else => error.Unexpected,
        };
    }
};

/// Waits until one of `handles` is ready or `timeout_ns` passes (null =
/// forever). Returns the index of a ready handle, or null on timeout.
/// The timeout is rounded up to whole milliseconds so the loop never wakes
/// early and spins.
pub fn wait(handles: []const WaitHandle, timeout_ns: ?u64) common.WaitError!?usize {
    std.debug.assert(handles.len <= 64);
    const ms: u32 = if (timeout_ns) |ns| @intCast(@min(
        (ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms,
        INFINITE - 1,
    )) else INFINITE;
    const r = WaitForMultipleObjects(@intCast(handles.len), handles.ptr, 0, ms);
    if (r == WAIT_TIMEOUT) return null;
    if (r < handles.len) return r;
    if (r >= 0x80 and r < 0x80 + handles.len) return r - 0x80; // abandoned (mutex only)
    return error.Unexpected;
}

/// Becomes ready when a deadline passes on a clock that keeps counting
/// while the machine sleeps. WaitForMultipleObjects' own timeout does not
/// count time spent suspended (Windows 8 and later), so after a resume the
/// loop would otherwise wait out the rest of its pre-suspend timeout before
/// noticing the timers that fell due meanwhile. An auto-reset waitable
/// timer with an *absolute* due time fires as soon as the machine resumes
/// past it. The relative wait timeout stays as well: should the wall clock
/// be set back, it still wakes the loop on time (a forward step fires the
/// timer early, which only makes the loop recompute and re-arm).
pub const DeadlineTimer = struct {
    handle: HANDLE,

    pub fn init() common.WaitError!DeadlineTimer {
        return .{ .handle = CreateWaitableTimerExW(null, null, 0, TIMER_ALL_ACCESS) orelse return error.Unexpected };
    }

    pub fn deinit(t: *DeadlineTimer) void {
        _ = CloseHandle(t.handle);
        t.* = undefined;
    }

    pub fn waitHandle(t: *const DeadlineTimer) ?WaitHandle {
        return t.handle;
    }

    /// Ready `ns` from now (replaces any earlier arming).
    pub fn arm(t: *DeadlineTimer, ns: u64) void {
        var now: i64 = 0;
        GetSystemTimePreciseAsFileTime(&now);
        const due: i64 = now +| @as(i64, @intCast(@min(ns / 100, std.math.maxInt(i64) / 2)));
        // fResume = FALSE: never wakes a sleeping machine, only fires after it resumes.
        _ = SetWaitableTimer(t.handle, &due, 0, null, null, 0);
    }

    pub fn disarm(t: *DeadlineTimer) void {
        _ = CancelWaitableTimer(t.handle);
    }

    /// After it was reported ready (auto-reset: nothing to consume).
    pub fn clear(t: *DeadlineTimer) void {
        _ = t;
    }
};

/// A named event `zwg down` can set to stop a running `zwg up` for the
/// same interface name. Created by `up` (fails if one is already running).
pub const StopSignal = struct {
    handle: HANDLE,

    pub fn create(name: []const u8) common.StopError!StopSignal {
        var wbuf: [128]u16 = undefined;
        const w = try eventName(&wbuf, name);
        const sd = try userOnlyDescriptor();
        defer _ = LocalFree(sd);
        var sa: SECURITY_ATTRIBUTES = .{ .descriptor = sd };
        const h = CreateEventW(&sa, 1, 0, w) orelse return error.Unexpected;
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            _ = CloseHandle(h);
            return error.AlreadyRunning;
        }
        return .{ .handle = h };
    }

    /// For `zwg down`: signal a running instance. error.NotRunning if none.
    pub fn signalExisting(name: []const u8) common.StopError!void {
        var wbuf: [128]u16 = undefined;
        const w = try eventName(&wbuf, name);
        const h = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, 0, w) orelse return error.NotRunning;
        defer _ = CloseHandle(h);
        _ = SetEvent(h);
    }

    pub fn waitHandle(s: *const StopSignal) WaitHandle {
        return s.handle;
    }

    pub fn signal(s: *const StopSignal) void {
        _ = SetEvent(s.handle);
    }

    pub fn close(s: *StopSignal) void {
        _ = CloseHandle(s.handle);
        s.* = undefined;
    }

    fn eventName(buf: *[128]u16, name: []const u8) common.StopError![*:0]const u16 {
        const prefix = "Local\\zwg-stop-";
        if (prefix.len + name.len + 1 > buf.len) return error.NameTooLong;
        var i: usize = 0;
        for (prefix) |c| {
            buf[i] = c;
            i += 1;
        }
        for (name) |c| {
            if (c < 0x21 or c > 0x7e or c == '\\') return error.NameTooLong;
            buf[i] = c;
            i += 1;
        }
        buf[i] = 0;
        return buf[0..i :0];
    }
};

var ctrl_c_target: ?HANDLE = null;

fn ctrlHandler(kind: u32) callconv(.winapi) c_int {
    _ = kind;
    if (ctrl_c_target) |h| {
        _ = SetEvent(h);
        return 1;
    }
    return 0;
}

/// Ctrl+C / console close signals `stop` instead of killing the process.
pub fn stopOnInterrupt(stop: *const StopSignal) void {
    ctrl_c_target = stop.handle;
    _ = SetConsoleCtrlHandler(&ctrlHandler, 1);
}

test "the device's port cannot be taken over with SO_REUSEADDR (SO_EXCLUSIVEADDRUSE)" {
    var u = try Udp.open(.v4, 0); // loopback in tests
    defer u.close();
    const port = u.localPort();
    // The option is set on the device's socket.
    var val: u32 = 0;
    var len: c_int = 4;
    try std.testing.expect(getsockopt(u.sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &val, &len) == 0);
    try std.testing.expectEqual(@as(u32, 1), val);
    // Another socket, as a hijacking process would: SO_REUSEADDR, same address and port.
    const s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    try std.testing.expect(s != INVALID_SOCKET);
    defer _ = closesocket(s);
    const one: u32 = 1;
    try std.testing.expect(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, 4) == 0);
    const sa: sockaddr_in = .{ .family = AF_INET, .port = std.mem.nativeToBig(u16, port), .addr = bindAddr4(.loopback) };
    try std.testing.expectEqual(SOCKET_ERROR, bind(s, &sa, @sizeOf(sockaddr_in)));
    const e = WSAGetLastError();
    try std.testing.expect(e == WSAEACCES or e == WSAEADDRINUSE);
    // A plain second open of the same port is refused as well.
    try std.testing.expectError(error.AddressInUse, Udp.openScoped(.v4, port, .loopback));
}

test "the stop event has an explicit DACL: SYSTEM and this user only" {
    const S = struct {
        extern "advapi32" fn GetSecurityInfo(h: HANDLE, kind: c_int, info: u32, owner: ?*?*anyopaque, group: ?*?*anyopaque, dacl: ?*?*Acl, sacl: ?*?*anyopaque, sd: *?*anyopaque) callconv(.winapi) u32;
        extern "advapi32" fn GetSecurityDescriptorControl(sd: *anyopaque, control: *u16, revision: *u32) callconv(.winapi) c_int;
        const Acl = extern struct { revision: u8, sbz1: u8, size: u16, ace_count: u16, sbz2: u16 };
    };
    var s = try StopSignal.create("zwg-test-dacl");
    defer s.close();
    var dacl: ?*S.Acl = null;
    var sd: ?*anyopaque = null;
    const SE_KERNEL_OBJECT: c_int = 6;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    try std.testing.expectEqual(@as(u32, 0), S.GetSecurityInfo(s.handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, null, null, &dacl, null, &sd));
    defer _ = LocalFree(sd);
    try std.testing.expectEqual(@as(u16, 2), dacl.?.ace_count);
    var control: u16 = 0;
    var rev: u32 = 0;
    try std.testing.expect(S.GetSecurityDescriptorControl(sd.?, &control, &rev) != 0);
    try std.testing.expect(control & 0x1000 != 0); // SE_DACL_PROTECTED
    // Another account in the same session (this token with our user SID
    // deny-only: the logon SID and every group stay) cannot open it; the
    // default DACL would have let the logon session in.
    {
        const w32 = @import("../../service/win32.zig");
        const t = try w32.restrictedToken(true);
        defer _ = CloseHandle(t);
        try std.testing.expect(w32.ImpersonateLoggedOnUser(t) != 0);
        defer _ = w32.RevertToSelf();
        try std.testing.expectError(error.NotRunning, StopSignal.signalExisting("zwg-test-dacl"));
    }
    // `zwg down` (same user) can still signal it.
    try StopSignal.signalExisting("zwg-test-dacl");
    try std.testing.expectEqual(@as(?usize, 0), try wait(&.{s.waitHandle()}, std.time.ns_per_s));
}
