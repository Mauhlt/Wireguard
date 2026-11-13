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

/// The address the device's sockets listen on: every interface, as a real
/// endpoint must. Unit tests listen on loopback only, so running them never
/// opens the machine to the network (and never raises a Windows Firewall
/// prompt for each freshly built test executable).
const any4: [4]u8 = if (@import("builtin").is_test) .{ 127, 0, 0, 1 } else @splat(0);
const any6: [16]u8 = if (@import("builtin").is_test) .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } else @splat(0);

pub const Udp = struct {
    sock: SOCKET,
    event: HANDLE,
    family: common.Family,

    pub fn open(family: common.Family, port: u16) common.OpenError!Udp {
        try initNetworking();
        const af = if (family == .v4) AF_INET else AF_INET6;
        const s = socket(af, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return mapOpen(WSAGetLastError());
        errdefer _ = closesocket(s);
        if (family == .v6) {
            const one: u32 = 1;
            _ = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, 4);
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
                const sa: sockaddr_in = .{ .family = AF_INET, .port = std.mem.nativeToBig(u16, port), .addr = any4 };
                break :blk bind(s, &sa, @sizeOf(sockaddr_in));
            },
            .v6 => blk: {
                const sa: sockaddr_in6 = .{ .family = AF_INET6, .port = std.mem.nativeToBig(u16, port), .addr = any6 };
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

/// A named event `zwg down` can set to stop a running `zwg up` for the
/// same interface name. Created by `up` (fails if one is already running).
pub const StopSignal = struct {
    handle: HANDLE,

    pub fn create(name: []const u8) common.StopError!StopSignal {
        var wbuf: [128]u16 = undefined;
        const w = try eventName(&wbuf, name);
        const h = CreateEventW(null, 1, 0, w) orelse return error.Unexpected;
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
