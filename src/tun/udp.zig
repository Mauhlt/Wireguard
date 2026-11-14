//! UdpTun: a test-only Tun whose "OS side" is a UDP socket on 127.0.0.1.
//!
//! One IP packet per datagram. A test driver in another process sends IP
//! packets to the bound port (the device reads them as if the OS routed them
//! into the tunnel) and receives what the device writes (decrypted traffic).
//! Replies go to the address the last datagram came from, so the driver
//! registers first with `hello()` (an empty datagram, never surfaced as a
//! packet) or by sending a packet. This is how the two-process loopback runner and the live
//! interop driver exercise real `zwg` processes without Wintun or admin
//! rights (see tests/interop/README.md, `zwg up <conf> --tun udp:<port>`).
//!
//! Loopback only, by construction: it binds 127.0.0.1 and ignores datagrams
//! from any other source, so it can never become an injection point.
//!
//! Wait handle: the socket itself on POSIX; on Windows an event bound with
//! WSAEventSelect(FD_READ), reset when recvfrom reports WSAEWOULDBLOCK
//! (recvfrom re-enables FD_READ recording, so a datagram arriving after the
//! reset signals it again). No polling.
const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Cidr = @import("../ip.zig").Cidr;
const Tun = root.Tun;

const is_windows = builtin.os.tag == .windows;

pub const OpenError = error{ AddressInUse, SystemResources, Unexpected };

const SockaddrIn = extern struct {
    family: u16 = 2, // AF_INET (Windows, Linux); Darwin uses len+family bytes, see below
    port_be: u16,
    addr: [4]u8,
    zero: [8]u8 = @splat(0),
};

fn loopbackAddr(port: u16) SockaddrIn {
    var sa: SockaddrIn = .{ .port_be = std.mem.nativeToBig(u16, port), .addr = .{ 127, 0, 0, 1 } };
    if (builtin.os.tag.isDarwin()) sa.family = std.mem.nativeToLittle(u16, (2 << 8) | 16); // sin_len=16, sin_family=AF_INET
    return sa;
}

pub const UdpTun = struct {
    sock: Socket,
    event: if (is_windows) std.os.windows.HANDLE else void,
    mtu_value: u16,
    local_port: u16,
    peer: ?SockaddrIn = null,
    /// Writes dropped because no driver has sent anything yet.
    dropped_no_peer: u64 = 0,

    const Socket = if (is_windows) usize else std.posix.fd_t;

    /// Bind 127.0.0.1:`port` (0 = any free port; see `port()`).
    pub fn open(listen_port: u16, mtu_bytes: u16) OpenError!UdpTun {
        if (is_windows) {
            try ws.startup();
            const s = ws.socket(2, 2, 17); // AF_INET, SOCK_DGRAM, IPPROTO_UDP
            if (s == ws.INVALID_SOCKET) return error.SystemResources;
            errdefer _ = ws.closesocket(s);
            // ICMP port-unreachable from a vanished driver must not poison reads.
            var off: u32 = 0;
            var ret: u32 = 0;
            _ = ws.WSAIoctl(s, ws.SIO_UDP_CONNRESET, &off, 4, null, 0, &ret, null, null);
            var sa = loopbackAddr(listen_port);
            if (ws.bind(s, &sa, @sizeOf(SockaddrIn)) != 0)
                return if (ws.WSAGetLastError() == ws.WSAEADDRINUSE) error.AddressInUse else error.Unexpected;
            const ev = @import("queue.zig").win.CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
            errdefer std.os.windows.CloseHandle(ev);
            if (ws.WSAEventSelect(s, ev, ws.FD_READ) != 0) return error.Unexpected; // also makes s non-blocking
            return .{ .sock = s, .event = ev, .mtu_value = mtu_bytes, .local_port = try boundPort(s) };
        } else {
            const sys = std.posix.system;
            const rc = sys.socket(2, std.posix.SOCK.DGRAM, 0);
            if (std.posix.errno(rc) != .SUCCESS) return error.SystemResources;
            const s: std.posix.fd_t = @intCast(rc);
            errdefer _ = sys.close(s);
            var sa = loopbackAddr(listen_port);
            switch (std.posix.errno(sys.bind(s, @ptrCast(&sa), @sizeOf(SockaddrIn)))) {
                .SUCCESS => {},
                .ADDRINUSE => return error.AddressInUse,
                else => return error.Unexpected,
            }
            try setNonBlocking(s);
            return .{ .sock = s, .event = {}, .mtu_value = mtu_bytes, .local_port = try boundPort(s) };
        }
    }

    pub fn close(u: *UdpTun) void {
        if (is_windows) {
            _ = ws.closesocket(u.sock);
            std.os.windows.CloseHandle(u.event);
        } else {
            _ = std.posix.system.close(u.sock);
        }
        u.* = undefined;
    }

    pub fn port(u: *const UdpTun) u16 {
        return u.local_port;
    }

    /// Driver side: send writes to 127.0.0.1:`peer_port` (instead of waiting
    /// to learn the peer from the first received datagram).
    pub fn setPeerPort(u: *UdpTun, peer_port: u16) void {
        u.peer = loopbackAddr(peer_port);
    }

    /// Driver side: register with the device end (an empty datagram).
    pub fn hello(u: *UdpTun) void {
        if (u.peer) |to| _ = sendTo(u.sock, "", &to);
    }

    pub fn tun(u: *UdpTun) Tun {
        return .{ .ptr = u, .vtable = &vtable };
    }

    /// "udp:<port>" or "udp:127.0.0.1:<port>" -> port.
    pub fn parseSpec(spec: []const u8) error{InvalidSpec}!u16 {
        const rest = if (std.mem.startsWith(u8, spec, "udp:")) spec[4..] else return error.InvalidSpec;
        const p = if (std.mem.startsWith(u8, rest, "127.0.0.1:")) rest["127.0.0.1:".len..] else rest;
        return std.fmt.parseInt(u16, p, 10) catch error.InvalidSpec;
    }

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = ignoreConfig,
        .addRoute = ignoreConfig,
    };

    fn self(ptr: *anyopaque) *UdpTun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) root.WaitHandle {
        const u = self(ptr);
        return if (is_windows) u.event else u.sock;
    }

    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        const u = self(ptr);
        var attempts: u2 = 0;
        while (true) {
            var from: SockaddrIn = undefined;
            switch (recvFrom(u.sock, buf, &from)) {
                .packet => |n| {
                    if (!std.mem.eql(u8, &from.addr, &.{ 127, 0, 0, 1 })) continue; // loopback only
                    u.peer = from;
                    if (n == 0) continue; // `hello`: the driver registering itself
                    if (n > buf.len) return error.BufferTooSmall;
                    return buf[0..n];
                },
                .truncated => {
                    u.peer = from;
                    return error.BufferTooSmall;
                },
                .empty => {
                    if (!is_windows or attempts == 1) return null;
                    // Reset, then look once more: a datagram that raced the
                    // reset is either read now or re-signals the event.
                    _ = @import("queue.zig").win.ResetEvent(u.event);
                    attempts += 1;
                },
                .failed => return error.Unexpected,
            }
        }
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const u = self(ptr);
        if (packet.len > u.mtu_value) return error.PacketTooLarge;
        const to = u.peer orelse {
            u.dropped_no_peer += 1;
            return;
        };
        if (!sendTo(u.sock, packet, &to)) return error.QueueFull;
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).mtu_value;
    }

    fn ignoreConfig(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        _ = ptr;
        _ = cidr; // nothing to configure: the driver owns addressing
    }
};

const RecvResult = union(enum) { packet: usize, truncated, empty, failed };

fn recvFrom(s: UdpTun.Socket, buf: []u8, from: *SockaddrIn) RecvResult {
    if (is_windows) {
        var len: c_int = @sizeOf(SockaddrIn);
        const n = ws.recvfrom(s, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(c_int))), 0, from, &len);
        if (n >= 0) return .{ .packet = @intCast(n) };
        return switch (ws.WSAGetLastError()) {
            ws.WSAEWOULDBLOCK => .empty,
            ws.WSAEMSGSIZE => .truncated,
            ws.WSAECONNRESET => .empty,
            else => .failed,
        };
    } else {
        const sys = std.posix.system;
        while (true) {
            var len: std.posix.socklen_t = @sizeOf(SockaddrIn);
            const rc = sys.recvfrom(s, buf.ptr, buf.len, std.posix.system.MSG.TRUNC, @ptrCast(from), &len);
            switch (std.posix.errno(rc)) {
                // With MSG_TRUNC, Linux returns the real datagram length.
                .SUCCESS => return .{ .packet = @intCast(rc) },
                .INTR => continue,
                .AGAIN => return .empty,
                else => return .failed,
            }
        }
    }
}

fn sendTo(s: UdpTun.Socket, packet: []const u8, to: *const SockaddrIn) bool {
    if (is_windows) {
        return ws.sendto(s, packet.ptr, @intCast(packet.len), 0, to, @sizeOf(SockaddrIn)) >= 0;
    } else {
        const rc = std.posix.system.sendto(s, packet.ptr, packet.len, 0, @ptrCast(to), @sizeOf(SockaddrIn));
        return std.posix.errno(rc) == .SUCCESS;
    }
}

fn boundPort(s: UdpTun.Socket) OpenError!u16 {
    var sa: SockaddrIn = undefined;
    if (is_windows) {
        var len: c_int = @sizeOf(SockaddrIn);
        if (ws.getsockname(s, &sa, &len) != 0) return error.Unexpected;
    } else {
        var len: std.posix.socklen_t = @sizeOf(SockaddrIn);
        if (std.posix.errno(std.posix.system.getsockname(s, @ptrCast(&sa), &len)) != .SUCCESS) return error.Unexpected;
    }
    return std.mem.bigToNative(u16, sa.port_be);
}

fn setNonBlocking(s: std.posix.fd_t) OpenError!void {
    const sys = std.posix.system;
    const flags = sys.fcntl(s, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(flags) != .SUCCESS) return error.Unexpected;
    const nb: usize = @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }));
    if (std.posix.errno(sys.fcntl(s, std.posix.F.SETFL, @as(usize, @intCast(flags)) | nb)) != .SUCCESS) return error.Unexpected;
}

/// Minimal Winsock surface (std declares types but no functions).
pub const ws = struct {
    const HANDLE = std.os.windows.HANDLE;
    pub const INVALID_SOCKET: usize = std.math.maxInt(usize);
    pub const FD_READ: c_long = 1;
    pub const WSAEWOULDBLOCK: c_int = 10035;
    pub const WSAEMSGSIZE: c_int = 10040;
    pub const WSAEADDRINUSE: c_int = 10048;
    pub const WSAECONNRESET: c_int = 10054;
    pub const SIO_UDP_CONNRESET: u32 = 0x9800000C;

    pub extern "ws2_32" fn WSAStartup(version: u16, data: *[512]u8) callconv(.winapi) c_int;
    pub extern "ws2_32" fn socket(af: c_int, kind: c_int, proto: c_int) callconv(.winapi) usize;
    pub extern "ws2_32" fn bind(s: usize, addr: *const SockaddrIn, len: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockname(s: usize, addr: *SockaddrIn, len: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn recvfrom(s: usize, buf: [*]u8, len: c_int, flags: c_int, from: ?*SockaddrIn, fromlen: ?*c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn sendto(s: usize, buf: [*]const u8, len: c_int, flags: c_int, to: *const SockaddrIn, tolen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn closesocket(s: usize) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAEventSelect(s: usize, event: HANDLE, events: c_long) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAIoctl(s: usize, code: u32, in: ?*const anyopaque, in_len: u32, out: ?*anyopaque, out_len: u32, ret: *u32, overlapped: ?*anyopaque, completion: ?*const anyopaque) callconv(.winapi) c_int;

    var started = std.atomic.Value(bool).init(false);

    /// WSAStartup once per process (reference-counted by Winsock; we never
    /// call WSACleanup, process exit does).
    pub fn startup() OpenError!void {
        if (started.load(.acquire)) return;
        var data: [512]u8 align(8) = undefined;
        if (WSAStartup(0x0202, &data) != 0) return error.SystemResources;
        started.store(true, .release);
    }
};

test "UdpTun: driver -> read, write -> driver (loopback, two sockets)" {
    var dev = try UdpTun.open(0, 1280);
    defer dev.close();
    var drv = try UdpTun.open(0, 1280); // the "test driver" end
    defer drv.close();
    const t = dev.tun();
    const d = drv.tun();
    var buf: [1280]u8 = undefined;

    // Device writes before any driver traffic are dropped (no peer yet).
    try t.write("\x45early");
    try std.testing.expectEqual(@as(u64, 1), dev.dropped_no_peer);

    // Driver -> device: the driver needs a peer, so point it at the device.
    drv.setPeerPort(dev.port());
    try d.write("\x45ping");
    try @import("queue.zig").waitReadable(t.waitHandle(), 2000);
    try std.testing.expectEqualStrings("\x45ping", (try t.read(&buf)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try t.read(&buf));

    // A hello registers without producing a packet.
    drv.hello();
    try @import("queue.zig").waitReadable(t.waitHandle(), 2000);
    try std.testing.expectEqual(@as(?[]u8, null), try t.read(&buf));

    // Device -> driver: goes back to where the ping came from.
    try t.write("\x45pong");
    try @import("queue.zig").waitReadable(d.waitHandle(), 2000);
    try std.testing.expectEqualStrings("\x45pong", (try d.read(&buf)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try d.read(&buf));
}

test "UdpTun spec parsing" {
    try std.testing.expectEqual(@as(u16, 5000), try UdpTun.parseSpec("udp:5000"));
    try std.testing.expectEqual(@as(u16, 7), try UdpTun.parseSpec("udp:127.0.0.1:7"));
    try std.testing.expectError(error.InvalidSpec, UdpTun.parseSpec("tcp:1"));
    try std.testing.expectError(error.InvalidSpec, UdpTun.parseSpec("udp:10.0.0.1:7"));
}
