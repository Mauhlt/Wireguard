//! POSIX backend (Linux, macOS, iOS) for the device's OS seam: non-blocking
//! UDP sockets whose fd is the readiness handle, and poll(2) over
//! {sockets, TUN fd, wakers} with the next timer deadline as the timeout.
//!
//! Status: unit tests pass on Linux (WSL2) and the live netns test runs zwg on
//! it against kernel WireGuard (tests/interop/live_linux.zig). `zwg down` on POSIX is not wired up yet (SIGINT/SIGTERM stop a
//! foreground `zwg up`).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const net = std.Io.net;
const common = @import("common.zig");

pub const WaitHandle = posix.fd_t;
const is_linux = builtin.os.tag == .linux;

fn setNonBlockCloexec(fd: posix.fd_t) bool {
    if (is_linux) return true; // set via SOCK flags
    const c = std.c;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
    return c.fcntl(fd, c.F.SETFL, nonblock) != -1 and c.fcntl(fd, c.F.SETFD, @as(c_int, 1)) != -1;
}

pub const Udp = struct {
    fd: posix.fd_t,
    family: common.Family,

    pub fn open(family: common.Family, port: u16) common.OpenError!Udp {
        const af: u32 = if (family == .v4) posix.AF.INET else posix.AF.INET6;
        var kind: u32 = posix.SOCK.DGRAM;
        if (is_linux) kind |= posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
        const rc = sys.socket(@intCast(af), @intCast(kind), 0);
        if (posix.errno(rc) != .SUCCESS) return error.SystemResources;
        const fd: posix.fd_t = @intCast(rc);
        errdefer _ = sys.close(fd);
        if (!setNonBlockCloexec(fd)) return error.Unexpected;
        if (family == .v6) {
            const one: c_int = 1;
            posix.setsockopt(fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, std.mem.asBytes(&one)) catch {};
        }
        const bufsz: c_int = 4 << 20;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&bufsz)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&bufsz)) catch {};

        var storage: posix.sockaddr.storage = undefined;
        const len = toSockaddr(&storage, switch (family) {
            .v4 => .{ .ip4 = .{ .bytes = @splat(0), .port = port } },
            .v6 => .{ .ip6 = .{ .bytes = @splat(0), .port = port } },
        });
        const brc = sys.bind(fd, @ptrCast(&storage), len);
        switch (posix.errno(brc)) {
            .SUCCESS => {},
            .ADDRINUSE => return error.AddressInUse,
            .ACCES, .PERM => return error.AccessDenied,
            .AFNOSUPPORT, .ADDRNOTAVAIL => return error.AddressFamilyUnsupported,
            else => return error.Unexpected,
        }
        return .{ .fd = fd, .family = family };
    }

    pub fn close(u: *Udp) void {
        _ = sys.close(u.fd);
        u.* = undefined;
    }

    pub fn localPort(u: *const Udp) u16 {
        var storage: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        if (posix.errno(sys.getsockname(u.fd, @ptrCast(&storage), &len)) != .SUCCESS) return 0;
        const a = fromSockaddr(&storage) orelse return 0;
        return a.getPort();
    }

    pub fn waitHandle(u: *const Udp) WaitHandle {
        return u.fd;
    }

    pub fn beginDrain(u: *Udp) void {
        _ = u;
    }

    pub fn recv(u: *Udp, buf: []u8) common.RecvError!?common.Datagram {
        while (true) {
            var storage: posix.sockaddr.storage = undefined;
            var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const rc = sys.recvfrom(u.fd, buf.ptr, buf.len, 0, @ptrCast(&storage), &len);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => return null,
                .INTR, .CONNREFUSED, .MSGSIZE => continue,
                else => return error.Unexpected,
            }
            const from = fromSockaddr(&storage) orelse continue;
            return .{ .len = @intCast(rc), .from = from };
        }
    }

    pub fn send(u: *Udp, to: net.IpAddress, data: []const u8) common.SendError!void {
        if ((to == .ip4) != (u.family == .v4)) return error.AddressFamilyMismatch;
        var storage: posix.sockaddr.storage = undefined;
        const len = toSockaddr(&storage, to);
        const rc = sys.sendto(u.fd, data.ptr, data.len, 0, @ptrCast(&storage), len);
        return switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .NOBUFS => error.WouldBlock,
            .HOSTUNREACH, .NETUNREACH, .ADDRNOTAVAIL, .NETDOWN => error.Unreachable,
            .MSGSIZE => error.MessageTooBig,
            else => error.Unexpected,
        };
    }

    fn toSockaddr(storage: *posix.sockaddr.storage, a: net.IpAddress) posix.socklen_t {
        switch (a) {
            .ip4 => |x| {
                const p: *posix.sockaddr.in = @ptrCast(storage);
                p.* = std.mem.zeroes(posix.sockaddr.in);
                if (@hasField(posix.sockaddr.in, "len")) p.len = @sizeOf(posix.sockaddr.in);
                p.family = posix.AF.INET;
                p.port = std.mem.nativeToBig(u16, x.port);
                p.addr = @bitCast(x.bytes);
                return @sizeOf(posix.sockaddr.in);
            },
            .ip6 => |x| {
                const p: *posix.sockaddr.in6 = @ptrCast(storage);
                p.* = std.mem.zeroes(posix.sockaddr.in6);
                if (@hasField(posix.sockaddr.in6, "len")) p.len = @sizeOf(posix.sockaddr.in6);
                p.family = posix.AF.INET6;
                p.port = std.mem.nativeToBig(u16, x.port);
                p.addr = x.bytes;
                p.scope_id = x.interface.index;
                return @sizeOf(posix.sockaddr.in6);
            },
        }
    }

    fn fromSockaddr(storage: *const posix.sockaddr.storage) ?net.IpAddress {
        switch (storage.family) {
            posix.AF.INET => {
                const p: *const posix.sockaddr.in = @ptrCast(storage);
                return .{ .ip4 = .{ .bytes = @bitCast(p.addr), .port = std.mem.bigToNative(u16, p.port) } };
            },
            posix.AF.INET6 => {
                const p: *const posix.sockaddr.in6 = @ptrCast(storage);
                return .{ .ip6 = .{ .bytes = p.addr, .port = std.mem.bigToNative(u16, p.port), .interface = .{ .index = p.scope_id } } };
            },
            else => return null,
        }
    }
};

pub fn wait(handles: []const WaitHandle, timeout_ns: ?u64) common.WaitError!?usize {
    var fds: [64]posix.pollfd = undefined;
    std.debug.assert(handles.len <= fds.len);
    for (handles, 0..) |h, i| fds[i] = .{ .fd = h, .events = posix.POLL.IN, .revents = 0 };
    const ms: i32 = if (timeout_ns) |ns| @intCast(@min((ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms, std.math.maxInt(i32))) else -1;
    const n = posix.poll(fds[0..handles.len], ms) catch return error.Unexpected;
    if (n == 0) return null;
    for (fds[0..handles.len], 0..) |f, i| if (f.revents != 0) return i;
    return null;
}

const is_darwin = builtin.os.tag.isDarwin();

/// Becomes ready when a deadline passes on a clock that keeps counting
/// while the machine sleeps. poll(2)'s timeout does not (Linux:
/// CLOCK_MONOTONIC; Darwin: mach_absolute_time), so after a resume the
/// loop would otherwise wait out the rest of its pre-suspend timeout before
/// noticing the timers that fell due meanwhile. Linux: a timerfd on
/// CLOCK_BOOTTIME. macOS / iOS: a kqueue (pollable) with a one-shot
/// EVFILT_TIMER on mach_continuous_time (NOTE_MACH_CONTINUOUS_TIME).
/// Elsewhere: none (null handle; the poll timeout alone).
pub const DeadlineTimer = struct {
    fd: posix.fd_t,

    pub fn init() common.WaitError!DeadlineTimer {
        if (is_linux) {
            const rc = std.os.linux.timerfd_create(.BOOTTIME, .{ .NONBLOCK = true, .CLOEXEC = true });
            if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
            return .{ .fd = @intCast(rc) };
        }
        if (is_darwin) {
            const kq = std.c.kqueue();
            if (kq < 0) return error.Unexpected;
            if (std.c.fcntl(kq, std.c.F.SETFD, @as(c_int, 1)) == -1) {
                _ = sys.close(kq);
                return error.Unexpected;
            }
            return .{ .fd = kq };
        }
        return .{ .fd = -1 };
    }

    pub fn deinit(t: *DeadlineTimer) void {
        if (t.fd >= 0) _ = sys.close(t.fd);
        t.* = undefined;
    }

    pub fn waitHandle(t: *const DeadlineTimer) ?WaitHandle {
        return if (t.fd >= 0) t.fd else null;
    }

    /// Ready `ns` from now (replaces any earlier arming).
    pub fn arm(t: *DeadlineTimer, ns: u64) void {
        t.set(@max(ns, 1));
    }

    pub fn disarm(t: *DeadlineTimer) void {
        t.set(0);
    }

    /// After it was reported ready: consume the expiration.
    pub fn clear(t: *DeadlineTimer) void {
        if (is_linux) {
            var ticks: u64 = 0;
            _ = sys.read(t.fd, std.mem.asBytes(&ticks), 8);
        } else if (is_darwin) {
            var ev: [1]std.c.Kevent = undefined;
            const zero: std.c.timespec = .{ .sec = 0, .nsec = 0 };
            _ = std.c.kevent(t.fd, &ev, 0, &ev, 1, &zero);
        }
    }

    fn set(t: *DeadlineTimer, ns: u64) void {
        if (is_linux) {
            const spec: std.os.linux.itimerspec = .{
                .it_interval = .{ .sec = 0, .nsec = 0 },
                .it_value = .{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) },
            };
            // Re-arming resets the expiration count: no stale wake-up.
            _ = std.os.linux.timerfd_settime(t.fd, .{}, &spec, null);
        } else if (is_darwin) {
            const c = std.c;
            const change: [1]c.Kevent = .{.{
                .ident = 1,
                .filter = c.EVFILT.TIMER,
                .flags = if (ns == 0) c.EV.DELETE else c.EV.ADD | c.EV.ONESHOT,
                .fflags = c.NOTE.NSECONDS | c.NOTE.MACH_CONTINUOUS_TIME,
                .data = @intCast(@min(ns, std.math.maxInt(isize))),
                .udata = 0,
            }};
            var out: [1]c.Kevent = undefined;
            const zero: c.timespec = .{ .sec = 0, .nsec = 0 };
            t.clear();
            _ = c.kevent(t.fd, &change, 1, &out, 0, &zero);
        }
    }
};

/// Self-pipe the loop waits on; SIGINT/SIGTERM write to it.
pub const StopSignal = struct {
    read_fd: posix.fd_t,
    write_fd: posix.fd_t,

    pub fn create(name: []const u8) common.StopError!StopSignal {
        _ = name;
        var fds: [2]posix.fd_t = undefined;
        if (is_linux) {
            if (posix.errno(std.os.linux.pipe2(&fds, .{ .NONBLOCK = true, .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
        } else {
            if (std.c.pipe(&fds) != 0) return error.Unexpected;
            if (!setNonBlockCloexec(fds[0]) or !setNonBlockCloexec(fds[1])) return error.Unexpected;
        }
        return .{ .read_fd = fds[0], .write_fd = fds[1] };
    }

    pub fn signalExisting(name: []const u8) common.StopError!void {
        _ = name;
        return error.Unsupported;
    }

    pub fn waitHandle(s: *const StopSignal) WaitHandle {
        return s.read_fd;
    }

    pub fn signal(s: *const StopSignal) void {
        const one = [1]u8{1};
        _ = sys.write(s.write_fd, &one, 1);
    }

    pub fn close(s: *StopSignal) void {
        _ = sys.close(s.read_fd);
        _ = sys.close(s.write_fd);
        s.* = undefined;
    }
};

var stop_target: posix.fd_t = -1;

fn onSignal(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    if (stop_target >= 0) {
        const one = [1]u8{1};
        _ = sys.write(stop_target, &one, 1);
    }
}

pub fn stopOnInterrupt(stop: *const StopSignal) void {
    stop_target = stop.write_fd;
    const act: posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(.INT, &act, null);
    posix.sigaction(.TERM, &act, null);
}
