//! Linux TUN backend: /dev/net/tun with IFF_TUN | IFF_NO_PI.
//!
//! Raw syscalls (std.os.linux), no libc. The tun fd is non-blocking and is
//! itself the wait handle (poll POLLIN / epoll EPOLLIN). Addresses, MTU and
//! routes use the classic ioctls (SIOCSIFADDR, SIOCSIFMTU, SIOCADDRT on an
//! AF_INET / AF_INET6 datagram socket), which need CAP_NET_ADMIN.
//!
//! Status: compile-checked only (cross-compiled from Windows in
//! `zig build test`); not yet run on a Linux host.
const std = @import("std");
const linux = std.os.linux;
const root = @import("root.zig");
const Cidr = root.Cidr;
const Tun = root.Tun;

pub const OpenError = error{
    /// No CAP_NET_ADMIN (run as root or `setcap cap_net_admin+ep zwg`).
    AccessDenied,
    /// /dev/net/tun missing (tun module not loaded / container without it).
    TunNotAvailable,
    NameTooLong,
    InvalidName,
    SystemResources,
    Unexpected,
};

pub const OpenOptions = struct {
    mtu: u16 = root.default_mtu,
};

const TUNSETIFF: u32 = 0x400454ca; // _IOW('T', 202, int)
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFNETMASK: u32 = 0x891c;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCADDRT: u32 = 0x890B;
const RTF_UP: u16 = 0x0001;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const SockaddrIn = extern struct { family: u16, port: u16 = 0, addr: [4]u8, zero: [8]u8 = @splat(0) };
const Sockaddr = extern struct { family: u16, data: [14]u8 };

const IfReq = extern struct {
    name: [16]u8,
    u: extern union {
        addr: Sockaddr,
        flags: u16,
        ivalue: i32,
        pad: [24]u8,
    },
};

const In6IfReq = extern struct {
    addr: [16]u8,
    prefixlen: u32,
    ifindex: i32,
};

const RtEntry = extern struct {
    pad1: c_ulong = 0,
    dst: Sockaddr,
    gateway: Sockaddr,
    genmask: Sockaddr,
    flags: u16,
    pad2: i16 = 0,
    pad3: c_ulong = 0,
    pad4: ?*anyopaque = null,
    metric: i16 = 0,
    dev: ?[*:0]const u8,
    mtu: c_ulong = 0,
    window: c_ulong = 0,
    irtt: u16 = 0,
};

const In6RtMsg = extern struct {
    dst: [16]u8,
    src: [16]u8,
    gateway: [16]u8,
    type: u32,
    dst_len: u16,
    src_len: u16,
    metric: u32,
    info: c_ulong,
    flags: u32,
    ifindex: i32,
};

comptime {
    std.debug.assert(@sizeOf(SockaddrIn) == @sizeOf(Sockaddr));
    std.debug.assert(@sizeOf(IfReq) == 40);
    std.debug.assert(@sizeOf(In6IfReq) == 24);
}

fn sockaddr4(a: [4]u8) Sockaddr {
    const sin: SockaddrIn = .{ .family = AF_INET, .addr = a };
    return std.mem.bytesToValue(Sockaddr, std.mem.asBytes(&sin));
}

pub const LinuxTun = struct {
    fd: linux.fd_t,
    /// AF_INET datagram socket for interface ioctls.
    ctl4: linux.fd_t,
    name_buf: [16]u8,
    mtu_value: u16,

    pub fn open(name: []const u8, options: OpenOptions) OpenError!LinuxTun {
        if (name.len == 0) return error.InvalidName;
        if (name.len >= 16) return error.NameTooLong;
        const rc = linux.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0);
        const fd: linux.fd_t = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .NOENT, .NODEV, .NXIO => return error.TunNotAvailable,
            .ACCES, .PERM => return error.AccessDenied,
            .MFILE, .NFILE, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        };
        errdefer _ = linux.close(fd);

        var ifr = std.mem.zeroes(IfReq);
        @memcpy(ifr.name[0..name.len], name);
        ifr.u.flags = IFF_TUN | IFF_NO_PI;
        try check(linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)));

        const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(s) != .SUCCESS) return error.SystemResources;
        const ctl4: linux.fd_t = @intCast(s);
        errdefer _ = linux.close(ctl4);

        var t: LinuxTun = .{ .fd = fd, .ctl4 = ctl4, .name_buf = ifr.name, .mtu_value = options.mtu };
        // MTU, then administratively up.
        var req = t.ifreq();
        req.u.ivalue = options.mtu;
        try check(linux.ioctl(ctl4, SIOCSIFMTU, @intFromPtr(&req)));
        req = t.ifreq();
        try check(linux.ioctl(ctl4, SIOCGIFFLAGS, @intFromPtr(&req)));
        req.u.flags |= 0x1 | 0x40; // IFF_UP | IFF_RUNNING
        try check(linux.ioctl(ctl4, SIOCSIFFLAGS, @intFromPtr(&req)));
        return t;
    }

    pub fn close(t: *LinuxTun) void {
        _ = linux.close(t.fd);
        _ = linux.close(t.ctl4);
        t.* = undefined;
    }

    pub fn ifName(t: *const LinuxTun) []const u8 {
        return std.mem.sliceTo(&t.name_buf, 0);
    }

    pub fn tun(t: *LinuxTun) Tun {
        return .{ .ptr = t, .vtable = &vtable };
    }

    fn ifreq(t: *const LinuxTun) IfReq {
        var r = std.mem.zeroes(IfReq);
        r.name = t.name_buf;
        return r;
    }

    fn ifindex(t: *const LinuxTun) root.ConfigError!i32 {
        var r = t.ifreq();
        try checkConfig(linux.ioctl(t.ctl4, SIOCGIFINDEX, @intFromPtr(&r)));
        return r.u.ivalue;
    }

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = setAddress,
        .addRoute = addRoute,
    };

    fn self(ptr: *anyopaque) *LinuxTun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) root.WaitHandle {
        return self(ptr).fd;
    }

    /// The kernel truncates a packet longer than `buf`, so pass a buffer of
    /// at least `mtu()` bytes; a full-length read is reported as too small.
    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        const t = self(ptr);
        while (true) {
            const rc = linux.read(t.fd, buf.ptr, buf.len);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == buf.len and buf.len < t.mtu_value) return error.BufferTooSmall;
                    return buf[0..rc];
                },
                .INTR => continue,
                .AGAIN => return null,
                .BADF, .BADFD, .IO => return error.Closed,
                else => return error.Unexpected,
            }
        }
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const t = self(ptr);
        if (packet.len == 0) return error.InvalidPacket;
        while (true) {
            const rc = linux.write(t.fd, packet.ptr, packet.len);
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN, .NOBUFS => return error.QueueFull,
                .INVAL => return error.InvalidPacket,
                .MSGSIZE => return error.PacketTooLarge,
                .BADF, .BADFD, .IO => return error.Closed,
                else => return error.Unexpected,
            }
        }
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).mtu_value;
    }

    fn setAddress(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        const t = self(ptr);
        switch (cidr.family) {
            .ip4 => {
                var r = t.ifreq();
                r.u.addr = sockaddr4(cidr.addr[0..4].*);
                try checkConfig(linux.ioctl(t.ctl4, SIOCSIFADDR, @intFromPtr(&r)));
                r = t.ifreq();
                r.u.addr = sockaddr4(cidr.netmask4());
                try checkConfig(linux.ioctl(t.ctl4, SIOCSIFNETMASK, @intFromPtr(&r)));
            },
            .ip6 => {
                const s6 = try socket6();
                defer _ = linux.close(s6);
                var r: In6IfReq = .{ .addr = cidr.addr, .prefixlen = cidr.prefix_len, .ifindex = try t.ifindex() };
                try checkConfig(linux.ioctl(s6, SIOCSIFADDR, @intFromPtr(&r)));
            },
        }
    }

    fn addRoute(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        const t = self(ptr);
        const net = cidr.network();
        switch (cidr.family) {
            .ip4 => {
                var rt: RtEntry = .{
                    .dst = sockaddr4(net.addr[0..4].*),
                    .gateway = sockaddr4(.{ 0, 0, 0, 0 }),
                    .genmask = sockaddr4(cidr.netmask4()),
                    .flags = RTF_UP,
                    .dev = @ptrCast(&t.name_buf),
                };
                try checkConfig(linux.ioctl(t.ctl4, SIOCADDRT, @intFromPtr(&rt)));
            },
            .ip6 => {
                const s6 = try socket6();
                defer _ = linux.close(s6);
                var rt = std.mem.zeroes(In6RtMsg);
                rt.dst = net.addr;
                rt.dst_len = cidr.prefix_len;
                rt.metric = 1;
                rt.flags = RTF_UP;
                rt.ifindex = try t.ifindex();
                try checkConfig(linux.ioctl(s6, SIOCADDRT, @intFromPtr(&rt)));
            },
        }
    }

    fn socket6() root.ConfigError!linux.fd_t {
        const s = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(s) != .SUCCESS) return error.Unexpected;
        return @intCast(s);
    }
};

fn check(rc: usize) OpenError!void {
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => error.AccessDenied,
        .BUSY, .INVAL => error.InvalidName,
        .NOMEM, .NOBUFS => error.SystemResources,
        else => error.Unexpected,
    };
}

fn checkConfig(rc: usize) root.ConfigError!void {
    return switch (linux.errno(rc)) {
        .SUCCESS, .EXIST => {},
        .PERM, .ACCES => error.AccessDenied,
        .NODEV, .NXIO => error.Closed,
        else => error.Unexpected,
    };
}
