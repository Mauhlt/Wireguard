//! macOS TUN backend: utun via a PF_SYSTEM / SYSPROTO_CONTROL socket.
//!
//! utun frames every packet with a 4-byte big-endian address family
//! (AF_INET = 2, AF_INET6 = 30); we strip it on read and add it on write,
//! so the device only ever sees raw IP packets. The socket is non-blocking
//! and is itself the wait handle (kqueue EVFILT_READ / poll POLLIN).
//!
//! Interface names are chosen by the kernel: pass "utun" for the next free
//! unit or "utunN" for a specific one; `ifName()` reports what we got.
//! Addresses: SIOCAIFADDR / SIOCAIFADDR_IN6 (point-to-point, like
//! wg-quick's `ifconfig utunN inet A A alias`). Routes: an RTM_ADD message on
//! a PF_ROUTE socket with the interface as gateway (like
//! `route add -net P -interface utunN`). All of it needs root.
//!
//! Status: compile-checked only (cross-compiled in `zig build test`).
const std = @import("std");
const c = std.c;
const root = @import("root.zig");
const Cidr = root.Cidr;
const Tun = root.Tun;

pub const OpenError = error{ AccessDenied, InvalidName, NameTooLong, SystemResources, Unexpected };

pub const OpenOptions = struct {
    mtu: u16 = root.default_mtu,
};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;
const AF_ROUTE: c_uint = 17;
const AF_SYSTEM: c_uint = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: c_uint = 2;
const SOCK_DGRAM: c_uint = 2;
const SOCK_RAW: c_uint = 3;
const UTUN_OPT_IFNAME: u32 = 2;
const CTLIOCGINFO: c_ulong = 0xc0644e03; // _IOWR('N', 3, struct ctl_info)
const SIOCSIFMTU: c_ulong = 0x80206934; // _IOW('i', 52, struct ifreq)
const SIOCAIFADDR: c_ulong = 0x8040691a; // _IOW('i', 26, struct ifaliasreq)
const SIOCAIFADDR_IN6: c_ulong = 0x8080691a; // _IOW('i', 26, struct in6_aliasreq)
const RTM_VERSION: u8 = 5;
const RTM_ADD: u8 = 1;
const RTF_UP: i32 = 0x1;
const RTF_STATIC: i32 = 0x800;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
const ND6_INFINITE_LIFETIME: u32 = 0xffff_ffff;

const CtlInfo = extern struct { id: u32, name: [96]u8 };
const SockaddrCtl = extern struct {
    len: u8 = @sizeOf(SockaddrCtl),
    family: u8 = AF_SYSTEM,
    sysaddr: u16 = AF_SYS_CONTROL,
    id: u32,
    unit: u32,
    reserved: [5]u32 = @splat(0),
};
const SockaddrIn = extern struct { len: u8 = 16, family: u8 = AF_INET, port: u16 = 0, addr: [4]u8, zero: [8]u8 = @splat(0) };
const SockaddrIn6 = extern struct { len: u8 = 28, family: u8 = AF_INET6, port: u16 = 0, flowinfo: u32 = 0, addr: [16]u8, scope_id: u32 = 0 };
const SockaddrDl = extern struct { len: u8 = 20, family: u8 = AF_LINK, index: u16, type: u8 = 0, nlen: u8 = 0, alen: u8 = 0, slen: u8 = 0, data: [12]u8 = @splat(0) };
const IfReqMtu = extern struct { name: [16]u8, mtu: i32, pad: [12]u8 = @splat(0) };
const IfAliasReq = extern struct { name: [16]u8, addr: SockaddrIn, dstaddr: SockaddrIn, mask: SockaddrIn };
const In6AddrLifetime = extern struct { expire: i64 = 0, preferred: i64 = 0, vltime: u32 = ND6_INFINITE_LIFETIME, pltime: u32 = ND6_INFINITE_LIFETIME };
const In6AliasReq = extern struct {
    name: [16]u8,
    addr: SockaddrIn6,
    dstaddr: SockaddrIn6,
    prefixmask: SockaddrIn6,
    flags: i32 = 0,
    lifetime: In6AddrLifetime = .{},
};
const RtMsgHdr = extern struct {
    msglen: u16,
    version: u8 = RTM_VERSION,
    type: u8,
    index: u16 = 0,
    flags: i32,
    addrs: i32,
    pid: i32 = 0,
    seq: i32,
    errno: i32 = 0,
    use: i32 = 0,
    inits: u32 = 0,
    rmx: [14]u32 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(CtlInfo) == 100);
    std.debug.assert(@sizeOf(SockaddrCtl) == 32);
    std.debug.assert(@sizeOf(IfReqMtu) == 32);
    std.debug.assert(@sizeOf(IfAliasReq) == 64);
    std.debug.assert(@sizeOf(In6AliasReq) == 128);
    std.debug.assert(@sizeOf(RtMsgHdr) == 92);
    std.debug.assert(@sizeOf(SockaddrDl) == 20);
}

extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

pub const Utun = struct {
    fd: c.fd_t,
    name_buf: [16]u8,
    mtu_value: u16,
    route_seq: i32 = 0,

    pub fn open(name: []const u8, options: OpenOptions) OpenError!Utun {
        const unit: u32 = if (std.mem.eql(u8, name, "utun")) 0 else blk: {
            if (!std.mem.startsWith(u8, name, "utun")) return error.InvalidName;
            const n = std.fmt.parseInt(u32, name[4..], 10) catch return error.InvalidName;
            if (n > 1_000_000) return error.InvalidName;
            break :blk n + 1; // sc_unit is 1-based; 0 = next free
        };

        const fd = c.socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return errnoOpen();
        errdefer _ = c.close(fd);

        var info: CtlInfo = .{ .id = 0, .name = @splat(0) };
        const ctl_name = "com.apple.net.utun_control";
        @memcpy(info.name[0..ctl_name.len], ctl_name);
        if (c.ioctl(fd, @bitCast(@as(c_uint, @truncate(CTLIOCGINFO))), &info) < 0) return errnoOpen();

        var addr: SockaddrCtl = .{ .id = info.id, .unit = unit };
        if (c.connect(fd, @ptrCast(&addr), @sizeOf(SockaddrCtl)) < 0) return errnoOpen();

        // Non-blocking + close-on-exec.
        const nonblock: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
        if (c.fcntl(fd, c.F.SETFL, nonblock) < 0) return error.Unexpected;
        if (c.fcntl(fd, c.F.SETFD, @as(c_int, 1)) < 0) return error.Unexpected;

        var t: Utun = .{ .fd = fd, .name_buf = @splat(0), .mtu_value = options.mtu };
        var len: c.socklen_t = t.name_buf.len;
        if (c.getsockopt(fd, @intCast(SYSPROTO_CONTROL), UTUN_OPT_IFNAME, &t.name_buf, &len) < 0) return error.Unexpected;

        const s = c.socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return error.SystemResources;
        defer _ = c.close(s);
        var req: IfReqMtu = .{ .name = t.name_buf, .mtu = options.mtu };
        if (c.ioctl(s, @bitCast(@as(c_uint, @truncate(SIOCSIFMTU))), &req) < 0) return errnoOpen();
        return t;
    }

    pub fn close(t: *Utun) void {
        _ = c.close(t.fd);
        t.* = undefined;
    }

    pub fn ifName(t: *const Utun) []const u8 {
        return std.mem.sliceTo(&t.name_buf, 0);
    }

    pub fn tun(t: *Utun) Tun {
        return .{ .ptr = t, .vtable = &vtable };
    }

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = setAddress,
        .addRoute = addRoute,
    };

    fn self(ptr: *anyopaque) *Utun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) root.WaitHandle {
        return self(ptr).fd;
    }

    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        const t = self(ptr);
        var hdr: [4]u8 = undefined;
        const iov = [2]c.iovec{
            .{ .base = &hdr, .len = 4 },
            .{ .base = buf.ptr, .len = buf.len },
        };
        while (true) {
            const n = c.readv(t.fd, &iov, 2);
            if (n < 0) switch (c.errno(n)) {
                .INTR => continue,
                .AGAIN => return null,
                .BADF, .NOTCONN, .IO => return error.Closed,
                else => return error.Unexpected,
            };
            if (n <= 4) continue; // empty / malformed frame: skip it
            const len: usize = @intCast(n - 4);
            // A datagram socket truncates silently; a full buffer smaller than
            // the MTU may have lost bytes.
            if (len == buf.len and buf.len < t.mtu_value) return error.BufferTooSmall;
            return buf[0..len];
        }
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const t = self(ptr);
        if (packet.len == 0) return error.InvalidPacket;
        const af: u32 = switch (packet[0] >> 4) {
            4 => AF_INET,
            6 => AF_INET6,
            else => return error.InvalidPacket,
        };
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, af, .big);
        const iov = [2]c.iovec_const{
            .{ .base = &hdr, .len = 4 },
            .{ .base = packet.ptr, .len = packet.len },
        };
        while (true) {
            const n = c.writev(t.fd, &iov, 2);
            if (n >= 0) return;
            switch (c.errno(n)) {
                .INTR => continue,
                .AGAIN, .NOBUFS => return error.QueueFull,
                .MSGSIZE => return error.PacketTooLarge,
                .INVAL => return error.InvalidPacket,
                .BADF, .NOTCONN, .IO => return error.Closed,
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
                const s = try socketConfig(AF_INET, SOCK_DGRAM);
                defer _ = c.close(s);
                const a = cidr.addr[0..4].*;
                var req: IfAliasReq = .{
                    .name = t.name_buf,
                    .addr = .{ .addr = a },
                    .dstaddr = .{ .addr = a },
                    .mask = .{ .addr = cidr.netmask4() },
                };
                if (c.ioctl(s, @bitCast(@as(c_uint, @truncate(SIOCAIFADDR))), &req) < 0) return errnoConfig();
            },
            .ip6 => {
                const s = try socketConfig(AF_INET6, SOCK_DGRAM);
                defer _ = c.close(s);
                var req: In6AliasReq = .{
                    .name = t.name_buf,
                    .addr = .{ .addr = cidr.addr },
                    .dstaddr = .{ .len = 0, .family = 0, .addr = @splat(0) },
                    .prefixmask = .{ .addr = prefixMask6(cidr.prefix_len) },
                };
                if (c.ioctl(s, @bitCast(@as(c_uint, @truncate(SIOCAIFADDR_IN6))), &req) < 0) return errnoConfig();
            },
        }
    }

    fn addRoute(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        const t = self(ptr);
        const index = if_nametoindex(@ptrCast(&t.name_buf));
        if (index == 0) return error.Closed;
        const net = cidr.network();
        t.route_seq +%= 1;

        var msg: [512]u8 align(4) = undefined;
        var len: usize = @sizeOf(RtMsgHdr);
        switch (cidr.family) {
            .ip4 => {
                len += appendSa(&msg, len, SockaddrIn{ .addr = net.addr[0..4].* });
                len += appendSa(&msg, len, SockaddrDl{ .index = @intCast(index) });
                len += appendSa(&msg, len, SockaddrIn{ .addr = cidr.netmask4() });
            },
            .ip6 => {
                len += appendSa(&msg, len, SockaddrIn6{ .addr = net.addr });
                len += appendSa(&msg, len, SockaddrDl{ .index = @intCast(index) });
                len += appendSa(&msg, len, SockaddrIn6{ .addr = prefixMask6(cidr.prefix_len) });
            },
        }
        const hdr: RtMsgHdr = .{
            .msglen = @intCast(len),
            .type = RTM_ADD,
            .flags = RTF_UP | RTF_STATIC,
            .addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK,
            .seq = t.route_seq,
        };
        @memcpy(msg[0..@sizeOf(RtMsgHdr)], std.mem.asBytes(&hdr));

        const s = try socketConfig(AF_ROUTE, SOCK_RAW);
        defer _ = c.close(s);
        const n = c.write(s, &msg, len);
        if (n < 0) {
            if (c.errno(n) == .EXIST) return;
            return errnoConfig();
        }
    }
};

fn appendSa(msg: []u8, at: usize, sa: anytype) usize {
    const b = std.mem.asBytes(&sa);
    @memcpy(msg[at..][0..b.len], b);
    return std.mem.alignForward(usize, b.len, 4);
}

fn prefixMask6(prefix_len: u8) [16]u8 {
    var m: [16]u8 = @splat(0);
    var bits: usize = prefix_len;
    for (&m) |*b| {
        if (bits >= 8) {
            b.* = 0xff;
            bits -= 8;
        } else {
            b.* = @truncate(@as(u16, 0xff00) >> @intCast(bits));
            bits = 0;
        }
    }
    return m;
}

fn socketConfig(family: c_uint, kind: c_uint) root.ConfigError!c.fd_t {
    const s = c.socket(family, kind, 0);
    if (s < 0) return errnoConfig();
    return s;
}

fn errnoOpen() OpenError {
    return switch (c.errno(@as(c_int, -1))) {
        .PERM, .ACCES => error.AccessDenied,
        .BUSY, .INVAL => error.InvalidName,
        .MFILE, .NFILE, .NOMEM, .NOBUFS => error.SystemResources,
        else => error.Unexpected,
    };
}

fn errnoConfig() root.ConfigError {
    return switch (c.errno(@as(c_int, -1))) {
        .PERM, .ACCES => error.AccessDenied,
        .NXIO, .NODEV => error.Closed,
        else => error.Unexpected,
    };
}

test "ipv6 prefix masks" {
    try std.testing.expectEqual(@as(u8, 0xff), prefixMask6(64)[7]);
    try std.testing.expectEqual(@as(u8, 0), prefixMask6(64)[8]);
    try std.testing.expectEqual(@as(u8, 0xfe), prefixMask6(7)[0]);
}
