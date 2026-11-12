//! An interface address or route prefix: "10.0.0.1/24", "fd00::1/64".
//! Used by `Tun.setAddress` / `Tun.addRoute`; the device's allowed-IPs trie
//! may convert to and from it.
const std = @import("std");
const net = std.Io.net;

pub const Cidr = struct {
    family: Family,
    /// Network byte order. IPv4 uses the first 4 bytes; the rest are zero.
    addr: [16]u8,
    prefix_len: u8,

    pub const Family = enum { ip4, ip6 };

    pub const ParseError = error{InvalidCidr};

    pub fn ip4(a: [4]u8, prefix_len: u8) Cidr {
        std.debug.assert(prefix_len <= 32);
        var addr: [16]u8 = @splat(0);
        addr[0..4].* = a;
        return .{ .family = .ip4, .addr = addr, .prefix_len = prefix_len };
    }

    pub fn ip6(a: [16]u8, prefix_len: u8) Cidr {
        std.debug.assert(prefix_len <= 128);
        return .{ .family = .ip6, .addr = a, .prefix_len = prefix_len };
    }

    /// "a.b.c.d/n" or "x:y::z/n". A bare address means a host prefix (/32, /128).
    pub fn parse(text: []const u8) ParseError!Cidr {
        const slash = std.mem.indexOfScalar(u8, text, '/');
        const addr_text = if (slash) |s| text[0..s] else text;
        const is6 = std.mem.indexOfScalar(u8, addr_text, ':') != null;
        const max: u8 = if (is6) 128 else 32;
        const prefix_len: u8 = if (slash) |s| blk: {
            const digits = text[s + 1 ..];
            if (digits.len == 0 or digits.len > 3) return error.InvalidCidr;
            break :blk std.fmt.parseInt(u8, digits, 10) catch return error.InvalidCidr;
        } else max;
        if (prefix_len > max) return error.InvalidCidr;
        if (is6) {
            const a = net.Ip6Address.parse(addr_text, 0) catch return error.InvalidCidr;
            return ip6(a.bytes, prefix_len);
        } else {
            const a = net.Ip4Address.parse(addr_text, 0) catch return error.InvalidCidr;
            return ip4(a.bytes, prefix_len);
        }
    }

    pub fn addrLen(c: Cidr) usize {
        return switch (c.family) {
            .ip4 => 4,
            .ip6 => 16,
        };
    }

    pub fn bytes(c: *const Cidr) []const u8 {
        return c.addr[0..c.addrLen()];
    }

    /// The prefix with host bits cleared (what a route wants).
    pub fn network(c: Cidr) Cidr {
        var out = c;
        const n = c.addrLen();
        for (0..n) |i| {
            const bit_start: usize = i * 8;
            if (bit_start >= c.prefix_len) {
                out.addr[i] = 0;
            } else if (bit_start + 8 > c.prefix_len) {
                const keep: u3 = @intCast(c.prefix_len - bit_start);
                out.addr[i] &= @as(u8, 0xff) << @intCast(@as(u4, 8) - keep);
            }
        }
        return out;
    }

    /// IPv4 netmask as 4 bytes (for ioctl-style APIs).
    pub fn netmask4(c: Cidr) [4]u8 {
        std.debug.assert(c.family == .ip4);
        const m: u32 = if (c.prefix_len == 0) 0 else ~@as(u32, 0) << @intCast(32 - @as(u6, @intCast(c.prefix_len)));
        var out: [4]u8 = undefined;
        std.mem.writeInt(u32, &out, m, .big);
        return out;
    }

    pub fn format(c: Cidr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (c.family) {
            .ip4 => try w.print("{d}.{d}.{d}.{d}", .{ c.addr[0], c.addr[1], c.addr[2], c.addr[3] }),
            .ip6 => {
                // Plain (uncompressed) groups; good enough for logs.
                for (0..8) |i| {
                    if (i != 0) try w.writeByte(':');
                    try w.print("{x}", .{std.mem.readInt(u16, c.addr[i * 2 ..][0..2], .big)});
                }
            },
        }
        try w.print("/{d}", .{c.prefix_len});
    }
};

test "parse ipv4" {
    const c = try Cidr.parse("10.0.0.1/24");
    try std.testing.expectEqual(Cidr.Family.ip4, c.family);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, c.bytes());
    try std.testing.expectEqual(@as(u8, 24), c.prefix_len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, c.network().bytes());
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 0 }, c.netmask4());
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, (try Cidr.parse("0.0.0.0/0")).netmask4());
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, (try Cidr.parse("1.2.3.4")).netmask4());
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 128, 0 }, (try Cidr.parse("10.1.200.7/17")).network().bytes());
}

test "parse ipv6" {
    const c = try Cidr.parse("fd00:1::5/64");
    try std.testing.expectEqual(Cidr.Family.ip6, c.family);
    try std.testing.expectEqual(@as(u8, 0xfd), c.addr[0]);
    try std.testing.expectEqual(@as(u8, 5), c.addr[15]);
    try std.testing.expectEqual(@as(u8, 0), c.network().addr[15]);
    try std.testing.expectEqual(@as(u8, 128), (try Cidr.parse("::1")).prefix_len);
}

test "reject bad cidrs" {
    for ([_][]const u8{ "10.0.0.1/33", "10.0.0.1/", "fd00::/129", "nope", "10.0.0/8", "1.2.3.4/x" }) |s| {
        try std.testing.expectError(error.InvalidCidr, Cidr.parse(s));
    }
}

test "format" {
    var buf: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{try Cidr.parse("10.9.8.7/16")});
    try std.testing.expectEqualStrings("10.9.8.7/16", s);
}
