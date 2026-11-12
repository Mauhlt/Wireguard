//! IP addresses and prefixes as the device uses them: raw network-order
//! bytes (4 for IPv4, 16 for IPv6), parsing and printing the forms .conf
//! files use ("10.8.0.1/24", "fd00::1/64", "10.8.0.2" = /32).

const std = @import("std");
const net = std.Io.net;

pub const Family = enum { v4, v6 };

pub const Addr = union(Family) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn bytes(a: *const Addr) []const u8 {
        return switch (a.*) {
            .v4 => |*b| b,
            .v6 => |*b| b,
        };
    }

    pub fn bits(a: Addr) u8 {
        return switch (a) {
            .v4 => 32,
            .v6 => 128,
        };
    }

    pub fn eql(a: Addr, b: Addr) bool {
        return switch (a) {
            .v4 => |x| b == .v4 and std.mem.eql(u8, &x, &b.v4),
            .v6 => |x| b == .v6 and std.mem.eql(u8, &x, &b.v6),
        };
    }

    /// Parses a bare address (no port, no brackets, no scope).
    pub fn parse(text: []const u8) error{InvalidAddress}!Addr {
        if (net.Ip4Address.parse(text, 0)) |a| return .{ .v4 = a.bytes } else |_| {}
        if (std.mem.findScalar(u8, text, ':') == null) return error.InvalidAddress;
        const a = net.Ip6Address.parse(text, 0) catch return error.InvalidAddress;
        return .{ .v6 = a.bytes };
    }

    pub fn format(a: Addr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (a) {
            .v4 => |b| try w.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }),
            .v6 => |b| {
                const u: net.Ip6Address.Unresolved = .{ .bytes = b, .interface_name = null };
                try w.print("{f}", .{u});
            },
        }
    }

    pub fn fromIpAddress(a: net.IpAddress) Addr {
        return switch (a) {
            .ip4 => |x| .{ .v4 = x.bytes },
            .ip6 => |x| .{ .v6 = x.bytes },
        };
    }
};

pub const Cidr = struct {
    addr: Addr,
    prefix: u8,

    pub const ParseError = error{ InvalidAddress, InvalidPrefix };

    /// "a.b.c.d/n", "x::y/n", or a bare address meaning a host route
    /// (/32 or /128), as wg-quick and WireGuard for Windows accept.
    pub fn parse(text: []const u8) ParseError!Cidr {
        const slash = std.mem.findScalar(u8, text, '/');
        const addr = try Addr.parse(if (slash) |s| text[0..s] else text);
        const max = addr.bits();
        const prefix: u8 = if (slash) |s| p: {
            const t = text[s + 1 ..];
            if (t.len == 0 or t.len > 3) return error.InvalidPrefix;
            for (t) |c| if (c < '0' or c > '9') return error.InvalidPrefix;
            const n = std.fmt.parseInt(u8, t, 10) catch return error.InvalidPrefix;
            break :p n;
        } else max;
        if (prefix > max) return error.InvalidPrefix;
        return .{ .addr = addr, .prefix = prefix };
    }

    /// The prefix with host bits cleared (what routing uses).
    pub fn masked(c: Cidr) Cidr {
        var out = c;
        switch (out.addr) {
            .v4 => |*b| maskBytes(b, c.prefix),
            .v6 => |*b| maskBytes(b, c.prefix),
        }
        return out;
    }

    pub fn hasHostBits(c: Cidr) bool {
        return !c.masked().addr.eql(c.addr);
    }

    pub fn contains(c: Cidr, a: Addr) bool {
        if (std.meta.activeTag(c.addr) != std.meta.activeTag(a)) return false;
        return commonPrefix(c.addr.bytes(), a.bytes(), c.prefix) >= c.prefix;
    }

    pub fn eql(a: Cidr, b: Cidr) bool {
        return a.prefix == b.prefix and a.addr.eql(b.addr);
    }

    pub fn format(c: Cidr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}/{d}", .{ c.addr, c.prefix });
    }
};

pub fn maskBytes(b: []u8, prefix: u8) void {
    for (b, 0..) |*byte, i| {
        const start: usize = i * 8;
        if (start >= prefix) {
            byte.* = 0;
        } else if (start + 8 > prefix) {
            const keep: u3 = @intCast(prefix - start);
            byte.* &= ~(@as(u8, 0xff) >> keep);
        }
    }
}

/// Number of leading bits `a` and `b` share, capped at `limit`.
pub fn commonPrefix(a: []const u8, b: []const u8, limit: u8) u8 {
    var n: usize = 0;
    for (a, b) |x, y| {
        const d = x ^ y;
        if (d != 0) {
            n += @clz(d);
            break;
        }
        n += 8;
    }
    return @intCast(@min(n, limit));
}

/// Bit `i` (0 = most significant bit of byte 0).
pub fn bitAt(b: []const u8, i: u8) u1 {
    return @truncate(b[i / 8] >> @intCast(7 - (i % 8)));
}

/// Source and destination of an IP packet, or null if it is not a
/// well-formed IPv4/IPv6 header (or too short to tell).
pub const PacketAddrs = struct { src: Addr, dst: Addr, total_len: usize };

pub fn packetAddrs(pkt: []const u8) ?PacketAddrs {
    if (pkt.len < 1) return null;
    switch (pkt[0] >> 4) {
        4 => {
            if (pkt.len < 20) return null;
            const total = std.mem.readInt(u16, pkt[2..4], .big);
            return .{ .src = .{ .v4 = pkt[12..16].* }, .dst = .{ .v4 = pkt[16..20].* }, .total_len = total };
        },
        6 => {
            if (pkt.len < 40) return null;
            const payload = std.mem.readInt(u16, pkt[4..6], .big);
            return .{ .src = .{ .v6 = pkt[8..24].* }, .dst = .{ .v6 = pkt[24..40].* }, .total_len = @as(usize, payload) + 40 };
        },
        else => return null,
    }
}

test "parse and format" {
    var buf: [64]u8 = undefined;
    const c = try Cidr.parse("10.8.0.1/24");
    try std.testing.expectEqualStrings("10.8.0.1/24", try std.fmt.bufPrint(&buf, "{f}", .{c}));
    try std.testing.expectEqualStrings("10.8.0.0/24", try std.fmt.bufPrint(&buf, "{f}", .{c.masked()}));
    try std.testing.expect(c.hasHostBits());
    const h = try Cidr.parse("10.8.0.2");
    try std.testing.expectEqual(@as(u8, 32), h.prefix);
    const v6 = try Cidr.parse("fd00:0:0::1/64");
    try std.testing.expectEqualStrings("fd00::1/64", try std.fmt.bufPrint(&buf, "{f}", .{v6}));
    try std.testing.expectEqualStrings("::/0", try std.fmt.bufPrint(&buf, "{f}", .{try Cidr.parse("::/0")}));
    try std.testing.expectError(error.InvalidPrefix, Cidr.parse("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidPrefix, Cidr.parse("10.0.0.0/"));
    try std.testing.expectError(error.InvalidPrefix, Cidr.parse("10.0.0.0/+1"));
    try std.testing.expectError(error.InvalidPrefix, Cidr.parse("::/129"));
    try std.testing.expectError(error.InvalidAddress, Cidr.parse("10.0.0/8"));
    try std.testing.expectError(error.InvalidAddress, Cidr.parse("10.0.0.256/8"));
    try std.testing.expectError(error.InvalidAddress, Cidr.parse("example.com/8"));
    try std.testing.expect((try Cidr.parse("10.8.0.0/24")).contains(try Addr.parse("10.8.0.77")));
    try std.testing.expect(!(try Cidr.parse("10.8.0.0/24")).contains(try Addr.parse("10.8.1.1")));
    try std.testing.expect((try Cidr.parse("0.0.0.0/0")).contains(try Addr.parse("1.2.3.4")));
    try std.testing.expect(!(try Cidr.parse("0.0.0.0/0")).contains(try Addr.parse("::1")));
}

test "packet addresses" {
    var p4: [20]u8 = @splat(0);
    p4[0] = 0x45;
    std.mem.writeInt(u16, p4[2..4], 20, .big);
    p4[12..16].* = .{ 10, 8, 0, 2 };
    p4[16..20].* = .{ 10, 8, 0, 1 };
    const a = packetAddrs(&p4).?;
    try std.testing.expect(a.src.eql(.{ .v4 = .{ 10, 8, 0, 2 } }));
    try std.testing.expect(a.dst.eql(.{ .v4 = .{ 10, 8, 0, 1 } }));
    try std.testing.expectEqual(@as(?PacketAddrs, null), packetAddrs(p4[0..19]));
    var p6: [40]u8 = @splat(0);
    p6[0] = 0x60;
    p6[39] = 1;
    try std.testing.expect(packetAddrs(&p6).?.dst.eql(try Addr.parse("::1")));
    try std.testing.expectEqual(@as(usize, 40), packetAddrs(&p6).?.total_len);
}
