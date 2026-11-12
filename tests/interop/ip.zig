//! Tiny IPv4 + UDP packet builder/parser for the interop drivers (the
//! traffic we push through tunnels and expect back).
const std = @import("std");

pub const header_len = 20 + 8;

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) sum += std.mem.readInt(u16, data[i..][0..2], .big);
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

/// IPv4/UDP datagram src:sport -> dst:dport carrying `payload`. UDP checksum
/// is computed (Windows accepts 0 too, but some stacks count it as an error).
pub fn buildUdp4(out: []u8, src: [4]u8, sport: u16, dst: [4]u8, dport: u16, payload: []const u8, id: u16) []u8 {
    const total = header_len + payload.len;
    std.debug.assert(out.len >= total and total <= 0xffff);
    const p = out[0..total];
    p[0] = 0x45; // v4, IHL 5
    p[1] = 0;
    std.mem.writeInt(u16, p[2..4], @intCast(total), .big);
    std.mem.writeInt(u16, p[4..6], id, .big);
    std.mem.writeInt(u16, p[6..8], 0x4000, .big); // DF
    p[8] = 64; // TTL
    p[9] = 17; // UDP
    @memset(p[10..12], 0);
    p[12..16].* = src;
    p[16..20].* = dst;
    std.mem.writeInt(u16, p[10..12], checksum(p[0..20]), .big);

    const u = p[20..];
    std.mem.writeInt(u16, u[0..2], sport, .big);
    std.mem.writeInt(u16, u[2..4], dport, .big);
    std.mem.writeInt(u16, u[4..6], @intCast(8 + payload.len), .big);
    @memset(u[6..8], 0);
    @memcpy(u[8..][0..payload.len], payload);

    // Pseudo-header checksum.
    var pseudo: [12 + 65535]u8 = undefined;
    pseudo[0..4].* = src;
    pseudo[4..8].* = dst;
    pseudo[8] = 0;
    pseudo[9] = 17;
    std.mem.writeInt(u16, pseudo[10..12], @intCast(8 + payload.len), .big);
    @memcpy(pseudo[12..][0..u.len], u);
    var c = checksum(pseudo[0 .. 12 + u.len]);
    if (c == 0) c = 0xffff;
    std.mem.writeInt(u16, u[6..8], c, .big);
    return p;
}

pub const Udp4 = struct {
    src: [4]u8,
    dst: [4]u8,
    sport: u16,
    dport: u16,
    payload: []const u8,
};

/// Parses an IPv4/UDP packet; trailing padding (WireGuard pads plaintext to
/// 16 bytes) is cut using the IPv4 total length.
pub fn parseUdp4(packet: []const u8) ?Udp4 {
    if (packet.len < header_len or packet[0] >> 4 != 4) return null;
    const ihl = @as(usize, packet[0] & 0x0f) * 4;
    const total = std.mem.readInt(u16, packet[2..4], .big);
    if (ihl < 20 or total > packet.len or total < ihl + 8 or packet[9] != 17) return null;
    if (checksum(packet[0..ihl]) != 0) return null;
    const u = packet[ihl..total];
    const ulen = std.mem.readInt(u16, u[4..6], .big);
    if (ulen < 8 or ulen > u.len) return null;
    return .{
        .src = packet[12..16].*,
        .dst = packet[16..20].*,
        .sport = std.mem.readInt(u16, u[0..2], .big),
        .dport = std.mem.readInt(u16, u[2..4], .big),
        .payload = u[8..ulen],
    };
}

test "build/parse round trip with padding" {
    var buf: [128]u8 = @splat(0);
    const p = buildUdp4(&buf, .{ 10, 77, 0, 2 }, 40000, .{ 10, 77, 0, 1 }, 7777, "ping", 1);
    const padded = buf[0..std.mem.alignForward(usize, p.len, 16)];
    const u = parseUdp4(padded).?;
    try std.testing.expectEqualStrings("ping", u.payload);
    try std.testing.expectEqual(@as(u16, 7777), u.dport);
    try std.testing.expectEqual([4]u8{ 10, 77, 0, 2 }, u.src);
}
