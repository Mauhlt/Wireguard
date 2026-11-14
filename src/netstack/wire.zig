//! Wire formats: the one parser / serializer per protocol (IPv4, TCP,
//! ICMPv4 echo) and the Internet checksum, shared by the stack, the tests
//! and the fuzz targets. Every parser validates every field it relies on
//! and returns an error for anything malformed: no `unreachable`, no
//! unchecked casts on packet data. Big-endian via std.mem.readInt/writeInt.
const std = @import("std");
const Addr = @import("../device/ip.zig").Addr;

pub const proto_icmp: u8 = 1;
pub const proto_tcp: u8 = 6;

pub const ip4_header_len = 20;
pub const tcp_header_len = 20;
pub const tcp_max_options_len = 40;
/// IPv4 + TCP headers without options: what MSS is relative to.
pub const tcp_ip4_overhead = ip4_header_len + tcp_header_len;
/// RFC 7323: the largest window shift.
pub const max_window_scale = 14;

/// MSS for a tunnel MTU (1420 -> 1380). The one place this is derived.
pub fn mssForMtu(mtu: u16) u16 {
    return mtu -| tcp_ip4_overhead;
}

pub const ParseError = error{
    Truncated,
    BadVersion,
    BadHeaderLength,
    BadTotalLength,
    BadChecksum,
    /// IPv4 fragment (MF set or offset != 0): dropped, we control the MTU.
    Fragment,
    BadOptions,
    BadDataOffset,
};

// ---- Internet checksum (RFC 1071) -------------------------------------

/// Incremental one's-complement sum; `add` accepts any lengths in any
/// order (an odd trailing byte is carried into the next call).
pub const Checksum = struct {
    sum: u64 = 0,
    odd: ?u8 = null,

    pub fn add(c: *Checksum, data: []const u8) void {
        var d = data;
        if (c.odd) |hi| {
            if (d.len == 0) return;
            c.sum += (@as(u64, hi) << 8) | d[0];
            c.odd = null;
            d = d[1..];
        }
        var i: usize = 0;
        while (i + 1 < d.len) : (i += 2) c.sum += std.mem.readInt(u16, d[i..][0..2], .big);
        if (i < d.len) c.odd = d[i];
    }

    pub fn addU16(c: *Checksum, v: u16) void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .big);
        c.add(&b);
    }

    /// The checksum field value (complement of the folded sum).
    pub fn final(c: Checksum) u16 {
        var s = c.sum;
        if (c.odd) |hi| s += @as(u64, hi) << 8;
        while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
        return ~@as(u16, @truncate(s));
    }
};

pub fn checksum(data: []const u8) u16 {
    var c: Checksum = .{};
    c.add(data);
    return c.final();
}

/// Sum of the TCP/UDP pseudo-header (RFC 793 / RFC 8200 8.1).
pub fn pseudoHeader(src: Addr, dst: Addr, protocol: u8, len: u32) Checksum {
    var c: Checksum = .{};
    c.add(src.bytes());
    c.add(dst.bytes());
    switch (src) {
        .v4 => {
            c.addU16(protocol);
            c.addU16(@truncate(len));
        },
        .v6 => {
            c.addU16(@truncate(len >> 16));
            c.addU16(@truncate(len));
            c.addU16(0);
            c.addU16(protocol);
        },
    }
    return c;
}

// ---- IPv4 --------------------------------------------------------------

pub const Ip4 = struct {
    tos: u8 = 0,
    id: u16 = 0,
    dont_fragment: bool = true,
    ttl: u8 = 64,
    protocol: u8,
    src: [4]u8,
    dst: [4]u8,

    pub const Parsed = struct {
        header: Ip4,
        header_len: usize,
        /// Exactly total_length - header_len bytes (trailing padding,
        /// e.g. WireGuard's 16-byte plaintext padding, is cut off).
        payload: []const u8,
    };

    /// Validates version, IHL (5..15, within the packet), total length
    /// (>= IHL, <= packet), the header checksum, and rejects fragments.
    /// IP options are skipped (not interpreted).
    pub fn parse(pkt: []const u8) ParseError!Parsed {
        if (pkt.len < ip4_header_len) return error.Truncated;
        if (pkt[0] >> 4 != 4) return error.BadVersion;
        const ihl: usize = @as(usize, pkt[0] & 0x0f) * 4;
        if (ihl < ip4_header_len or ihl > pkt.len) return error.BadHeaderLength;
        const total: usize = std.mem.readInt(u16, pkt[2..4], .big);
        if (total < ihl or total > pkt.len) return error.BadTotalLength;
        if (checksum(pkt[0..ihl]) != 0) return error.BadChecksum;
        const frag = std.mem.readInt(u16, pkt[6..8], .big);
        if (frag & 0x2000 != 0 or frag & 0x1fff != 0) return error.Fragment;
        return .{
            .header = .{
                .tos = pkt[1],
                .id = std.mem.readInt(u16, pkt[4..6], .big),
                .dont_fragment = frag & 0x4000 != 0,
                .ttl = pkt[8],
                .protocol = pkt[9],
                .src = pkt[12..16].*,
                .dst = pkt[16..20].*,
            },
            .header_len = ihl,
            .payload = pkt[ihl..total],
        };
    }

    /// Writes the 20-byte header (no options) for `payload_len` bytes of
    /// payload, checksum included.
    pub fn write(h: Ip4, out: []u8, payload_len: usize) error{ BufferTooSmall, PacketTooLarge }!void {
        if (out.len < ip4_header_len) return error.BufferTooSmall;
        const total = std.math.cast(u16, ip4_header_len + payload_len) orelse return error.PacketTooLarge;
        const p = out[0..ip4_header_len];
        p[0] = 0x45;
        p[1] = h.tos;
        std.mem.writeInt(u16, p[2..4], total, .big);
        std.mem.writeInt(u16, p[4..6], h.id, .big);
        std.mem.writeInt(u16, p[6..8], if (h.dont_fragment) 0x4000 else 0, .big);
        p[8] = h.ttl;
        p[9] = h.protocol;
        @memset(p[10..12], 0);
        p[12..16].* = h.src;
        p[16..20].* = h.dst;
        std.mem.writeInt(u16, p[10..12], checksum(p), .big);
    }
};

// ---- TCP ---------------------------------------------------------------

pub const Flags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,
};

pub const TcpOptions = struct {
    mss: ?u16 = null,
    /// Shift count as sent; parse clamps values above 14 to 14 (RFC 7323 2.3).
    window_scale: ?u8 = null,
    sack_permitted: bool = false,
    /// TSval, TSecr. Parsed (validated) but not used by the stack.
    timestamp: ?[2]u32 = null,

    /// Encoded length, padded to a multiple of 4.
    pub fn len(o: TcpOptions) usize {
        var n: usize = 0;
        if (o.mss != null) n += 4;
        if (o.window_scale != null) n += 3;
        if (o.sack_permitted) n += 2;
        if (o.timestamp != null) n += 10;
        return std.mem.alignForward(usize, n, 4);
    }

    fn write(o: TcpOptions, out: []u8) void {
        var i: usize = 0;
        if (o.mss) |m| {
            out[i] = 2;
            out[i + 1] = 4;
            std.mem.writeInt(u16, out[i + 2 ..][0..2], m, .big);
            i += 4;
        }
        if (o.window_scale) |s| {
            out[i] = 3;
            out[i + 1] = 3;
            out[i + 2] = s;
            i += 3;
        }
        if (o.sack_permitted) {
            out[i] = 4;
            out[i + 1] = 2;
            i += 2;
        }
        if (o.timestamp) |ts| {
            out[i] = 8;
            out[i + 1] = 10;
            std.mem.writeInt(u32, out[i + 2 ..][0..4], ts[0], .big);
            std.mem.writeInt(u32, out[i + 6 ..][0..4], ts[1], .big);
            i += 10;
        }
        @memset(out[i..], 1); // NOP padding (EOL would also do)
    }

    /// Strict: every option's length must match its kind and stay inside
    /// the option area; unknown kinds are skipped by their length.
    pub fn parse(area: []const u8) ParseError!TcpOptions {
        var o: TcpOptions = .{};
        var i: usize = 0;
        while (i < area.len) {
            const kind = area[i];
            if (kind == 0) break; // EOL
            if (kind == 1) {
                i += 1;
                continue;
            }
            if (i + 1 >= area.len) return error.BadOptions;
            const l: usize = area[i + 1];
            if (l < 2 or i + l > area.len) return error.BadOptions;
            const body = area[i + 2 .. i + l];
            switch (kind) {
                2 => {
                    if (l != 4) return error.BadOptions;
                    o.mss = std.mem.readInt(u16, body[0..2], .big);
                },
                3 => {
                    if (l != 3) return error.BadOptions;
                    o.window_scale = @min(body[0], max_window_scale);
                },
                4 => {
                    if (l != 2) return error.BadOptions;
                    o.sack_permitted = true;
                },
                8 => {
                    if (l != 10) return error.BadOptions;
                    o.timestamp = .{ std.mem.readInt(u32, body[0..4], .big), std.mem.readInt(u32, body[4..8], .big) };
                },
                else => {}, // SACK blocks (5) and others: ignored
            }
            i += l;
        }
        return o;
    }
};

pub const Tcp = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32 = 0,
    flags: Flags,
    window: u16,
    urgent: u16 = 0,
    options: TcpOptions = .{},
    payload: []const u8 = &.{},

    /// Sequence space the segment occupies (payload + SYN + FIN).
    pub fn segLen(t: Tcp) u32 {
        return @as(u32, @intCast(t.payload.len)) + @intFromBool(t.flags.syn) + @intFromBool(t.flags.fin);
    }

    pub fn headerLen(t: Tcp) usize {
        return tcp_header_len + t.options.len();
    }

    /// Parses a TCP segment (the IP payload) and verifies its checksum
    /// against the pseudo-header for `src` -> `dst`.
    pub fn parse(src: Addr, dst: Addr, bytes: []const u8) ParseError!Tcp {
        if (bytes.len < tcp_header_len) return error.Truncated;
        const off: usize = @as(usize, bytes[12] >> 4) * 4;
        if (off < tcp_header_len or off > bytes.len) return error.BadDataOffset;
        const len32 = std.math.cast(u32, bytes.len) orelse return error.BadTotalLength;
        var c = pseudoHeader(src, dst, proto_tcp, len32);
        c.add(bytes);
        if (c.final() != 0) return error.BadChecksum;
        return .{
            .src_port = std.mem.readInt(u16, bytes[0..2], .big),
            .dst_port = std.mem.readInt(u16, bytes[2..4], .big),
            .seq = std.mem.readInt(u32, bytes[4..8], .big),
            .ack = std.mem.readInt(u32, bytes[8..12], .big),
            .flags = @bitCast(bytes[13]),
            .window = std.mem.readInt(u16, bytes[14..16], .big),
            .urgent = std.mem.readInt(u16, bytes[18..20], .big),
            .options = try TcpOptions.parse(bytes[tcp_header_len..off]),
            .payload = bytes[off..],
        };
    }

    /// Serializes header + options + payload into `out`, checksum included.
    /// Returns the segment length.
    pub fn write(t: Tcp, src: Addr, dst: Addr, out: []u8) error{ BufferTooSmall, PacketTooLarge }!usize {
        const hl = t.headerLen();
        if (hl > tcp_header_len + tcp_max_options_len) return error.PacketTooLarge;
        const total = hl + t.payload.len;
        if (out.len < total) return error.BufferTooSmall;
        const len32 = std.math.cast(u32, total) orelse return error.PacketTooLarge;
        const p = out[0..total];
        std.mem.writeInt(u16, p[0..2], t.src_port, .big);
        std.mem.writeInt(u16, p[2..4], t.dst_port, .big);
        std.mem.writeInt(u32, p[4..8], t.seq, .big);
        std.mem.writeInt(u32, p[8..12], t.ack, .big);
        p[12] = @as(u8, @intCast(hl / 4)) << 4;
        p[13] = @bitCast(t.flags);
        std.mem.writeInt(u16, p[14..16], t.window, .big);
        @memset(p[16..18], 0);
        std.mem.writeInt(u16, p[18..20], t.urgent, .big);
        t.options.write(p[tcp_header_len..hl]);
        // payload may already be in place (zero-copy build): copy only if not.
        if (t.payload.len != 0 and t.payload.ptr != p[hl..].ptr) @memmove(p[hl..total], t.payload);
        var c = pseudoHeader(src, dst, proto_tcp, len32);
        c.add(p);
        std.mem.writeInt(u16, p[16..18], c.final(), .big);
        return total;
    }
};

// ---- ICMPv4 echo -------------------------------------------------------

pub const icmp_echo_request: u8 = 8;
pub const icmp_echo_reply: u8 = 0;

/// Validates an ICMPv4 message (length >= 8, checksum) and returns its type.
pub fn icmp4Type(bytes: []const u8) ParseError!u8 {
    if (bytes.len < 8) return error.Truncated;
    if (checksum(bytes) != 0) return error.BadChecksum;
    return bytes[0];
}

// ---- whole packets -----------------------------------------------------

/// A complete IPv4/TCP packet into `out`; returns it.
pub fn buildTcp4(out: []u8, ip: Ip4, seg: Tcp) error{ BufferTooSmall, PacketTooLarge }![]u8 {
    if (out.len < ip4_header_len) return error.BufferTooSmall;
    var h = ip;
    h.protocol = proto_tcp;
    const n = try seg.write(.{ .v4 = h.src }, .{ .v4 = h.dst }, out[ip4_header_len..]);
    try h.write(out, n);
    return out[0 .. ip4_header_len + n];
}

/// A parsed IPv4/TCP packet (any validation failure is an error).
pub const Tcp4Packet = struct { ip: Ip4.Parsed, tcp: Tcp };

pub fn parseTcp4(pkt: []const u8) (ParseError || error{NotTcp})!Tcp4Packet {
    const p = try Ip4.parse(pkt);
    if (p.header.protocol != proto_tcp) return error.NotTcp;
    return .{ .ip = p, .tcp = try Tcp.parse(.{ .v4 = p.header.src }, .{ .v4 = p.header.dst }, p.payload) };
}

// ---- tests -------------------------------------------------------------

test "checksum: RFC 1071 example, odd lengths, incremental == one shot" {
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(@as(u16, ~@as(u16, 0xddf2)), checksum(&data));
    var c: Checksum = .{};
    c.add(data[0..3]);
    c.add(data[3..4]);
    c.add(data[4..]);
    try std.testing.expectEqual(checksum(&data), c.final());
    const odd = [_]u8{ 1, 2, 3 };
    try std.testing.expectEqual(~@as(u16, 0x0102 + 0x0300), checksum(&odd));
}

test "tcp4 build -> parse round trip, options, padding cut" {
    var buf: [256]u8 = @splat(0);
    const seg: Tcp = .{
        .src_port = 40000,
        .dst_port = 8420,
        .seq = 0xfffffff0,
        .ack = 7,
        .flags = .{ .syn = true, .ack = true },
        .window = 65535,
        .options = .{ .mss = 1380, .window_scale = 7, .sack_permitted = true, .timestamp = .{ 1, 2 } },
        .payload = "hello",
    };
    const pkt = try buildTcp4(&buf, .{ .protocol = proto_tcp, .src = .{ 10, 8, 0, 2 }, .dst = .{ 10, 8, 0, 1 }, .id = 9 }, seg);
    const padded = buf[0..std.mem.alignForward(usize, pkt.len, 16)];
    const p = try parseTcp4(padded);
    try std.testing.expectEqualStrings("hello", p.tcp.payload);
    try std.testing.expectEqual(@as(?u16, 1380), p.tcp.options.mss);
    try std.testing.expectEqual(@as(?u8, 7), p.tcp.options.window_scale);
    try std.testing.expect(p.tcp.options.sack_permitted);
    try std.testing.expectEqual(@as(u32, 0xfffffff0), p.tcp.seq);
    try std.testing.expectEqual(@as(u32, 6), p.tcp.segLen()); // 5 + SYN
    try std.testing.expectEqual(@as(u16, 9), p.ip.header.id);
}

test "parse rejects malformed packets" {
    var buf: [128]u8 = @splat(0);
    const pkt = try buildTcp4(&buf, .{ .protocol = proto_tcp, .src = .{ 10, 8, 0, 2 }, .dst = .{ 10, 8, 0, 1 } }, .{ .src_port = 1, .dst_port = 2, .seq = 3, .flags = .{ .syn = true }, .window = 1, .options = .{ .mss = 1000 } });
    var bad: [128]u8 = undefined;

    @memcpy(bad[0..pkt.len], pkt);
    bad[0] = 0x44; // IHL 4
    try std.testing.expectError(error.BadHeaderLength, parseTcp4(bad[0..pkt.len]));
    @memcpy(bad[0..pkt.len], pkt);
    bad[0] = 0x65;
    try std.testing.expectError(error.BadVersion, parseTcp4(bad[0..pkt.len]));
    try std.testing.expectError(error.BadTotalLength, parseTcp4(pkt[0 .. pkt.len - 1]));
    try std.testing.expectError(error.Truncated, parseTcp4(pkt[0..19]));
    @memcpy(bad[0..pkt.len], pkt);
    bad[8] ^= 1; // TTL: header checksum
    try std.testing.expectError(error.BadChecksum, parseTcp4(bad[0..pkt.len]));
    @memcpy(bad[0..pkt.len], pkt);
    bad[pkt.len - 1] ^= 1; // TCP checksum
    try std.testing.expectError(error.BadChecksum, parseTcp4(bad[0..pkt.len]));
    // Fragment: MF set (and fix the header checksum so that is what fails).
    @memcpy(bad[0..pkt.len], pkt);
    bad[6] |= 0x20;
    @memset(bad[10..12], 0);
    std.mem.writeInt(u16, bad[10..12], checksum(bad[0..20]), .big);
    try std.testing.expectError(error.Fragment, parseTcp4(bad[0..pkt.len]));
    // Data offset beyond the segment.
    var hdr: [20]u8 = @splat(0);
    hdr[12] = 0xf0;
    try std.testing.expectError(error.BadDataOffset, Tcp.parse(.{ .v4 = .{ 0, 0, 0, 0 } }, .{ .v4 = .{ 0, 0, 0, 0 } }, &hdr));
    // Options: truncated MSS, zero length, wrong lengths.
    try std.testing.expectError(error.BadOptions, TcpOptions.parse(&.{ 2, 4, 0 }));
    try std.testing.expectError(error.BadOptions, TcpOptions.parse(&.{ 9, 0 }));
    try std.testing.expectError(error.BadOptions, TcpOptions.parse(&.{ 2, 3, 0 }));
    try std.testing.expectError(error.BadOptions, TcpOptions.parse(&.{3}));
    const ws = try TcpOptions.parse(&.{ 1, 3, 3, 200, 0, 99 });
    try std.testing.expectEqual(@as(?u8, 14), ws.window_scale);
}

test "mss for the tunnel mtu" {
    try std.testing.expectEqual(@as(u16, 1380), mssForMtu(1420));
    try std.testing.expectEqual(@as(u16, 0), mssForMtu(10));
}