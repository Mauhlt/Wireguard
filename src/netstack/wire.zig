//! Wire formats: the one parser / serializer per protocol (IPv4, IPv6 with
//! a bounded extension-header walk, TCP with SACK, ICMPv4 / ICMPv6 echo)
//! and the Internet checksum, shared by the stack, the tests
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
pub const proto_icmp6: u8 = 58;
pub const ip6_header_len = 40;
/// IPv4 + TCP headers without options: what MSS is relative to.
pub const tcp_ip4_overhead = ip4_header_len + tcp_header_len;
pub const tcp_ip6_overhead = ip6_header_len + tcp_header_len;
/// RFC 7323: the largest window shift.
pub const max_window_scale = 14;
/// SACK blocks per segment: 4 fill the 40-byte option space (2 NOP + 2 +
/// 4 * 8 = 36; with timestamps it would be 3, but we send none). The
/// window-scale option only ever appears on SYNs, which carry no SACK.
pub const max_sack_blocks = 4;
/// IPv6 extension headers walked at most, and their total bytes.
pub const max_ext_headers = 4;
pub const max_ext_bytes = 256;

/// MSS for a tunnel MTU over IPv4 (1420 -> 1380).
pub fn mssForMtu(mtu: u16) u16 {
    return mtu -| tcp_ip4_overhead;
}

/// MSS for a tunnel MTU over IPv6 (1420 -> 1360).
pub fn mssForMtu6(mtu: u16) u16 {
    return mtu -| tcp_ip6_overhead;
}

/// MSS for connections of `a`'s family: the one place this is derived.
pub fn mssFor(a: Addr, mtu: u16) u16 {
    return switch (a) {
        .v4 => mssForMtu(mtu),
        .v6 => mssForMtu6(mtu),
    };
}

pub fn ipHeaderLen(a: Addr) usize {
    return switch (a) {
        .v4 => ip4_header_len,
        .v6 => ip6_header_len,
    };
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

/// IPv6 adds one reason: an extension header we do not accept (routing,
/// AH / ESP, a non-padding option, a chain too long, ...).
pub const Ip6Error = ParseError || error{BadExtensionHeader};

pub const BuildError = error{ BufferTooSmall, PacketTooLarge, AddressFamilyMismatch };

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

// ---- IPv6 --------------------------------------------------------------

pub const Ip6 = struct {
    traffic_class: u8 = 0,
    flow_label: u20 = 0,
    /// On parse: the upper-layer protocol after the extension headers.
    next_header: u8,
    hop_limit: u8 = 64,
    src: [16]u8,
    dst: [16]u8,

    pub const Parsed = struct {
        header: Ip6,
        /// 40 + extension headers.
        header_len: usize,
        /// Exactly what the payload length covers, minus extension headers.
        payload: []const u8,
    };

    /// Validates version and payload length, then walks at most
    /// `max_ext_headers` extension headers within `max_ext_bytes`:
    /// hop-by-hop (first only) and destination options are skipped when
    /// they hold nothing but padding; a fragment header is error.Fragment;
    /// routing, AH, ESP, "no next header" and everything unexpected are
    /// error.BadExtensionHeader. A jumbogram (payload length 0 with a
    /// hop-by-hop jumbo option) is rejected by the padding-only rule.
    pub fn parse(pkt: []const u8) Ip6Error!Parsed {
        if (pkt.len < ip6_header_len) return error.Truncated;
        if (pkt[0] >> 4 != 6) return error.BadVersion;
        const plen: usize = std.mem.readInt(u16, pkt[4..6], .big);
        const end = ip6_header_len + plen;
        if (end > pkt.len) return error.BadTotalLength;
        var nh = pkt[6];
        var off: usize = ip6_header_len;
        var count: usize = 0;
        while (true) {
            switch (nh) {
                ext_hop_by_hop, ext_dest_opts => {
                    if (nh == ext_hop_by_hop and off != ip6_header_len) return error.BadExtensionHeader;
                    count += 1;
                    if (count > max_ext_headers) return error.BadExtensionHeader;
                    if (off + 2 > end) return error.Truncated;
                    const hl = (@as(usize, pkt[off + 1]) + 1) * 8;
                    if (off + hl > end) return error.Truncated;
                    if (off + hl - ip6_header_len > max_ext_bytes) return error.BadExtensionHeader;
                    try paddingOnly(pkt[off + 2 .. off + hl]);
                    nh = pkt[off];
                    off += hl;
                },
                ext_fragment => return error.Fragment,
                ext_routing, ext_esp, ext_ah, ext_none, ext_mobility, ext_hip, ext_shim6, 253, 254 => return error.BadExtensionHeader,
                else => break,
            }
        }
        const b0: u32 = std.mem.readInt(u32, pkt[0..4], .big);
        return .{
            .header = .{
                .traffic_class = @truncate(b0 >> 20),
                .flow_label = @truncate(b0),
                .next_header = nh,
                .hop_limit = pkt[7],
                .src = pkt[8..24].*,
                .dst = pkt[24..40].*,
            },
            .header_len = off,
            .payload = pkt[off..end],
        };
    }

    /// Only Pad1 / PadN options (each PadN within the area).
    fn paddingOnly(area: []const u8) Ip6Error!void {
        var i: usize = 0;
        while (i < area.len) {
            switch (area[i]) {
                0 => i += 1,
                1 => {
                    if (i + 1 >= area.len) return error.BadExtensionHeader;
                    i += 2 + @as(usize, area[i + 1]);
                    if (i > area.len) return error.BadExtensionHeader;
                },
                else => return error.BadExtensionHeader,
            }
        }
    }

    /// Writes the 40-byte header (no extension headers) for `payload_len`
    /// bytes of payload.
    pub fn write(h: Ip6, out: []u8, payload_len: usize) error{ BufferTooSmall, PacketTooLarge }!void {
        if (out.len < ip6_header_len) return error.BufferTooSmall;
        const plen = std.math.cast(u16, payload_len) orelse return error.PacketTooLarge;
        const p = out[0..ip6_header_len];
        std.mem.writeInt(u32, p[0..4], (@as(u32, 6) << 28) | (@as(u32, h.traffic_class) << 20) | h.flow_label, .big);
        std.mem.writeInt(u16, p[4..6], plen, .big);
        p[6] = h.next_header;
        p[7] = h.hop_limit;
        p[8..24].* = h.src;
        p[24..40].* = h.dst;
    }
};

const ext_hop_by_hop: u8 = 0;
const ext_routing: u8 = 43;
const ext_fragment: u8 = 44;
const ext_esp: u8 = 50;
const ext_ah: u8 = 51;
const ext_none: u8 = 59;
const ext_dest_opts: u8 = 60;
const ext_mobility: u8 = 135;
const ext_hip: u8 = 139;
const ext_shim6: u8 = 140;

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

pub const SackBlock = struct { start: u32, end: u32 };

/// Up to `max_sack_blocks` SACK blocks (RFC 2018), as received or to send.
/// Parsing checks only the encoding; the stack validates block contents.
pub const Sack = struct {
    blocks: [max_sack_blocks]SackBlock = undefined,
    len: u8 = 0,

    pub fn slice(s: *const Sack) []const SackBlock {
        return s.blocks[0..@min(s.len, max_sack_blocks)];
    }
};

pub const TcpOptions = struct {
    mss: ?u16 = null,
    /// Shift count as sent; parse clamps values above 14 to 14 (RFC 7323 2.3).
    window_scale: ?u8 = null,
    sack_permitted: bool = false,
    /// TSval, TSecr. Parsed (validated) but not used by the stack.
    timestamp: ?[2]u32 = null,
    /// SACK blocks (kind 5). A malformed SACK option is ignored (null),
    /// not trusted and not fatal.
    sack: ?Sack = null,

    /// Encoded length, padded to a multiple of 4.
    pub fn len(o: TcpOptions) usize {
        var n: usize = 0;
        if (o.mss != null) n += 4;
        if (o.window_scale != null) n += 3;
        if (o.sack_permitted) n += 2;
        if (o.timestamp != null) n += 10;
        if (o.sack) |s| if (s.slice().len > 0) {
            n += 4 + 8 * s.slice().len; // NOP NOP kind len blocks
        };
        return std.mem.alignForward(usize, n, 4);
    }

    fn write(o: TcpOptions, out: []u8) void {
        var i: usize = 0;
        if (o.sack) |s| if (s.slice().len > 0) {
            const blocks = s.slice();
            out[i] = 1;
            out[i + 1] = 1;
            out[i + 2] = 5;
            out[i + 3] = @intCast(2 + 8 * blocks.len);
            i += 4;
            for (blocks) |b| {
                std.mem.writeInt(u32, out[i..][0..4], b.start, .big);
                std.mem.writeInt(u32, out[i + 4 ..][0..4], b.end, .big);
                i += 8;
            }
        };
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
                5 => {
                    // 1..4 blocks of 8 bytes; anything else is ignored.
                    const nb = body.len / 8;
                    if (body.len % 8 == 0 and nb >= 1 and nb <= max_sack_blocks) {
                        var s: Sack = .{ .len = @intCast(nb) };
                        for (0..nb) |k| s.blocks[k] = .{
                            .start = std.mem.readInt(u32, body[8 * k ..][0..4], .big),
                            .end = std.mem.readInt(u32, body[8 * k + 4 ..][0..4], .big),
                        };
                        o.sack = s;
                    }
                },
                else => {}, // others: skipped by length
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
        // Saturating: parsed payloads are < 64 KiB, but a hand-built Tcp may be anything.
        const n = std.math.cast(u32, t.payload.len) orelse std.math.maxInt(u32);
        return n +| @intFromBool(t.flags.syn) +| @intFromBool(t.flags.fin);
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

// ---- ICMPv6 echo -------------------------------------------------------

pub const icmp6_echo_request: u8 = 128;
pub const icmp6_echo_reply: u8 = 129;

/// Validates an ICMPv6 message (length >= 8, checksum over the IPv6
/// pseudo-header) and returns its type.
pub fn icmp6Type(src: Addr, dst: Addr, bytes: []const u8) ParseError!u8 {
    if (bytes.len < 8) return error.Truncated;
    const n = std.math.cast(u32, bytes.len) orelse return error.BadTotalLength;
    var c = pseudoHeader(src, dst, proto_icmp6, n);
    c.add(bytes);
    if (c.final() != 0) return error.BadChecksum;
    return bytes[0];
}

/// The ICMPv6 checksum field value for `msg` (its checksum bytes zero).
pub fn icmp6Checksum(src: Addr, dst: Addr, msg: []const u8) u16 {
    var c = pseudoHeader(src, dst, proto_icmp6, @intCast(msg.len));
    c.add(msg);
    return c.final();
}

// ---- either family -----------------------------------------------------

/// An IP packet of either family, validated (see Ip4.parse / Ip6.parse).
pub const IpPacket = struct {
    src: Addr,
    dst: Addr,
    /// Upper-layer protocol (after any IPv6 extension headers).
    protocol: u8,
    payload: []const u8,
};

pub fn parseIp(pkt: []const u8) Ip6Error!IpPacket {
    if (pkt.len < 1) return error.Truncated;
    switch (pkt[0] >> 4) {
        4 => {
            const p = try Ip4.parse(pkt);
            return .{ .src = .{ .v4 = p.header.src }, .dst = .{ .v4 = p.header.dst }, .protocol = p.header.protocol, .payload = p.payload };
        },
        6 => {
            const p = try Ip6.parse(pkt);
            return .{ .src = .{ .v6 = p.header.src }, .dst = .{ .v6 = p.header.dst }, .protocol = p.header.next_header, .payload = p.payload };
        },
        else => return error.BadVersion,
    }
}

/// Writes an IP header (no options / extension headers) for `src` ->
/// `dst`; returns its length. `id` is used by IPv4 only.
pub fn writeIpHeader(out: []u8, src: Addr, dst: Addr, protocol: u8, id: u16, payload_len: usize) BuildError!usize {
    switch (src) {
        .v4 => |s4| {
            if (dst != .v4) return error.AddressFamilyMismatch;
            try (Ip4{ .protocol = protocol, .id = id, .src = s4, .dst = dst.v4 }).write(out, payload_len);
            return ip4_header_len;
        },
        .v6 => |s6| {
            if (dst != .v6) return error.AddressFamilyMismatch;
            try (Ip6{ .next_header = protocol, .src = s6, .dst = dst.v6 }).write(out, payload_len);
            return ip6_header_len;
        },
    }
}

/// A complete IPv4 or IPv6 TCP packet `src` -> `dst` into `out`.
pub fn buildTcp(out: []u8, src: Addr, dst: Addr, id: u16, seg: Tcp) BuildError![]u8 {
    const hl = ipHeaderLen(src);
    if (out.len < hl) return error.BufferTooSmall;
    const n = try seg.write(src, dst, out[hl..]);
    _ = try writeIpHeader(out, src, dst, proto_tcp, id, n);
    return out[0 .. hl + n];
}

pub const TcpPacket = struct { ip: IpPacket, tcp: Tcp };

/// Parses a TCP packet of either family (any validation failure is an error).
pub fn parseTcp(pkt: []const u8) (Ip6Error || error{NotTcp})!TcpPacket {
    const p = try parseIp(pkt);
    if (p.protocol != proto_tcp) return error.NotTcp;
    return .{ .ip = p, .tcp = try Tcp.parse(p.src, p.dst, p.payload) };
}

// ---- whole IPv4 packets -------------------------------------------------

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
/// The IPv6 pseudo-header written out byte by byte as RFC 8200 8.1 lays
/// it out (an independent second implementation of `pseudoHeader`).
fn referenceSum6(src: [16]u8, dst: [16]u8, protocol: u8, upper: []const u8) u16 {
    var buf: [40 + 1600]u8 = undefined;
    @memcpy(buf[0..16], &src);
    @memcpy(buf[16..32], &dst);
    std.mem.writeInt(u32, buf[32..36], @intCast(upper.len), .big);
    buf[36] = 0;
    buf[37] = 0;
    buf[38] = 0;
    buf[39] = protocol;
    @memcpy(buf[40..][0..upper.len], upper);
    return checksum(buf[0 .. 40 + upper.len]);
}

const ula_a = [16]u8{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
const ula_b = [16]u8{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

test "ipv6 tcp: build -> parse, checksum agrees with the RFC 8200 layout, MSS 1360" {
    var buf: [256]u8 = @splat(0);
    const seg: Tcp = .{
        .src_port = 40000,
        .dst_port = 8420,
        .seq = 1,
        .ack = 2,
        .flags = .{ .ack = true, .psh = true },
        .window = 512,
        .payload = "hello, v6 (odd)",
    };
    const pkt = try buildTcp(&buf, .{ .v6 = ula_a }, .{ .v6 = ula_b }, 0, seg);
    try std.testing.expectEqual(@as(usize, 40 + 20 + 15), pkt.len);
    const p = try parseTcp(pkt);
    try std.testing.expectEqualStrings("hello, v6 (odd)", p.tcp.payload);
    try std.testing.expect(p.ip.src.eql(.{ .v6 = ula_a }));
    // The checksum field makes the reference sum come out zero.
    try std.testing.expectEqual(@as(u16, 0), referenceSum6(ula_a, ula_b, proto_tcp, pkt[40..]));
    // Corrupting any byte of the pseudo-header inputs is caught.
    try std.testing.expectError(error.BadChecksum, Tcp.parse(.{ .v6 = ula_b }, .{ .v6 = ula_b }, pkt[40..]));
    try std.testing.expectEqual(@as(u16, 1360), mssForMtu6(1420));
    try std.testing.expectEqual(@as(u16, 1360), mssFor(.{ .v6 = ula_a }, 1420));
    try std.testing.expectEqual(@as(u16, 1380), mssFor(.{ .v4 = .{ 10, 8, 0, 1 } }, 1420));
    try std.testing.expectError(error.AddressFamilyMismatch, buildTcp(&buf, .{ .v6 = ula_a }, .{ .v4 = .{ 1, 2, 3, 4 } }, 0, seg));
}

test "ipv6 header fields round trip" {
    var buf: [64]u8 = @splat(0);
    try (Ip6{ .traffic_class = 0xab, .flow_label = 0xcdef1, .next_header = 99, .hop_limit = 7, .src = ula_a, .dst = ula_b }).write(&buf, 4);
    const p = try Ip6.parse(buf[0..44]);
    try std.testing.expectEqual(@as(u8, 0xab), p.header.traffic_class);
    try std.testing.expectEqual(@as(u20, 0xcdef1), p.header.flow_label);
    try std.testing.expectEqual(@as(u8, 99), p.header.next_header);
    try std.testing.expectEqual(@as(u8, 7), p.header.hop_limit);
    try std.testing.expectEqual(@as(usize, 4), p.payload.len);
}

test "ipv6 extension headers: padding-only skipped, everything else dropped" {
    var buf: [256]u8 = @splat(0);
    const tcp_len = 20;
    // hop-by-hop (8 bytes: PadN 4) -> dest options (8 bytes: Pad1 x6) -> TCP
    try (Ip6{ .next_header = 0, .src = ula_a, .dst = ula_b }).write(&buf, 16 + tcp_len);
    buf[40] = 60; // next: dest opts
    buf[41] = 0; // 8 bytes
    buf[42] = 1; // PadN
    buf[43] = 4;
    buf[48] = proto_tcp;
    buf[49] = 0;
    const seg = try (Tcp{ .src_port = 1, .dst_port = 2, .seq = 3, .flags = .{ .syn = true }, .window = 1 }).write(.{ .v6 = ula_a }, .{ .v6 = ula_b }, buf[56..]);
    try std.testing.expectEqual(@as(usize, tcp_len), seg);
    const ok = try parseTcp(buf[0 .. 56 + tcp_len]);
    try std.testing.expectEqual(@as(u16, 2), ok.tcp.dst_port);

    var bad: [256]u8 = undefined;
    // A real (non-padding) option in hop-by-hop: router alert.
    @memcpy(&bad, &buf);
    bad[42] = 5;
    bad[43] = 2;
    try std.testing.expectError(error.BadExtensionHeader, Ip6.parse(bad[0 .. 56 + tcp_len]));
    // PadN running past the header.
    @memcpy(&bad, &buf);
    bad[43] = 9;
    try std.testing.expectError(error.BadExtensionHeader, Ip6.parse(bad[0 .. 56 + tcp_len]));
    // Hop-by-hop that is not first.
    @memcpy(&bad, &buf);
    bad[40] = 0;
    try std.testing.expectError(error.BadExtensionHeader, Ip6.parse(bad[0 .. 56 + tcp_len]));
    // Fragment, routing, ESP, no-next-header.
    for ([_]struct { nh: u8, e: Ip6Error }{
        .{ .nh = 44, .e = error.Fragment },
        .{ .nh = 43, .e = error.BadExtensionHeader },
        .{ .nh = 50, .e = error.BadExtensionHeader },
        .{ .nh = 59, .e = error.BadExtensionHeader },
    }) |case| {
        @memcpy(&bad, &buf);
        bad[6] = case.nh;
        try std.testing.expectError(case.e, Ip6.parse(bad[0 .. 56 + tcp_len]));
    }
    // Chain longer than max_ext_headers (5 destination-option headers).
    var long: [40 + 5 * 8]u8 = @splat(0);
    try (Ip6{ .next_header = 60, .src = ula_a, .dst = ula_b }).write(&long, 5 * 8);
    for (0..5) |k| long[40 + 8 * k] = if (k == 4) proto_tcp else 60;
    try std.testing.expectError(error.BadExtensionHeader, Ip6.parse(&long));
    // Extension header longer than the packet / than the byte budget.
    @memcpy(&bad, &buf);
    bad[41] = 200;
    try std.testing.expectError(error.Truncated, Ip6.parse(bad[0 .. 56 + tcp_len]));
    // Payload length beyond the packet; wrong version.
    try std.testing.expectError(error.BadTotalLength, Ip6.parse(buf[0 .. 56 + tcp_len - 1]));
    @memcpy(&bad, &buf);
    bad[0] = 0x50;
    try std.testing.expectError(error.BadVersion, parseIp(bad[0 .. 56 + tcp_len]));
}

test "icmpv6 echo checksum" {
    var msg = [_]u8{ icmp6_echo_request, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g', '6' };
    std.mem.writeInt(u16, msg[2..4], icmp6Checksum(.{ .v6 = ula_a }, .{ .v6 = ula_b }, &msg), .big);
    try std.testing.expectEqual(icmp6_echo_request, try icmp6Type(.{ .v6 = ula_a }, .{ .v6 = ula_b }, &msg));
    try std.testing.expectEqual(@as(u16, 0), referenceSum6(ula_a, ula_b, proto_icmp6, &msg));
    try std.testing.expectError(error.BadChecksum, icmp6Type(.{ .v6 = ula_b }, .{ .v6 = ula_b }, &msg));
}

test "sack option: encode / decode, malformed ignored, option space" {
    var buf: [128]u8 = @splat(0);
    var s: Sack = .{ .len = 4 };
    for (0..4) |k| s.blocks[k] = .{ .start = @intCast(1000 * k), .end = @intCast(1000 * k + 500) };
    const seg: Tcp = .{ .src_port = 1, .dst_port = 2, .seq = 3, .ack = 4, .flags = .{ .ack = true }, .window = 5, .options = .{ .sack = s } };
    try std.testing.expectEqual(@as(usize, 20 + 36), seg.headerLen());
    const pkt = try buildTcp4(&buf, .{ .protocol = proto_tcp, .src = .{ 10, 8, 0, 2 }, .dst = .{ 10, 8, 0, 1 } }, seg);
    const p = try parseTcp4(pkt);
    try std.testing.expectEqual(@as(usize, 4), p.tcp.options.sack.?.slice().len);
    try std.testing.expectEqual(@as(u32, 3500), p.tcp.options.sack.?.slice()[3].end);
    // Malformed SACK lengths: ignored, the rest of the options still parse.
    for ([_][]const u8{
        &.{ 5, 2, 2, 4, 5, 0x34 },
        &.{ 5, 9, 0, 0, 0, 1, 0, 0, 0, 2, 0 },
        &.{ 5, 42 },
    }) |area| {
        const o = TcpOptions.parse(area) catch |e| {
            // Lengths that leave the area are malformed options as before.
            try std.testing.expectEqual(error.BadOptions, e);
            continue;
        };
        try std.testing.expectEqual(@as(?Sack, null), o.sack);
    }
    // Five blocks (42 bytes) cannot fit: never produced, ignored if seen.
    var five: [42]u8 = @splat(0);
    five[0] = 5;
    five[1] = 42;
    try std.testing.expectEqual(@as(?Sack, null), (try TcpOptions.parse(&five)).sack);
}