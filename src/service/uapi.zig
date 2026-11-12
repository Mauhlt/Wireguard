//! The cross-platform `wg` configuration protocol (wireguard.com/xplatform),
//! the read-only subset the tunnel service speaks on its control pipe.
//!
//! Request:  "get=1\n\n"            -> the device state, then "errno=0\n\n".
//!           "set=1\n..."           -> refused: "errno=-1\n\n" (EPERM). The
//!                                     service's configuration changes only
//!                                     by reinstalling (elevated).
//!           anything else          -> "errno=-22\n\n" (EINVAL), connection closed.
//!
//! The get response follows wg's key order: interface keys, then per peer
//! `public_key=` (which starts the peer) and its keys. Keys are lowercase hex.
//!
//! Secrets: unlike the kernel / wireguard-go, `private_key` and
//! `preshared_key` are never sent, to anyone (callers include the unelevated
//! installing user; admins can read the stored configuration). Instead the
//! interface's public key goes out as `zwg_public_key=` — wg's parser ignores
//! keys it does not know, so the response stays wg-compatible.
//!
//! Everything here is pure and bounded; `decode` treats its input as hostile.

const std = @import("std");
const ip = @import("../device/ip.zig");
const config = @import("../device/config.zig");

pub const max_request = 4096;
pub const max_response = 1 << 20;
pub const max_line = 256;
pub const max_peers = config.max_peers;
pub const max_allowed_ips = config.max_list_entries;

pub const errno_ok: i32 = 0;
pub const errno_perm: i32 = -1; // EPERM
pub const errno_io: i32 = -5; // EIO
pub const errno_invalid: i32 = -22; // EINVAL

// ---- requests (service side) -------------------------------------------------

pub const Request = enum { get, set };

/// `buf` is what the client sent so far. null = need more bytes.
pub fn parseRequest(buf: []const u8) error{InvalidRequest}!?Request {
    const nl = std.mem.findScalar(u8, buf, '\n') orelse {
        if (buf.len > "get=1".len) return error.InvalidRequest;
        if (!std.mem.startsWith(u8, "get=1", buf) and !std.mem.startsWith(u8, "set=1", buf)) return error.InvalidRequest;
        return null;
    };
    const line = buf[0..nl];
    if (std.mem.eql(u8, line, "set=1")) return .set;
    if (!std.mem.eql(u8, line, "get=1")) return error.InvalidRequest;
    if (buf.len == nl + 1) return null;
    if (buf[nl + 1] != '\n' or buf.len != nl + 2) return error.InvalidRequest;
    return .get;
}

pub fn writeErrno(w: *std.Io.Writer, errno: i32) std.Io.Writer.Error!void {
    try w.print("errno={d}\n\n", .{errno});
}

// ---- get response: encode (service side) ---------------------------------------

pub const Interface = struct {
    public_key: [32]u8,
    listen_port: u16,
};

pub const Peer = struct {
    public_key: [32]u8,
    endpoint: ?std.Io.net.IpAddress = null,
    /// Wall clock of the last completed handshake, ns since the Unix epoch.
    last_handshake_ns: ?i96 = null,
    tx_bytes: u64 = 0,
    rx_bytes: u64 = 0,
    persistent_keepalive: u16 = 0,
    allowed_ips: []const ip.Cidr = &.{},
};

/// Upper bound of `encodeGet`'s output for `peers` peers with
/// `allowed_ips` allowed IPs in total (to size a fixed buffer once).
pub fn maxGetLen(peers: usize, allowed_ips: usize) usize {
    return 128 + peers * 384 + allowed_ips * 64;
}

pub fn encodeGet(w: *std.Io.Writer, iface: Interface, peers: []const Peer) std.Io.Writer.Error!void {
    try w.print("zwg_public_key={s}\n", .{&std.fmt.bytesToHex(iface.public_key, .lower)});
    try w.print("listen_port={d}\n", .{iface.listen_port});
    for (peers) |p| {
        try w.print("public_key={s}\n", .{&std.fmt.bytesToHex(p.public_key, .lower)});
        if (p.endpoint) |e| try w.print("endpoint={f}\n", .{e});
        const ns: i96 = p.last_handshake_ns orelse 0;
        const sec: i96 = @divFloor(ns, std.time.ns_per_s);
        try w.print("last_handshake_time_sec={d}\nlast_handshake_time_nsec={d}\n", .{ sec, ns - sec * std.time.ns_per_s });
        try w.print("tx_bytes={d}\nrx_bytes={d}\n", .{ p.tx_bytes, p.rx_bytes });
        try w.print("persistent_keepalive_interval={d}\n", .{p.persistent_keepalive});
        for (p.allowed_ips) |a| try w.print("allowed_ip={f}\n", .{a});
        try w.writeAll("protocol_version=1\n");
    }
    try writeErrno(w, errno_ok);
}

// ---- get response: decode (client side) ---------------------------------------

pub const DecodedPeer = struct {
    public_key: [32]u8,
    endpoint: ?std.Io.net.IpAddress = null,
    last_handshake_sec: u64 = 0,
    last_handshake_nsec: u32 = 0,
    tx_bytes: u64 = 0,
    rx_bytes: u64 = 0,
    persistent_keepalive: u16 = 0,
    allowed_ips: []ip.Cidr = &.{},
};

pub const Status = struct {
    arena: std.heap.ArenaAllocator,
    public_key: ?[32]u8 = null,
    listen_port: ?u16 = null,
    peers: []DecodedPeer = &.{},

    pub fn deinit(s: *Status) void {
        s.arena.deinit();
        s.* = undefined;
    }
};

pub const DecodeError = error{
    /// The response breaks the protocol (malformed line, bad value, wrong
    /// order, over a limit, truncated, trailing bytes).
    InvalidResponse,
    /// Well formed, but errno != 0.
    RemoteError,
    OutOfMemory,
};

/// Parse a complete get response (ending "errno=N\n\n"). Unknown keys are
/// ignored, as wg does. `remote_errno` receives N when it is not 0.
pub fn decode(gpa: std.mem.Allocator, text: []const u8, remote_errno: ?*i32) DecodeError!Status {
    if (text.len > max_response) return error.InvalidResponse;
    var s: Status = .{ .arena = .init(gpa) };
    errdefer s.deinit();
    const a = s.arena.allocator();

    var peers: std.ArrayList(DecodedPeer) = .empty;
    var ips: std.ArrayList(ip.Cidr) = .empty;
    var total_ips: usize = 0;
    var seen: [8]bool = @splat(false); // per-peer duplicate detection
    var errno: ?i64 = null;

    var rest = text;
    while (true) {
        const nl = std.mem.findScalar(u8, rest, '\n') orelse return error.InvalidResponse;
        const line = rest[0..nl];
        rest = rest[nl + 1 ..];
        if (line.len > max_line) return error.InvalidResponse;
        if (line.len == 0) break; // end of response
        if (errno != null) return error.InvalidResponse; // errno must be last
        const eq = std.mem.findScalar(u8, line, '=') orelse return error.InvalidResponse;
        const key = line[0..eq];
        const val = line[eq + 1 ..];
        for (line) |c| if (c < 0x20 or c > 0x7e) return error.InvalidResponse;

        if (std.mem.eql(u8, key, "errno")) {
            errno = std.fmt.parseInt(i64, val, 10) catch return error.InvalidResponse;
        } else if (std.mem.eql(u8, key, "public_key")) {
            if (peers.items.len != 0) try finishPeer(a, &peers.items[peers.items.len - 1], &ips);
            if (peers.items.len >= max_peers) return error.InvalidResponse;
            try peers.append(a, .{ .public_key = try hexKey(val) });
            seen = @splat(false);
        } else if (peers.items.len == 0) {
            // Interface section.
            if (std.mem.eql(u8, key, "zwg_public_key")) {
                if (s.public_key != null) return error.InvalidResponse;
                s.public_key = try hexKey(val);
            } else if (std.mem.eql(u8, key, "listen_port")) {
                if (s.listen_port != null) return error.InvalidResponse;
                s.listen_port = try int(u16, val);
            } else if (std.mem.eql(u8, key, "private_key")) {
                _ = try hexKey(val); // well-formed, but never kept
            }
        } else {
            const p = &peers.items[peers.items.len - 1];
            const fields = [_][]const u8{ "endpoint", "last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes", "persistent_keepalive_interval", "protocol_version" };
            inline for (fields, 0..) |f, i| if (std.mem.eql(u8, key, f)) {
                if (seen[i]) return error.InvalidResponse;
                seen[i] = true;
            };
            if (std.mem.eql(u8, key, "endpoint")) {
                const e = config.Endpoint.parse(val) catch return error.InvalidResponse;
                p.endpoint = e.literal() orelse return error.InvalidResponse;
            } else if (std.mem.eql(u8, key, "last_handshake_time_sec")) {
                p.last_handshake_sec = try int(u64, val);
            } else if (std.mem.eql(u8, key, "last_handshake_time_nsec")) {
                p.last_handshake_nsec = try int(u32, val);
                if (p.last_handshake_nsec >= std.time.ns_per_s) return error.InvalidResponse;
            } else if (std.mem.eql(u8, key, "tx_bytes")) {
                p.tx_bytes = try int(u64, val);
            } else if (std.mem.eql(u8, key, "rx_bytes")) {
                p.rx_bytes = try int(u64, val);
            } else if (std.mem.eql(u8, key, "persistent_keepalive_interval")) {
                p.persistent_keepalive = try int(u16, val);
            } else if (std.mem.eql(u8, key, "protocol_version")) {
                if (try int(u32, val) != 1) return error.InvalidResponse;
            } else if (std.mem.eql(u8, key, "allowed_ip")) {
                if (ips.items.len >= max_allowed_ips or total_ips >= 16 * max_allowed_ips) return error.InvalidResponse;
                const c = ip.Cidr.parse(val) catch return error.InvalidResponse;
                if (std.mem.findScalar(u8, val, '/') == null) return error.InvalidResponse; // wg always sends the prefix
                try ips.append(a, c);
                total_ips += 1;
            } else if (std.mem.eql(u8, key, "preshared_key")) {
                _ = try hexKey(val);
            }
        }
    }
    if (rest.len != 0) return error.InvalidResponse;
    const e = errno orelse return error.InvalidResponse;
    if (e != 0) {
        if (remote_errno) |r| r.* = std.math.cast(i32, e) orelse std.math.minInt(i32);
        return error.RemoteError;
    }
    if (peers.items.len != 0) try finishPeer(a, &peers.items[peers.items.len - 1], &ips);
    s.peers = peers.items;
    return s;
}

fn finishPeer(a: std.mem.Allocator, p: *DecodedPeer, ips: *std.ArrayList(ip.Cidr)) !void {
    p.allowed_ips = try a.dupe(ip.Cidr, ips.items);
    ips.clearRetainingCapacity();
}

fn hexKey(val: []const u8) DecodeError![32]u8 {
    if (val.len != 64) return error.InvalidResponse;
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| {
        const hi = std.fmt.charToDigit(val[2 * i], 16) catch return error.InvalidResponse;
        const lo = std.fmt.charToDigit(val[2 * i + 1], 16) catch return error.InvalidResponse;
        if (std.ascii.isUpper(val[2 * i]) or std.ascii.isUpper(val[2 * i + 1])) return error.InvalidResponse;
        b.* = hi << 4 | lo;
    }
    return k;
}

fn int(comptime T: type, val: []const u8) DecodeError!T {
    if (val.len == 0 or val.len > 20) return error.InvalidResponse;
    for (val) |c| if (c < '0' or c > '9') return error.InvalidResponse; // no sign, no spaces
    return std.fmt.parseInt(T, val, 10) catch error.InvalidResponse;
}

// ---- `zwg show <name>` text ----------------------------------------------------

/// `wg show`-style text for a decoded status. `state` is the service state
/// ("running", ...); `now_unix` for "N seconds ago".
pub fn writeShow(w: *std.Io.Writer, name: []const u8, state: []const u8, s: *const Status, now_unix: i64) std.Io.Writer.Error!void {
    const keys = @import("../device/keys.zig");
    try w.print("interface: {s}\n  service: {s}\n", .{ name, state });
    if (s.public_key) |*k| try w.print("  public key: {s}\n", .{&keys.encode(k)});
    try w.writeAll("  private key: (hidden)\n");
    if (s.listen_port) |p| try w.print("  listening port: {d}\n", .{p});
    for (s.peers) |*p| {
        try w.print("\npeer: {s}\n", .{&keys.encode(&p.public_key)});
        if (p.endpoint) |e| try w.print("  endpoint: {f}\n", .{e});
        try w.writeAll("  allowed ips: ");
        if (p.allowed_ips.len == 0) try w.writeAll("(none)") else try config.writeCidrs(w, p.allowed_ips);
        try w.writeAll("\n");
        if (p.last_handshake_sec != 0) {
            const ago = now_unix - @as(i64, @intCast(@min(p.last_handshake_sec, std.math.maxInt(i63))));
            try w.print("  latest handshake: {d} second{s} ago\n", .{ @max(ago, 0), if (ago == 1) "" else "s" });
        }
        if (p.rx_bytes != 0 or p.tx_bytes != 0)
            try w.print("  transfer: {d} B received, {d} B sent\n", .{ p.rx_bytes, p.tx_bytes });
        if (p.persistent_keepalive != 0)
            try w.print("  persistent keepalive: every {d} seconds\n", .{p.persistent_keepalive});
    }
}

// ---- tests -----------------------------------------------------------------------

const t = std.testing;

test "requests" {
    try t.expectEqual(@as(?Request, .get), try parseRequest("get=1\n\n"));
    try t.expectEqual(@as(?Request, .set), try parseRequest("set=1\n"));
    try t.expectEqual(@as(?Request, .set), try parseRequest("set=1\nprivate_key=00\n\n"));
    for ([_][]const u8{ "", "g", "get=", "get=1", "get=1\n" }) |partial| try t.expectEqual(@as(?Request, null), try parseRequest(partial));
    for ([_][]const u8{ "x", "get=2\n\n", "GET=1\n\n", "get=1\nx\n", "get=1\n\nmore", "get=1\r\n\r\n", "get=11", "\n", "get =1\n\n" }) |bad|
        try t.expectError(error.InvalidRequest, parseRequest(bad));
}

fn sample(buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const allowed = [_]ip.Cidr{ try .parse("10.0.0.2/32"), try .parse("fd00::/64") };
    var v6: [16]u8 = @splat(0);
    v6[0..4].* = .{ 0x20, 0x01, 0x0d, 0xb8 };
    try encodeGet(&w, .{ .public_key = @splat(0xab), .listen_port = 51820 }, &.{
        .{
            .public_key = @splat(0x01),
            .endpoint = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 51820 } },
            .last_handshake_ns = 1_700_000_000 * std.time.ns_per_s + 123,
            .tx_bytes = 10,
            .rx_bytes = 20,
            .persistent_keepalive = 25,
            .allowed_ips = &allowed,
        },
        .{ .public_key = @splat(0xfe), .endpoint = .{ .ip6 = .{ .bytes = v6, .port = 1 } } },
    });
    return w.buffered();
}

test "encode get" {
    var buf: [2048]u8 = undefined;
    const text = try sample(&buf);
    try t.expectEqualStrings(
        "zwg_public_key=" ++ comptime rep("ab", 32) ++ "\n" ++
            "listen_port=51820\n" ++
            "public_key=" ++ rep("01", 32) ++ "\n" ++
            "endpoint=192.0.2.1:51820\n" ++
            "last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=123\n" ++
            "tx_bytes=10\nrx_bytes=20\npersistent_keepalive_interval=25\n" ++
            "allowed_ip=10.0.0.2/32\nallowed_ip=fd00::/64\nprotocol_version=1\n" ++
            "public_key=" ++ rep("fe", 32) ++ "\n" ++
            "endpoint=[2001:db8::]:1\n" ++
            "last_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" ++
            "tx_bytes=0\nrx_bytes=0\npersistent_keepalive_interval=0\nprotocol_version=1\n" ++
            "errno=0\n\n",
        text,
    );
    // Never a private or preshared key.
    try t.expect(std.mem.indexOf(u8, text, "private_key") == null);
    try t.expect(std.mem.indexOf(u8, text, "preshared_key") == null);
    try t.expect(text.len <= maxGetLen(2, 2));
}

test "decode round trip" {
    var buf: [2048]u8 = undefined;
    var s = try decode(t.allocator, try sample(&buf), null);
    defer s.deinit();
    try t.expectEqual(@as([32]u8, @splat(0xab)), s.public_key.?);
    try t.expectEqual(@as(?u16, 51820), s.listen_port);
    try t.expectEqual(@as(usize, 2), s.peers.len);
    const p = s.peers[0];
    try t.expectEqual(@as([32]u8, @splat(0x01)), p.public_key);
    try t.expectEqual(@as(u64, 1_700_000_000), p.last_handshake_sec);
    try t.expectEqual(@as(u32, 123), p.last_handshake_nsec);
    try t.expectEqual(@as(u64, 10), p.tx_bytes);
    try t.expectEqual(@as(u64, 20), p.rx_bytes);
    try t.expectEqual(@as(u16, 25), p.persistent_keepalive);
    try t.expectEqual(@as(usize, 2), p.allowed_ips.len);
    try t.expectEqual(@as(u8, 64), p.allowed_ips[1].prefix);
    try t.expectEqual(@as(u16, 51820), p.endpoint.?.getPort());
    try t.expectEqual(@as(usize, 0), s.peers[1].allowed_ips.len);
    try t.expect(s.peers[1].endpoint.? == .ip6);

    var out_buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    try writeShow(&w, "laptop", "running", &s, 1_700_000_005);
    const shown = w.buffered();
    try t.expect(std.mem.indexOf(u8, shown, "latest handshake: 5 seconds ago") != null);
    try t.expect(std.mem.indexOf(u8, shown, "allowed ips: 10.0.0.2/32, fd00::/64") != null);
    try t.expect(std.mem.indexOf(u8, shown, "private key: (hidden)") != null);
}

test "decode: remote errno" {
    var e: i32 = 0;
    try t.expectError(error.RemoteError, decode(t.allocator, "errno=-1\n\n", &e));
    try t.expectEqual(@as(i32, -1), e);
    var s = try decode(t.allocator, "errno=0\n\n", null);
    s.deinit();
}

test "decode: hostile input is rejected, never crashes" {
    const k = comptime rep("01", 32);
    const bad = [_][]const u8{
        "",
        "\n",
        "errno=0\n", // not terminated by a blank line
        "errno=0", // truncated
        "listen_port=1\n\n", // no errno
        "errno=0\n\nextra", // trailing bytes
        "errno=0\nlisten_port=1\n\n", // errno not last
        "listen_port\nerrno=0\n\n", // no '='
        "listen_port=65536\nerrno=0\n\n",
        "listen_port=-1\nerrno=0\n\n",
        "listen_port= 1\nerrno=0\n\n",
        "listen_port=1\nlisten_port=2\nerrno=0\n\n", // duplicate
        "listen_port=\nerrno=0\n\n",
        "errno=x\n\n",
        "public_key=0\nerrno=0\n\n", // short key
        "public_key=" ++ comptime rep("zz", 32) ++ "\nerrno=0\n\n", // not hex
        "public_key=" ++ comptime rep("AB", 32) ++ "\nerrno=0\n\n", // uppercase is not what wg sends
        "public_key=" ++ k ++ "0\nerrno=0\n\n", // long key
        "public_key=" ++ k ++ "\nendpoint=example.com:1\nerrno=0\n\n", // not a literal
        "public_key=" ++ k ++ "\nendpoint=1.2.3.4\nerrno=0\n\n", // no port
        "public_key=" ++ k ++ "\nallowed_ip=10.0.0.0/33\nerrno=0\n\n",
        "public_key=" ++ k ++ "\nallowed_ip=10.0.0.1\nerrno=0\n\n", // no prefix
        "public_key=" ++ k ++ "\nlast_handshake_time_nsec=1000000000\nerrno=0\n\n",
        "public_key=" ++ k ++ "\ntx_bytes=18446744073709551616\nerrno=0\n\n", // u64 overflow
        "public_key=" ++ k ++ "\nrx_bytes=1\nrx_bytes=2\nerrno=0\n\n", // duplicate
        "public_key=" ++ k ++ "\nprotocol_version=2\nerrno=0\n\n",
        "public_key=" ++ k ++ "\npersistent_keepalive_interval=70000\nerrno=0\n\n",
        "listen_port=1\x00\nerrno=0\n\n", // control byte
        "x=\xff\nerrno=0\n\n", // non-ASCII
        "x=" ++ comptime rep("a", 300) ++ "\nerrno=0\n\n", // over-long line
        "zwg_public_key=00\nerrno=0\n\n",
        "private_key=00\nerrno=0\n\n",
    };
    for (bad) |b| {
        if (decode(t.allocator, b, null)) |s_| {
            var s = s_;
            s.deinit();
            std.debug.print("accepted: {s}\n", .{b});
            return error.TestUnexpectedResult;
        } else |err| switch (err) {
            error.InvalidResponse, error.RemoteError => {},
            error.OutOfMemory => return err,
        }
    }
    // Unknown keys are ignored (forward compatible, as wg).
    var s = try decode(t.allocator, "fwmark=0\nfuture=1\npublic_key=" ++ k ++ "\nfuture_peer=x\nerrno=0\n\n", null);
    defer s.deinit();
    try t.expectEqual(@as(usize, 1), s.peers.len);
}

test "decode: peer count is bounded" {
    var w: std.Io.Writer.Allocating = .init(t.allocator);
    defer w.deinit();
    for (0..max_peers + 1) |i| try w.writer.print("public_key={x:0>64}\n", .{i});
    try w.writer.writeAll("errno=0\n\n");
    try t.expectError(error.InvalidResponse, decode(t.allocator, w.written(), null));
}

test "decode: random bytes never crash" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const r = prng.random();
    var buf: [512]u8 = undefined;
    const alphabet = "0123456789abcdef=\n_.:[]/-errnopublic_keyallowed_ip";
    for (0..20_000) |_| {
        const n = r.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*c| c.* = if (r.boolean()) alphabet[r.uintLessThan(usize, alphabet.len)] else r.int(u8);
        if (decode(t.allocator, buf[0..n], null)) |s_| {
            var s = s_;
            s.deinit();
        } else |_| {}
    }
}

fn rep(comptime s: []const u8, comptime n: usize) []const u8 {
    comptime {
        var out: []const u8 = "";
        for (0..n) |_| out = out ++ s;
        return out;
    }
}
