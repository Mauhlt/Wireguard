//! `wg show`-style text for a configuration and (when running) live peer
//! state. Never prints private or preshared keys: they show as "(hidden)",
//! exactly as `wg show` does.

const std = @import("std");
const keys = @import("keys.zig");
const config = @import("config.zig");

pub const PeerStatus = struct {
    endpoint: ?std.Io.net.IpAddress = null,
    /// Wall-clock seconds since the Unix epoch of the last completed
    /// handshake, null if none yet.
    last_handshake_unix: ?i64 = null,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
};

pub const InterfaceStatus = struct {
    listen_port: ?u16 = null,
};

/// `peer_status[i]` (optional) is live state for `c.peers[i]`.
pub fn write(
    w: *std.Io.Writer,
    name: []const u8,
    c: *const config.Config,
    iface_status: ?InterfaceStatus,
    peer_status: ?[]const PeerStatus,
    now_unix: i64,
) std.Io.Writer.Error!void {
    const pub_key = keys.publicFromPrivate(&c.interface.private_key);
    try w.print("interface: {s}\n", .{name});
    try w.print("  public key: {s}\n", .{&keys.encode(&pub_key)});
    try w.writeAll("  private key: (hidden)\n");
    const port = if (iface_status) |s| s.listen_port orelse c.interface.listen_port else c.interface.listen_port;
    if (port) |p| {
        if (p != 0) try w.print("  listening port: {d}\n", .{p});
    }
    if (c.interface.addresses.len != 0) {
        try w.writeAll("  address: ");
        try config.writeCidrs(w, c.interface.addresses);
        try w.writeAll("\n");
    }
    if (c.interface.dns.len + c.interface.dns_search.len != 0) {
        try w.writeAll("  dns: ");
        var first = true;
        for (c.interface.dns) |d| {
            if (!first) try w.writeAll(", ");
            first = false;
            try w.print("{f}", .{d});
        }
        for (c.interface.dns_search) |d| {
            if (!first) try w.writeAll(", ");
            first = false;
            try w.writeAll(d);
        }
        try w.writeAll("\n");
    }
    if (c.interface.mtu) |m| try w.print("  mtu: {d}\n", .{m});

    for (c.peers, 0..) |*p, i| {
        const st: ?PeerStatus = if (peer_status) |ps| ps[i] else null;
        try w.print("\npeer: {s}\n", .{&keys.encode(&p.public_key)});
        if (p.preshared_key != null) try w.writeAll("  preshared key: (hidden)\n");
        if (st != null and st.?.endpoint != null) {
            try w.print("  endpoint: {f}\n", .{st.?.endpoint.?});
        } else if (p.endpoint) |e| {
            try w.print("  endpoint: {f}\n", .{e});
        }
        try w.writeAll("  allowed ips: ");
        if (p.allowed_ips.len == 0) try w.writeAll("(none)") else try config.writeCidrs(w, p.allowed_ips);
        try w.writeAll("\n");
        if (st) |s| {
            if (s.last_handshake_unix) |t| {
                try w.writeAll("  latest handshake: ");
                try writeAgo(w, now_unix - t);
                try w.writeAll("\n");
            }
            if (s.rx_bytes != 0 or s.tx_bytes != 0) {
                try w.writeAll("  transfer: ");
                try writeBytes(w, s.rx_bytes);
                try w.writeAll(" received, ");
                try writeBytes(w, s.tx_bytes);
                try w.writeAll(" sent\n");
            }
        }
        if (p.persistent_keepalive != 0) try w.print("  persistent keepalive: every {d} second{s}\n", .{
            p.persistent_keepalive, if (p.persistent_keepalive == 1) "" else "s",
        });
    }
}

/// "1 day, 2 hours, 3 minutes, 4 seconds ago", like wg's ago().
pub fn writeAgo(w: *std.Io.Writer, seconds_in: i64) std.Io.Writer.Error!void {
    if (seconds_in < 0) return w.writeAll("in the future");
    if (seconds_in == 0) return w.writeAll("Now");
    var s: u64 = @intCast(seconds_in);
    const units = [_]struct { n: u64, name: []const u8 }{
        .{ .n = 365 * 24 * 3600, .name = "year" },
        .{ .n = 24 * 3600, .name = "day" },
        .{ .n = 3600, .name = "hour" },
        .{ .n = 60, .name = "minute" },
        .{ .n = 1, .name = "second" },
    };
    var first = true;
    for (units) |u| {
        const v = s / u.n;
        s %= u.n;
        if (v == 0) continue;
        if (!first) try w.writeAll(", ");
        first = false;
        try w.print("{d} {s}{s}", .{ v, u.name, if (v == 1) "" else "s" });
    }
    try w.writeAll(" ago");
}

/// "123 B", "1.50 KiB", "12.34 MiB", like wg's bytes().
pub fn writeBytes(w: *std.Io.Writer, b: u64) std.Io.Writer.Error!void {
    const f: f64 = @floatFromInt(b);
    if (b < 1024) return w.print("{d} B", .{b});
    if (b < 1024 * 1024) return w.print("{d:.2} KiB", .{f / 1024});
    if (b < 1024 * 1024 * 1024) return w.print("{d:.2} MiB", .{f / (1024 * 1024)});
    if (b < 1024 * 1024 * 1024 * 1024) return w.print("{d:.2} GiB", .{f / (1024 * 1024 * 1024)});
    return w.print("{d:.2} TiB", .{f / (1024 * 1024 * 1024 * 1024)});
}

test "show a config: no secrets, wg show layout" {
    const priv = "eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w=";
    const peer_pub = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const psk = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";
    const text = "[Interface]\nPrivateKey = " ++ priv ++ "\nAddress = 10.8.0.2/24\nListenPort = 51820\n" ++
        "[Peer]\nPublicKey = " ++ peer_pub ++ "\nPresharedKey = " ++ psk ++
        "\nEndpoint = vpn.example.org:51820\nAllowedIPs = 10.8.0.1/32\nPersistentKeepalive = 25\n";
    var d: config.Diagnostic = .{};
    var c = try config.parse(std.testing.allocator, text, &d);
    defer c.deinit();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    const status = [_]PeerStatus{.{ .last_handshake_unix = 1000 - 62, .rx_bytes = 1536, .tx_bytes = 92 }};
    try write(&out.writer, "laptop", &c, null, &status, 1000);
    const s = out.written();
    try std.testing.expect(std.mem.find(u8, s, priv) == null);
    try std.testing.expect(std.mem.find(u8, s, psk) == null);
    const want =
        \\interface: laptop
        \\  public key:
    ;
    try std.testing.expect(std.mem.startsWith(u8, s, want));
    try std.testing.expect(std.mem.find(u8, s, "  private key: (hidden)\n  listening port: 51820\n  address: 10.8.0.2/24\n") != null);
    try std.testing.expect(std.mem.find(u8, s, "\npeer: " ++ peer_pub ++ "\n  preshared key: (hidden)\n  endpoint: vpn.example.org:51820\n  allowed ips: 10.8.0.1/32\n") != null);
    try std.testing.expect(std.mem.find(u8, s, "  latest handshake: 1 minute, 2 seconds ago\n") != null);
    try std.testing.expect(std.mem.find(u8, s, "  transfer: 1.50 KiB received, 92 B sent\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, s, "  persistent keepalive: every 25 seconds\n"));
}
