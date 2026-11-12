//! Shared helpers for the interop drivers (loopback.zig, live.zig): keys,
//! .conf files, child processes, bounded waits. Test tooling only.
const std = @import("std");
const Io = std.Io;
const wg = @import("WireGuard");
const spec = @import("spec.zig");

pub const tun = wg.tun;

pub const KeyPair = struct {
    private: [32]u8,
    public: [32]u8,

    pub fn generate(io: Io) KeyPair {
        var k: [32]u8 = undefined;
        io.random(&k);
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        return .{ .private = k, .public = spec.publicKey(k) };
    }

    pub fn wipe(kp: *KeyPair) void {
        std.crypto.secureZero(u8, &kp.private);
    }
};

pub fn b64(key: [32]u8) [44]u8 {
    var out: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &key);
    return out;
}

/// A free UDP port on 127.0.0.1 (bound, read back, released).
pub fn freePort() !u16 {
    var u = try tun.UdpTun.open(0, 1500);
    defer u.close();
    return u.port();
}

pub const Conf = struct {
    private: [32]u8,
    listen_port: ?u16 = null,
    address: ?[]const u8 = null,
    peer_public: [32]u8,
    allowed_ips: []const u8,
    endpoint_port: ?u16 = null,
    persistent_keepalive: ?u16 = null,

    /// `[Interface]/[Peer]` text as wg-quick / WireGuard for Windows read it.
    pub fn render(c: Conf, buf: []u8) ![]u8 {
        var w: Io.Writer = .fixed(buf);
        try w.print("[Interface]\nPrivateKey = {s}\n", .{&b64(c.private)});
        if (c.listen_port) |p| try w.print("ListenPort = {d}\n", .{p});
        if (c.address) |a| try w.print("Address = {s}\n", .{a});
        try w.print("\n[Peer]\nPublicKey = {s}\nAllowedIPs = {s}\n", .{ &b64(c.peer_public), c.allowed_ips });
        if (c.endpoint_port) |p| try w.print("Endpoint = 127.0.0.1:{d}\n", .{p});
        if (c.persistent_keepalive) |k| try w.print("PersistentKeepalive = {d}\n", .{k});
        return w.buffered();
    }
};

pub fn writeFile(io: Io, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

/// Overwrite then delete (the .conf files hold private keys, even if
/// throwaway ones).
pub fn shredFile(io: Io, path: []const u8, len: usize) void {
    var zeros: [4096]u8 = @splat(0);
    writeFile(io, path, zeros[0..@min(len, zeros.len)]) catch {};
    Io.Dir.cwd().deleteFile(io, path) catch {};
}

pub const RunOutput = struct {
    ok: bool,
    stdout: []u8,
    stderr: []u8,
};

/// Run a command to completion (bounded output), echoing it to stderr.
pub fn run(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !RunOutput {
    std.debug.print("  $", .{});
    for (argv) |a| std.debug.print(" {s}", .{a});
    std.debug.print("\n", .{});
    const r = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    });
    if (!r.term.success()) std.debug.print("    -> {f}\n{s}{s}", .{ r.term, r.stdout, r.stderr });
    return .{ .ok = r.term.success(), .stdout = r.stdout, .stderr = r.stderr };
}

pub fn sleepMs(io: Io, ms: i64) void {
    io.sleep(.fromMilliseconds(ms), .awake) catch {};
}

/// Wait (bounded) for a datagram on a UdpTun and return it.
pub fn recvWithin(t: tun.Tun, buf: []u8, timeout_ms: u32) !?[]u8 {
    if (try t.read(buf)) |p| return p;
    tun.queue.waitReadable(t.waitHandle(), timeout_ms) catch return null;
    return t.read(buf);
}

pub fn fail(comptime fmt: []const u8, args: anytype) error{InteropFailed} {
    std.debug.print("FAIL: " ++ fmt ++ "\n", args);
    return error.InteropFailed;
}

pub fn step(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("== " ++ fmt ++ "\n", args);
}
