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
    if (!r.term.eql(.success)) std.debug.print("    -> {f}\n{s}{s}", .{ r.term, r.stdout, r.stderr });
    return .{ .ok = r.term.eql(.success), .stdout = r.stdout, .stderr = r.stderr };
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

// ---- live tests: UDP echo / probe through a tunnel, PASS/FAIL report -----

const os = wg.device.os;

pub fn monoMs(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, std.time.ns_per_ms));
}

pub fn nowS(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// UDP echo server on 0.0.0.0:<port> until `stop` is signalled (blocks on
/// the socket and the stop handle; no polling).
pub fn echoServe(port: u16, stop: ?os.WaitHandle) !void {
    var u = try os.Udp.open(.v4, port);
    defer u.close();
    var buf: [65535]u8 = undefined;
    while (true) {
        if (stop) |s| {
            const r = try os.wait(&.{ s, u.waitHandle() }, null);
            if (r == 0) return;
        } else _ = try os.wait(&.{u.waitHandle()}, null);
        u.beginDrain();
        while (try u.recv(&buf)) |dg| u.send(dg.from, buf[0..dg.len]) catch {};
    }
}

/// Sends `len` tagged bytes to dst:port and waits for the identical echo,
/// resending every second (a handshake may be under way) until
/// `timeout_ms`. Returns the round-trip time in ms, or null.
pub fn udpProbe(io: Io, dst: [4]u8, port: u16, len: usize, timeout_ms: u32) !?i64 {
    var u = try os.Udp.open(.v4, 0);
    defer u.close();
    var payload: [65507]u8 = undefined;
    if (len > payload.len) return error.TooLong;
    var tag: [8]u8 = undefined;
    io.random(&tag);
    for (payload[0..len], 0..) |*b, i| b.* = if (i < 8) tag[i] else @truncate(i);
    var buf: [65535]u8 = undefined;
    const t0 = monoMs(io);
    const t_end = t0 + timeout_ms;
    while (monoMs(io) < t_end) {
        u.send(.{ .ip4 = .{ .bytes = dst, .port = port } }, payload[0..len]) catch {};
        const t_resend = @min(t_end, monoMs(io) + 1000);
        while (true) {
            const left = t_resend - monoMs(io);
            if (left <= 0) break;
            _ = try os.wait(&.{u.waitHandle()}, @as(u64, @intCast(left)) * std.time.ns_per_ms) orelse break;
            u.beginDrain();
            while (try u.recv(&buf)) |dg| {
                if (dg.len == len and std.mem.eql(u8, buf[0..len], payload[0..len])) return monoMs(io) - t0;
            }
        }
    }
    return null;
}

pub const Check = struct { name: []const u8, ok: bool, detail: []const u8 };

/// Named PASS/FAIL checks, printed as they happen and written as a results
/// file at the end.
pub const Report = struct {
    checks: std.ArrayList(Check) = .empty,
    gpa: std.mem.Allocator,

    pub fn add(r: *Report, name: []const u8, ok: bool, comptime fmt: []const u8, args: anytype) void {
        const detail = std.fmt.allocPrint(r.gpa, fmt, args) catch "";
        r.checks.append(r.gpa, .{ .name = name, .ok = ok, .detail = detail }) catch {};
        std.debug.print("  [{s}] {s}{s}{s}\n", .{ if (ok) "PASS" else "FAIL", name, if (detail.len != 0) ": " else "", detail });
    }

    pub fn passed(r: *const Report) bool {
        if (r.checks.items.len == 0) return false;
        for (r.checks.items) |c| if (!c.ok) return false;
        return true;
    }

    pub fn write(r: *const Report, w: *Io.Writer, title: []const u8, notes: []const u8) !void {
        var fails: usize = 0;
        for (r.checks.items) |c| fails += @intFromBool(!c.ok);
        try w.print("{s}: {s} ({d} checks, {d} failed)\n\n", .{ title, if (r.passed()) "PASS" else "FAIL", r.checks.items.len, fails });
        for (r.checks.items) |c| try w.print("{s}  {s}{s}{s}\n", .{ if (c.ok) "PASS" else "FAIL", c.name, if (c.detail.len != 0) " -- " else "", c.detail });
        if (notes.len != 0) try w.print("\n{s}\n", .{notes});
    }
};

pub fn okText(ok: bool) []const u8 {
    return if (ok) "OK" else "FAILED";
}
