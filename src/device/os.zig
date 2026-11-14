//! The device's OS seam: UDP sockets with a waitable readiness handle, one
//! blocking wait over many handles with a timeout, and the stop signal
//! `zwg down` uses. Windows: Winsock + WaitForMultipleObjects. POSIX
//! (Linux, macOS, iOS): sockets + poll(2).
const builtin = @import("builtin");
const common = @import("os/common.zig");

const backend = if (builtin.os.tag == .windows) @import("os/windows.zig") else @import("os/posix.zig");

pub const Family = common.Family;
pub const Datagram = common.Datagram;
pub const OpenError = common.OpenError;
pub const RecvError = common.RecvError;
pub const SendError = common.SendError;
pub const WaitError = common.WaitError;
pub const StopError = common.StopError;

pub const WaitHandle = backend.WaitHandle;
pub const Udp = backend.Udp;
pub const wait = backend.wait;
pub const StopSignal = backend.StopSignal;
pub const DeadlineTimer = backend.DeadlineTimer;
pub const stopOnInterrupt = backend.stopOnInterrupt;

const std = @import("std");

test "udp loopback with readiness wait (IPv4 and IPv6)" {
    for ([_]Family{ .v4, .v6 }) |fam| {
        var a = Udp.open(fam, 0) catch |err| {
            if (fam == .v6 and err == error.AddressFamilyUnsupported) continue;
            return err;
        };
        defer a.close();
        var b = try Udp.open(fam, 0);
        defer b.close();
        const port = b.localPort();
        try std.testing.expect(port != 0);
        const to: std.Io.net.IpAddress = switch (fam) {
            .v4 => .{ .ip4 = .loopback(port) },
            .v6 => .{ .ip6 = .loopback(port) },
        };
        var buf: [64]u8 = undefined;
        b.beginDrain();
        try std.testing.expectEqual(@as(?Datagram, null), try b.recv(&buf));
        // Nothing ready: the wait times out.
        try std.testing.expectEqual(@as(?usize, null), try wait(&.{b.waitHandle()}, 5 * std.time.ns_per_ms));
        try a.send(to, "hello");
        try a.send(to, "again");
        try std.testing.expectEqual(@as(?usize, 1), try wait(&.{ a.waitHandle(), b.waitHandle() }, 2 * std.time.ns_per_s));
        b.beginDrain();
        const d1 = (try b.recv(&buf)).?;
        try std.testing.expectEqualStrings("hello", buf[0..d1.len]);
        try std.testing.expectEqual(a.localPort(), d1.from.getPort());
        const d2 = (try b.recv(&buf)).?;
        try std.testing.expectEqualStrings("again", buf[0..d2.len]);
        try std.testing.expectEqual(@as(?Datagram, null), try b.recv(&buf));
        // Drained and reset: not ready any more.
        try std.testing.expectEqual(@as(?usize, null), try wait(&.{b.waitHandle()}, 5 * std.time.ns_per_ms));
        try std.testing.expectError(error.AddressFamilyMismatch, a.send(if (fam == .v4) .{ .ip6 = .loopback(1) } else .{ .ip4 = .loopback(1) }, "x"));
    }
}

test "deadline timer: ready once armed time passes, not before, not after disarm" {
    var t = try DeadlineTimer.init();
    defer t.deinit();
    const h = t.waitHandle() orelse return error.SkipZigTest; // no such clock on this OS
    try std.testing.expectEqual(@as(?usize, null), try wait(&.{h}, 1 * std.time.ns_per_ms));
    t.arm(20 * std.time.ns_per_ms);
    // Not yet (the wait's own timeout ends first).
    try std.testing.expectEqual(@as(?usize, null), try wait(&.{h}, 1 * std.time.ns_per_ms));
    // Then it fires on its own, well inside a long wait.
    try std.testing.expectEqual(@as(?usize, 0), try wait(&.{h}, 5 * std.time.ns_per_s));
    t.clear();
    try std.testing.expectEqual(@as(?usize, null), try wait(&.{h}, 1 * std.time.ns_per_ms));
    // Re-arming replaces; disarming cancels.
    t.arm(std.time.ns_per_s);
    t.arm(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(?usize, 0), try wait(&.{h}, 5 * std.time.ns_per_s));
    t.clear();
    t.arm(10 * std.time.ns_per_ms);
    t.disarm();
    try std.testing.expectEqual(@as(?usize, null), try wait(&.{h}, 50 * std.time.ns_per_ms));
}

test "stop signal" {
    var s = try StopSignal.create("zwg-test-stop");
    defer s.close();
    try std.testing.expectEqual(@as(?usize, null), try wait(&.{s.waitHandle()}, 1 * std.time.ns_per_ms));
    s.signal();
    try std.testing.expectEqual(@as(?usize, 0), try wait(&.{s.waitHandle()}, 1 * std.time.ns_per_s));
}

test "zwg down: signal a running instance by name" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectError(error.NotRunning, StopSignal.signalExisting("zwg-test-down"));
    var s = try StopSignal.create("zwg-test-down");
    defer s.close();
    try std.testing.expectError(error.AlreadyRunning, StopSignal.create("zwg-test-down"));
    try StopSignal.signalExisting("zwg-test-down");
    try std.testing.expectEqual(@as(?usize, 0), try wait(&.{s.waitHandle()}, 1 * std.time.ns_per_s));
}
