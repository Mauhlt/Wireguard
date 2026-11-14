//! FakeTun: an in-memory Tun for tests (device loop, loopback harness).
//!
//! Two bounded queues, each with a real OS wait handle, so a device under
//! test runs its normal event loop unchanged:
//!
//!   test --inject()--> [inbound]  --Tun.read()-->  device   (what the OS "sends")
//!   test <--take()---- [outbound] <--Tun.write()-- device   (what the OS "receives")
//!
//! `inject` and `take` may be called from another thread than the device's
//! (one injector thread, one taker thread at most: the queues are SPSC).
//! Addresses and routes are recorded for assertions.
const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const queue = @import("queue.zig");
const Cidr = @import("../ip.zig").Cidr;
const Tun = root.Tun;

pub const FakeTun = struct {
    gpa: Allocator,
    inbound: queue.Channel,
    outbound: queue.Channel,
    mtu_value: u16,
    closed: std.atomic.Value(bool) = .init(false),
    addresses: [max_recorded]Cidr = undefined,
    address_count: usize = 0,
    routes: [max_recorded]Cidr = undefined,
    route_count: usize = 0,
    /// Packets the device wrote while `outbound` was full.
    dropped_writes: usize = 0,

    pub const max_recorded = 32;

    pub const Options = struct {
        mtu: u16 = root.default_mtu,
        /// Packets per direction.
        capacity: u32 = 256,
    };

    pub fn init(gpa: Allocator, options: Options) !FakeTun {
        var inbound = try queue.Channel.init(gpa, options.capacity, options.mtu);
        errdefer inbound.deinit(gpa);
        const outbound = try queue.Channel.init(gpa, options.capacity, options.mtu);
        return .{ .gpa = gpa, .inbound = inbound, .outbound = outbound, .mtu_value = options.mtu };
    }

    pub fn deinit(f: *FakeTun) void {
        f.inbound.deinit(f.gpa);
        f.outbound.deinit(f.gpa);
        f.* = undefined;
    }

    pub fn tun(f: *FakeTun) Tun {
        return .{ .ptr = f, .vtable = &vtable };
    }

    // ---- test side ---------------------------------------------------------

    /// Queue a packet for the device to read (as if the OS routed it to us).
    pub fn inject(f: *FakeTun, packet: []const u8) error{ QueueFull, PacketTooLarge }!void {
        return f.inbound.send(packet);
    }

    /// Next packet the device wrote, or null.
    pub fn take(f: *FakeTun, buf: []u8) error{BufferTooSmall}!?[]u8 {
        return f.outbound.recv(buf);
    }

    /// Ready when `take` may return a packet.
    pub fn takeHandle(f: *const FakeTun) root.WaitHandle {
        return f.outbound.handle();
    }

    /// Wait (bounded) for the device to write a packet and return it.
    pub fn takeWait(f: *FakeTun, buf: []u8, timeout_ms: u32) !?[]u8 {
        if (try f.take(buf)) |p| return p;
        queue.waitReadable(f.takeHandle(), timeout_ms) catch return null;
        return f.take(buf);
    }

    /// Simulate the adapter disappearing: reads and writes fail with Closed.
    pub fn simulateClose(f: *FakeTun) void {
        f.closed.store(true, .release);
        f.inbound.waker.signal(); // wake the loop so it notices
    }

    pub fn recordedAddresses(f: *const FakeTun) []const Cidr {
        return f.addresses[0..f.address_count];
    }

    pub fn recordedRoutes(f: *const FakeTun) []const Cidr {
        return f.routes[0..f.route_count];
    }

    // ---- Tun implementation -----------------------------------------------

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = setAddress,
        .addRoute = addRoute,
    };

    fn self(ptr: *anyopaque) *FakeTun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) root.WaitHandle {
        return self(ptr).inbound.handle();
    }

    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        const f = self(ptr);
        if (f.closed.load(.acquire)) return error.Closed;
        return f.inbound.recv(buf);
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const f = self(ptr);
        if (f.closed.load(.acquire)) return error.Closed;
        if (packet.len > f.mtu_value) return error.PacketTooLarge;
        f.outbound.send(packet) catch |e| switch (e) {
            error.QueueFull => {
                f.dropped_writes += 1;
                return error.QueueFull;
            },
            error.PacketTooLarge => return error.PacketTooLarge,
        };
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).mtu_value;
    }

    fn setAddress(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        const f = self(ptr);
        if (f.address_count == max_recorded) return error.Unexpected;
        f.addresses[f.address_count] = cidr;
        f.address_count += 1;
    }

    fn addRoute(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        const f = self(ptr);
        if (f.route_count == max_recorded) return error.Unexpected;
        f.routes[f.route_count] = cidr;
        f.route_count += 1;
    }
};

test "FakeTun: inject -> read, write -> take, handles" {
    const gpa = std.testing.allocator;
    var fake = try FakeTun.init(gpa, .{ .mtu = 1280, .capacity = 4 });
    defer fake.deinit();
    const t = fake.tun();
    var buf: [1280]u8 = undefined;

    try std.testing.expectEqual(@as(u16, 1280), t.mtu());
    try std.testing.expectEqual(@as(?[]u8, null), try t.read(&buf));

    try fake.inject("\x45hello");
    try queue.waitReadable(t.waitHandle(), 1000);
    try std.testing.expectEqualStrings("\x45hello", (try t.read(&buf)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try t.read(&buf));

    try t.write("\x60reply");
    try std.testing.expectEqualStrings("\x60reply", (try fake.takeWait(&buf, 1000)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try fake.take(&buf));

    var big: [1281]u8 = @splat(0);
    try std.testing.expectError(error.PacketTooLarge, t.write(&big));
    for (0..4) |_| try t.write("x");
    try std.testing.expectError(error.QueueFull, t.write("x"));
    try std.testing.expectEqual(@as(usize, 1), fake.dropped_writes);

    try t.setAddress(try Cidr.parse("10.0.0.2/24"));
    try t.addRoute(try Cidr.parse("10.0.0.0/24"));
    try t.addRoute(try Cidr.parse("fd00::/64"));
    try std.testing.expectEqual(@as(usize, 1), fake.recordedAddresses().len);
    try std.testing.expectEqual(@as(usize, 2), fake.recordedRoutes().len);

    fake.simulateClose();
    try std.testing.expectError(error.Closed, t.read(&buf));
    try std.testing.expectError(error.Closed, t.write("x"));
}
