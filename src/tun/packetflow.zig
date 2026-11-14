//! iOS backend: an adapter for NEPacketTunnelProvider.packetFlow.
//!
//! On iOS a Network Extension gets no TUN file descriptor; packets arrive as
//! `readPackets` completion callbacks and leave through `writePackets`. This
//! adapter turns that into the same `Tun` contract as every other backend:
//!
//!   packetFlow.readPackets --deliver()--> [bounded queue + wake fd] --read()--> device loop
//!   device loop --write()--> write callback --> packetFlow.writePackets
//!
//! The wake handle is the read end of a non-blocking pipe (pipes are allowed
//! inside an extension), so the device loop still sleeps in one kqueue/poll
//! on {UDP sockets, this fd, next timer deadline}. No polling.
//!
//! Addresses and routes on iOS belong to NEPacketTunnelNetworkSettings,
//! which the Swift provider applies before starting the device; setAddress /
//! addRoute therefore return `error.Unsupported` (the device should treat
//! that as "configured by the host").
//!
//! The adapter itself is plain Zig over `queue.Channel`, so it is unit-tested
//! on every host; only the Swift glue below is iOS-specific.
//!
//! Swift glue (sketch; the C functions are `c_api` below, exported by the
//! host library that embeds this module):
//!
//!     // write callback: called on the device thread
//!     let writeCb: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UInt8) -> Void = {
//!         ctx, p, n, af in
//!         let flow = Unmanaged<NEPacketTunnelFlow>.fromOpaque(ctx!).takeUnretainedValue()
//!         flow.writePackets([Data(bytes: p!, count: n)], withProtocols: [NSNumber(value: Int32(af))])
//!     }
//!     let tun = zwg_packetflow_create(mtu, Unmanaged.passUnretained(packetFlow).toOpaque(), writeCb)
//!     func pump() {
//!         packetFlow.readPackets { packets, _ in
//!             for p in packets { p.withUnsafeBytes { zwg_packetflow_deliver(tun, $0.baseAddress, $0.count) } }
//!             pump()   // re-arm: completions are therefore serial (one producer)
//!         }
//!     }
const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const queue = @import("queue.zig");
const Cidr = @import("../ip.zig").Cidr;
const Tun = root.Tun;

/// AF_INET / AF_INET6 as Darwin numbers them (what writePackets expects).
pub const af_inet: u8 = 2;
pub const af_inet6: u8 = 30;

pub const WriteFn = *const fn (ctx: ?*anyopaque, packet: [*]const u8, len: usize, family: u8) callconv(.c) void;

pub const PacketFlowTun = struct {
    gpa: Allocator,
    inbound: queue.Channel,
    mtu_value: u16,
    write_fn: WriteFn,
    write_ctx: ?*anyopaque,
    /// Packets dropped because the queue was full (device loop too slow).
    dropped_inbound: std.atomic.Value(u64) = .init(0),

    pub const Options = struct {
        mtu: u16 = root.default_mtu,
        capacity: u32 = 256,
        write_fn: WriteFn,
        write_ctx: ?*anyopaque = null,
    };

    pub fn init(gpa: Allocator, options: Options) !PacketFlowTun {
        return .{
            .gpa = gpa,
            .inbound = try queue.Channel.init(gpa, options.capacity, options.mtu),
            .mtu_value = options.mtu,
            .write_fn = options.write_fn,
            .write_ctx = options.write_ctx,
        };
    }

    pub fn deinit(p: *PacketFlowTun) void {
        p.inbound.deinit(p.gpa);
        p.* = undefined;
    }

    pub fn tun(p: *PacketFlowTun) Tun {
        return .{ .ptr = p, .vtable = &vtable };
    }

    /// Producer side (the readPackets completion). Drops and counts when the
    /// queue is full or the packet exceeds the MTU.
    pub fn deliver(p: *PacketFlowTun, packet: []const u8) void {
        p.inbound.send(packet) catch {
            _ = p.dropped_inbound.fetchAdd(1, .monotonic);
        };
    }

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = unsupported,
        .addRoute = unsupported,
    };

    fn self(ptr: *anyopaque) *PacketFlowTun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) root.WaitHandle {
        return self(ptr).inbound.handle();
    }

    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        return self(ptr).inbound.recv(buf);
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const p = self(ptr);
        if (packet.len == 0) return error.InvalidPacket;
        if (packet.len > p.mtu_value) return error.PacketTooLarge;
        const family = switch (packet[0] >> 4) {
            4 => af_inet,
            6 => af_inet6,
            else => return error.InvalidPacket,
        };
        p.write_fn(p.write_ctx, packet.ptr, packet.len, family);
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).mtu_value;
    }

    fn unsupported(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        _ = ptr;
        _ = cidr;
        return error.Unsupported;
    }
};

/// C entry points for the Swift side. The host library that embeds this
/// module exports them (e.g. `comptime { @export(&c_api.create, .{ .name = "zwg_packetflow_create" }); }`)
/// so nothing is exported from a plain test or desktop build.
pub const c_api = struct {
    pub fn create(mtu: u16, ctx: ?*anyopaque, write_fn: WriteFn) callconv(.c) ?*PacketFlowTun {
        // iOS always links libc; elsewhere (host tests) avoid requiring it.
        const gpa = if (@import("builtin").link_libc) std.heap.c_allocator else std.heap.page_allocator;
        const p = gpa.create(PacketFlowTun) catch return null;
        p.* = PacketFlowTun.init(gpa, .{ .mtu = mtu, .write_fn = write_fn, .write_ctx = ctx }) catch {
            gpa.destroy(p);
            return null;
        };
        return p;
    }

    pub fn deliver(p: *PacketFlowTun, data: [*]const u8, len: usize) callconv(.c) void {
        p.deliver(data[0..len]);
    }

    pub fn destroy(p: *PacketFlowTun) callconv(.c) void {
        const gpa = p.gpa;
        p.deinit();
        gpa.destroy(p);
    }
};

test "packetflow adapter: deliver -> read, write -> callback with family" {
    const Sink = struct {
        var last_len: usize = 0;
        var last_family: u8 = 0;
        fn cb(ctx: ?*anyopaque, packet: [*]const u8, len: usize, family: u8) callconv(.c) void {
            _ = ctx;
            _ = packet;
            last_len = len;
            last_family = family;
        }
    };
    var p = try PacketFlowTun.init(std.testing.allocator, .{ .mtu = 1280, .capacity = 2, .write_fn = Sink.cb });
    defer p.deinit();
    const t = p.tun();
    var buf: [1280]u8 = undefined;

    p.deliver("\x45abc");
    try queue.waitReadable(t.waitHandle(), 1000);
    try std.testing.expectEqualStrings("\x45abc", (try t.read(&buf)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try t.read(&buf));

    p.deliver("1");
    p.deliver("2");
    p.deliver("3"); // dropped: capacity 2
    try std.testing.expectEqual(@as(u64, 1), p.dropped_inbound.load(.monotonic));

    try t.write("\x60\x00\x00\x00rest");
    try std.testing.expectEqual(@as(usize, 8), Sink.last_len);
    try std.testing.expectEqual(af_inet6, Sink.last_family);
    try std.testing.expectError(error.InvalidPacket, t.write("\x10"));
    try std.testing.expectError(error.Unsupported, t.setAddress(try Cidr.parse("10.0.0.1/32")));
}
