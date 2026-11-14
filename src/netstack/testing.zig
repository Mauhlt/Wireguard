//! Test helpers shared by the unit tests, tests/netstack and the fuzz
//! targets: the one packet-crafting helper (a fake peer that builds and
//! parses IPv4/TCP packets with wire.zig) and `ImpairedTun`, a Tun
//! wrapper that drops / reorders / duplicates packets (seeded, so a run
//! is reproducible). Not used by the stack itself.
const std = @import("std");
const root = @import("root.zig");
const wire = @import("wire.zig");
const wg_tun = @import("../tun/root.zig");

const Endpoint = root.Endpoint;

/// A fake TCP peer: crafts packets from `peer` to `stack` (the stack under
/// test) and parses what the stack sends back.
pub const Peer = struct {
    peer: Endpoint,
    stack: Endpoint,
    ip_id: u16 = 0,

    /// Fields of a segment the test chooses; ports come from the endpoints.
    pub const Seg = struct {
        seq: u32,
        ack: u32 = 0,
        flags: wire.Flags,
        window: u16 = 65535,
        options: wire.TcpOptions = .{},
        payload: []const u8 = &.{},
    };

    /// A complete, valid IPv4/TCP packet peer -> stack in `out`.
    pub fn packet(p: *Peer, out: []u8, s: Seg) []u8 {
        p.ip_id +%= 1;
        return wire.buildTcp4(out, .{
            .protocol = wire.proto_tcp,
            .id = p.ip_id,
            .src = p.peer.addr.v4,
            .dst = p.stack.addr.v4,
        }, .{
            .src_port = p.peer.port,
            .dst_port = p.stack.port,
            .seq = s.seq,
            .ack = s.ack,
            .flags = s.flags,
            .window = s.window,
            .options = s.options,
            .payload = s.payload,
        }) catch @panic("testing.Peer.packet: buffer too small");
    }

    /// Parses a packet the stack sent and checks it is stack -> peer.
    pub fn expect(p: *const Peer, pkt: []const u8) !wire.Tcp {
        const t = try wire.parseTcp4(pkt);
        try std.testing.expectEqual(p.stack.addr.v4, t.ip.header.src);
        try std.testing.expectEqual(p.peer.addr.v4, t.ip.header.dst);
        try std.testing.expectEqual(p.stack.port, t.tcp.src_port);
        try std.testing.expectEqual(p.peer.port, t.tcp.dst_port);
        return t.tcp;
    }
};

/// Seeded per-direction impairment, in parts per million.
pub const Impairment = struct {
    loss_ppm: u32 = 0,
    /// Hold a packet back and release it after the next one.
    reorder_ppm: u32 = 0,
    duplicate_ppm: u32 = 0,
};

/// Wraps a Tun (normally `Stack.tun()`) and impairs both directions:
/// `inbound` applies to device -> stack (write), `outbound` to stack ->
/// device (read). Holds at most one packet per direction; event-driven
/// like the wrapped Tun (same wait handle).
pub const ImpairedTun = struct {
    inner: wg_tun.Tun,
    inbound: Impairment,
    outbound: Impairment,
    prng: std.Random.DefaultPrng,
    held_in: Held = .{},
    held_out: Held = .{},
    counts: Counts = .{},

    pub const Counts = struct { dropped: u64 = 0, reordered: u64 = 0, duplicated: u64 = 0, passed: u64 = 0 };

    const Held = struct {
        buf: [wg_tun.max_packet_size]u8 = undefined,
        len: ?usize = null,
    };

    pub fn init(inner: wg_tun.Tun, seed: u64, inbound: Impairment, outbound: Impairment) ImpairedTun {
        return .{ .inner = inner, .inbound = inbound, .outbound = outbound, .prng = .init(seed) };
    }

    pub fn tun(t: *ImpairedTun) wg_tun.Tun {
        return .{ .ptr = t, .vtable = &vtable };
    }

    fn hit(t: *ImpairedTun, ppm: u32) bool {
        return ppm != 0 and t.prng.random().uintLessThan(u32, 1_000_000) < ppm;
    }

    const vtable: wg_tun.Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = setAddress,
        .addRoute = addRoute,
    };

    fn self(ptr: *anyopaque) *ImpairedTun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) wg_tun.WaitHandle {
        return self(ptr).inner.waitHandle();
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).inner.mtu();
    }

    fn setAddress(ptr: *anyopaque, c: wg_tun.Cidr) wg_tun.ConfigError!void {
        return self(ptr).inner.setAddress(c);
    }

    fn addRoute(ptr: *anyopaque, c: wg_tun.Cidr) wg_tun.ConfigError!void {
        return self(ptr).inner.addRoute(c);
    }

    fn write(ptr: *anyopaque, packet: []const u8) wg_tun.WriteError!void {
        const t = self(ptr);
        if (t.hit(t.inbound.loss_ppm)) {
            t.counts.dropped += 1;
            return;
        }
        if (t.held_in.len == null and packet.len <= t.held_in.buf.len and t.hit(t.inbound.reorder_ppm)) {
            @memcpy(t.held_in.buf[0..packet.len], packet);
            t.held_in.len = packet.len;
            t.counts.reordered += 1;
            return;
        }
        t.counts.passed += 1;
        t.inner.write(packet) catch {};
        if (t.hit(t.inbound.duplicate_ppm)) {
            t.counts.duplicated += 1;
            t.inner.write(packet) catch {};
        }
        if (t.held_in.len) |n| {
            t.held_in.len = null;
            t.inner.write(t.held_in.buf[0..n]) catch {};
        }
    }

    fn read(ptr: *anyopaque, buf: []u8) wg_tun.ReadError!?[]u8 {
        const t = self(ptr);
        while (true) {
            const p = (try t.inner.read(buf)) orelse {
                // Nothing new: release a held packet rather than sit on it.
                if (t.held_out.len) |n| {
                    t.held_out.len = null;
                    if (n > buf.len) return error.BufferTooSmall;
                    @memcpy(buf[0..n], t.held_out.buf[0..n]);
                    return buf[0..n];
                }
                return null;
            };
            if (t.hit(t.outbound.loss_ppm)) {
                t.counts.dropped += 1;
                continue;
            }
            if (t.held_out.len == null and t.hit(t.outbound.reorder_ppm)) {
                @memcpy(t.held_out.buf[0..p.len], p);
                t.held_out.len = p.len;
                t.counts.reordered += 1;
                continue;
            }
            t.counts.passed += 1;
            return p;
        }
    }
};