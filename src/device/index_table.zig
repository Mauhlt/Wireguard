//! Receiver-index table: the random 32-bit `sender_index` values this
//! device puts in its handshake messages, mapped back to the peer (and
//! whether the index names a handshake in progress or an installed
//! keypair). Every inbound response (type 2), cookie reply (type 3) and data
//! message (type 4) is routed by its `receiver_index` through here.
//!
//! Indices are drawn from a CSPRNG and never collide with a live one (the
//! kernel's index_hashtable_insert does the same). Size is bounded by the
//! peers: at most one handshake plus three keypairs per peer.

const std = @import("std");

pub const Kind = enum { handshake, keypair };

pub fn IndexTable(comptime PeerId: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct { peer: PeerId, kind: Kind };

        map: std.AutoHashMapUnmanaged(u32, Entry) = .empty,
        /// Hard cap (set from the peer count); inserts beyond it fail.
        limit: usize,

        pub fn init(limit: usize) Self {
            return .{ .limit = limit };
        }

        pub fn deinit(t: *Self, gpa: std.mem.Allocator) void {
            t.map.deinit(gpa);
            t.* = undefined;
        }

        /// Picks a fresh random index not in use and records `entry` for it.
        pub fn insert(t: *Self, gpa: std.mem.Allocator, rand: std.Random, entry: Entry) error{ OutOfMemory, TableFull }!u32 {
            if (t.map.count() >= t.limit) return error.TableFull;
            try t.map.ensureUnusedCapacity(gpa, 1);
            while (true) {
                const idx = rand.int(u32);
                const gop = t.map.getOrPutAssumeCapacity(idx);
                if (gop.found_existing) continue;
                gop.value_ptr.* = entry;
                return idx;
            }
        }

        pub fn get(t: *const Self, idx: u32) ?Entry {
            return t.map.get(idx);
        }

        /// Re-labels an index (a handshake's index becomes its keypair's,
        /// as in the kernel, where the keypair keeps the handshake's index).
        pub fn setKind(t: *Self, idx: u32, kind: Kind) void {
            if (t.map.getPtr(idx)) |e| e.kind = kind;
        }

        pub fn remove(t: *Self, idx: u32) void {
            _ = t.map.remove(idx);
        }

        pub fn removePeer(t: *Self, peer: PeerId) void {
            var it = t.map.iterator();
            var buf: [64]u32 = undefined;
            while (true) {
                var n: usize = 0;
                it = t.map.iterator();
                while (it.next()) |e| {
                    if (e.value_ptr.peer == peer) {
                        buf[n] = e.key_ptr.*;
                        n += 1;
                        if (n == buf.len) break;
                    }
                }
                if (n == 0) return;
                for (buf[0..n]) |k| _ = t.map.remove(k);
            }
        }

        /// The peer table was replaced: `moved[old id]` is each peer's new
        /// id, null for a removed peer (whose indices go).
        pub fn remap(t: *Self, moved: []const ?PeerId) void {
            var it = t.map.iterator();
            // Removing marks a tombstone; the iteration stays valid.
            while (it.next()) |e| {
                if (moved[e.value_ptr.peer]) |id| e.value_ptr.peer = id else t.map.removeByPtr(e.key_ptr);
            }
        }

        pub fn count(t: *const Self) usize {
            return t.map.count();
        }
    };
}

test "unique random indices, lookup, remove" {
    const gpa = std.testing.allocator;
    var t = IndexTable(u16).init(10_000);
    defer t.deinit(gpa);
    // A generator with a tiny range forces collisions; insert must skip
    // used values rather than overwrite them.
    const Tiny = struct {
        n: u32 = 0,
        fn fill(ctx: *anyopaque, buf: []u8) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.n +%= 1;
            const v: u32 = s.n % 5; // 0..4 only
            @memset(buf, 0);
            std.mem.writeInt(u32, buf[0..4], v, .little);
        }
    };
    var tiny: Tiny = .{};
    const r: std.Random = .{ .ptr = &tiny, .fillFn = Tiny.fill };
    var got: [5]u32 = undefined;
    for (&got, 0..) |*g, i| g.* = try t.insert(gpa, r, .{ .peer = @intCast(i), .kind = .handshake });
    std.mem.sort(u32, &got, {}, std.sort.asc(u32));
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4 }, &got);
    try std.testing.expectEqual(@as(u16, 2), t.get(3).?.peer); // draws were 1,2,3,4,0
    t.setKind(3, .keypair);
    try std.testing.expectEqual(Kind.keypair, t.get(3).?.kind);
    t.remove(3);
    try std.testing.expectEqual(@as(?IndexTable(u16).Entry, null), t.get(3));
    try std.testing.expectEqual(@as(u32, 3), try t.insert(gpa, r, .{ .peer = 9, .kind = .keypair }));
    t.removePeer(9);
    try std.testing.expectEqual(@as(usize, 4), t.count());
}

test "limit" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1);
    var t = IndexTable(u8).init(3);
    defer t.deinit(gpa);
    for (0..3) |_| _ = try t.insert(gpa, prng.random(), .{ .peer = 0, .kind = .keypair });
    try std.testing.expectError(error.TableFull, t.insert(gpa, prng.random(), .{ .peer = 0, .kind = .keypair }));
    t.removePeer(0);
    try std.testing.expectEqual(@as(usize, 0), t.count());
}

test "remap renumbers peers and drops removed ones" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(2);
    var t = IndexTable(u8).init(100);
    defer t.deinit(gpa);
    var idx: [6]u32 = undefined;
    for (&idx, 0..) |*x, i| x.* = try t.insert(gpa, prng.random(), .{ .peer = @intCast(i % 3), .kind = .keypair });
    // Peer 0 removed, 1 -> 0, 2 -> 1.
    t.remap(&.{ null, 0, 1 });
    try std.testing.expectEqual(@as(usize, 4), t.count());
    for (idx, 0..) |x, i| switch (i % 3) {
        0 => try std.testing.expectEqual(@as(?IndexTable(u8).Entry, null), t.get(x)),
        else => try std.testing.expectEqual(@as(u8, @intCast(i % 3 - 1)), t.get(x).?.peer),
    };
}
