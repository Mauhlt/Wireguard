//! Cryptokey routing table: allowed IPs -> peer, longest-prefix match, one
//! path-compressed binary trie per address family (the kernel's
//! allowedips.c is the same shape).
//!
//! Outbound, `lookup(dst)` picks the peer to encrypt for. Inbound, after
//! decryption, `lookup(src) == peer` is the source check. Inserting a prefix
//! that already exists moves it to the new peer, like the kernel.
//!
//! Memory: one node per prefix plus at most one branch node per prefix; all
//! growth comes from configuration, never from network input.

const std = @import("std");
const ip = @import("../ip.zig");

pub fn AllowedIps(comptime V: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            key: [16]u8, // masked to `cidr` bits
            cidr: u8,
            value: ?V,
            child: [2]?*Node = .{ null, null },
        };

        gpa: std.mem.Allocator,
        root4: ?*Node = null,
        root6: ?*Node = null,

        pub fn init(gpa: std.mem.Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(t: *Self) void {
            t.freeTree(t.root4);
            t.freeTree(t.root6);
            t.* = undefined;
        }

        fn freeTree(t: *Self, n: ?*Node) void {
            const node = n orelse return;
            t.freeTree(node.child[0]);
            t.freeTree(node.child[1]);
            t.gpa.destroy(node);
        }

        fn rootFor(t: *Self, f: ip.Family) *?*Node {
            return switch (f) {
                .v4 => &t.root4,
                .v6 => &t.root6,
            };
        }

        fn toKey(a: ip.Addr) [16]u8 {
            var k: [16]u8 = @splat(0);
            const b = a.bytes();
            @memcpy(k[0..b.len], b);
            return k;
        }

        /// Adds (or reassigns) `cidr` to `value`. Host bits are ignored.
        pub fn insert(t: *Self, cidr: ip.Cidr, value: V) error{OutOfMemory}!void {
            const m = cidr.masked();
            const key = toKey(m.addr);
            const bits = m.prefix;
            var slot = t.rootFor(m.addr);
            while (slot.*) |node| {
                const common = ip.commonPrefix(&node.key, &key, @min(node.cidr, bits));
                if (common == node.cidr) {
                    if (node.cidr == bits) {
                        node.value = value;
                        return;
                    }
                    // `node` is a prefix of the new one: descend.
                    slot = &node.child[ip.bitAt(&key, node.cidr)];
                    continue;
                }
                const new = try t.gpa.create(Node);
                new.* = .{ .key = key, .cidr = bits, .value = value };
                if (common == bits) {
                    // The new prefix contains `node`.
                    new.child[ip.bitAt(&node.key, bits)] = node;
                    slot.* = new;
                    return;
                }
                // Diverge below `common`: a branch node holds both.
                const mid = t.gpa.create(Node) catch |err| {
                    t.gpa.destroy(new);
                    return err;
                };
                var mk = key;
                ip.maskBytes(&mk, common);
                mid.* = .{ .key = mk, .cidr = common, .value = null };
                mid.child[ip.bitAt(&node.key, common)] = node;
                mid.child[ip.bitAt(&key, common)] = new;
                slot.* = mid;
                return;
            }
            const leaf = try t.gpa.create(Node);
            leaf.* = .{ .key = key, .cidr = bits, .value = value };
            slot.* = leaf;
        }

        /// The value of exactly `cidr` (host bits ignored), if it is in
        /// the table.
        pub fn exact(t: *const Self, cidr: ip.Cidr) ?V {
            const m = cidr.masked();
            const key = toKey(m.addr);
            var n = switch (m.addr) {
                .v4 => t.root4,
                .v6 => t.root6,
            };
            while (n) |node| {
                if (node.cidr > m.prefix or ip.commonPrefix(&node.key, &key, node.cidr) < node.cidr) return null;
                if (node.cidr == m.prefix) return node.value;
                n = node.child[ip.bitAt(&key, node.cidr)];
            }
            return null;
        }

        /// The value of the longest prefix containing `addr`.
        pub fn lookup(t: *const Self, addr: ip.Addr) ?V {
            const key = toKey(addr);
            const max = addr.bits();
            var n = switch (addr) {
                .v4 => t.root4,
                .v6 => t.root6,
            };
            var best: ?V = null;
            while (n) |node| {
                if (ip.commonPrefix(&node.key, &key, node.cidr) < node.cidr) break;
                if (node.value) |v| best = v;
                if (node.cidr >= max) break;
                n = node.child[ip.bitAt(&key, node.cidr)];
            }
            return best;
        }

        /// Removes the exact prefix (whatever peer it belongs to).
        /// Returns whether it existed.
        pub fn remove(t: *Self, cidr: ip.Cidr) bool {
            const m = cidr.masked();
            const key = toKey(m.addr);
            var path: [130]*?*Node = undefined;
            var depth: usize = 0;
            var slot = t.rootFor(m.addr);
            while (slot.*) |node| {
                if (ip.commonPrefix(&node.key, &key, node.cidr) < node.cidr or node.cidr > m.prefix) return false;
                path[depth] = slot;
                depth += 1;
                if (node.cidr == m.prefix) {
                    if (node.value == null) return false;
                    node.value = null;
                    // Prune bottom-up: the emptied node, then branch nodes
                    // left with a single child.
                    while (depth > 0) {
                        depth -= 1;
                        t.compactOne(path[depth]);
                    }
                    return true;
                }
                slot = &node.child[ip.bitAt(&key, node.cidr)];
            }
            return false;
        }

        /// Removes every prefix that maps to `value`.
        pub fn removeValue(t: *Self, value: V) void {
            t.removeIn(&t.root4, value);
            t.removeIn(&t.root6, value);
        }

        fn removeIn(t: *Self, slot: *?*Node, value: V) void {
            const node = slot.* orelse return;
            t.removeIn(&node.child[0], value);
            t.removeIn(&node.child[1], value);
            if (node.value) |v| {
                if (v == value) node.value = null;
            }
            t.compactOne(slot);
        }

        /// Drops the node at `slot` if it carries no value and has at most
        /// one child (the child takes its place).
        fn compactOne(t: *Self, slot: *?*Node) void {
            const node = slot.* orelse return;
            if (node.value != null) return;
            const c0 = node.child[0];
            const c1 = node.child[1];
            if (c0 != null and c1 != null) return;
            slot.* = c0 orelse c1;
            t.gpa.destroy(node);
        }

        pub const Entry = struct { cidr: ip.Cidr, value: V };

        /// Calls `f(ctx, entry)` for every prefix, shortest first within a
        /// branch (order is stable for a given table).
        pub fn forEach(t: *const Self, ctx: anytype, comptime f: fn (@TypeOf(ctx), Entry) void) void {
            walk(t.root4, .v4, ctx, f);
            walk(t.root6, .v6, ctx, f);
        }

        fn walk(n: ?*Node, fam: ip.Family, ctx: anytype, comptime f: fn (@TypeOf(ctx), Entry) void) void {
            const node = n orelse return;
            if (node.value) |v| {
                const addr: ip.Addr = switch (fam) {
                    .v4 => .{ .v4 = node.key[0..4].* },
                    .v6 => .{ .v6 = node.key },
                };
                f(ctx, .{ .cidr = .{ .addr = addr, .prefix = node.cidr }, .value = v });
            }
            walk(node.child[0], fam, ctx, f);
            walk(node.child[1], fam, ctx, f);
        }

        /// Number of nodes (prefix + branch), for tests and bounds.
        pub fn nodeCount(t: *const Self) usize {
            return count(t.root4) + count(t.root6);
        }

        fn count(n: ?*Node) usize {
            const node = n orelse return 0;
            return 1 + count(node.child[0]) + count(node.child[1]);
        }
    };
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;
const Table = AllowedIps(u32);

fn cidrOf(s: []const u8) ip.Cidr {
    return ip.Cidr.parse(s) catch unreachable;
}
fn addrOf(s: []const u8) ip.Addr {
    return ip.Addr.parse(s) catch unreachable;
}

test "longest prefix match, IPv4 and IPv6, defaults" {
    var t = Table.init(testing.allocator);
    defer t.deinit();
    try t.insert(cidrOf("10.8.0.0/24"), 1);
    try t.insert(cidrOf("10.8.0.2/32"), 2);
    try t.insert(cidrOf("10.8.0.3/32"), 3);
    try t.insert(cidrOf("10.0.0.0/8"), 4);
    try t.insert(cidrOf("0.0.0.0/0"), 5);
    try t.insert(cidrOf("fd00::/64"), 6);
    try t.insert(cidrOf("fd00::1/128"), 7);
    try t.insert(cidrOf("::/0"), 8);

    try testing.expectEqual(@as(?u32, 2), t.lookup(addrOf("10.8.0.2")));
    try testing.expectEqual(@as(?u32, 3), t.lookup(addrOf("10.8.0.3")));
    try testing.expectEqual(@as(?u32, 1), t.lookup(addrOf("10.8.0.4")));
    try testing.expectEqual(@as(?u32, 4), t.lookup(addrOf("10.9.0.1")));
    try testing.expectEqual(@as(?u32, 5), t.lookup(addrOf("192.168.1.1")));
    try testing.expectEqual(@as(?u32, 7), t.lookup(addrOf("fd00::1")));
    try testing.expectEqual(@as(?u32, 6), t.lookup(addrOf("fd00::2")));
    try testing.expectEqual(@as(?u32, 8), t.lookup(addrOf("2001:db8::1")));
    // Families never mix: ::ffff:10.8.0.2 is an IPv6 address.
    try testing.expectEqual(@as(?u32, 8), t.lookup(addrOf("::ffff:10.8.0.2")));

    const before = t.nodeCount();
    try testing.expect(t.remove(cidrOf("0.0.0.0/0")));
    try testing.expect(!t.remove(cidrOf("0.0.0.0/0")));
    try testing.expect(!t.remove(cidrOf("10.8.0.0/23")));
    try testing.expect(t.nodeCount() < before);
    try testing.expect(t.remove(cidrOf("10.8.0.3/32")));
    try testing.expectEqual(@as(?u32, 1), t.lookup(addrOf("10.8.0.3")));
    try testing.expectEqual(@as(?u32, null), t.lookup(addrOf("192.168.1.1")));
    try testing.expectEqual(@as(?u32, 4), t.lookup(addrOf("10.1.2.3")));
}

test "reinsert moves a prefix; host bits ignored; empty table" {
    var t = Table.init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(?u32, null), t.lookup(addrOf("1.2.3.4")));
    try t.insert(cidrOf("10.8.0.2/32"), 1);
    try t.insert(cidrOf("10.8.0.2/32"), 2);
    try testing.expectEqual(@as(?u32, 2), t.lookup(addrOf("10.8.0.2")));
    try t.insert(cidrOf("192.168.7.9/16"), 3);
    try testing.expectEqual(@as(?u32, 3), t.lookup(addrOf("192.168.200.1")));
    try testing.expectEqual(@as(usize, 3), t.nodeCount());
}

test "remove by peer prunes the trie" {
    var t = Table.init(testing.allocator);
    defer t.deinit();
    try t.insert(cidrOf("10.8.0.2/32"), 1);
    try t.insert(cidrOf("10.8.0.3/32"), 2);
    try t.insert(cidrOf("10.8.0.0/24"), 1);
    try t.insert(cidrOf("fd00::2/128"), 1);
    try t.insert(cidrOf("0.0.0.0/0"), 2);
    t.removeValue(1);
    try testing.expectEqual(@as(?u32, 2), t.lookup(addrOf("10.8.0.2")));
    try testing.expectEqual(@as(?u32, 2), t.lookup(addrOf("10.8.0.3")));
    try testing.expectEqual(@as(?u32, null), t.lookup(addrOf("fd00::2")));
    try testing.expectEqual(@as(usize, 2), t.nodeCount());
    t.removeValue(2);
    try testing.expectEqual(@as(usize, 0), t.nodeCount());
}

test "overlapping prefixes against a brute-force reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var t = Table.init(testing.allocator);
    defer t.deinit();
    const Ref = struct { cidr: ip.Cidr, v: u32 };
    var ref: std.ArrayList(Ref) = .empty;
    defer ref.deinit(testing.allocator);

    // Prefixes clustered in a small space so they overlap a lot.
    for (0..600) |i| {
        const v6 = r.boolean();
        const prefix: u8 = if (v6) r.uintAtMost(u8, 128) else r.uintAtMost(u8, 32);
        var addr: ip.Addr = if (v6) .{ .v6 = @splat(0) } else .{ .v4 = @splat(0) };
        switch (addr) {
            .v4 => |*b| {
                b[0] = 10;
                b[1] = r.uintAtMost(u8, 3);
                b[2] = r.int(u8) & 0xf0;
                b[3] = r.int(u8);
            },
            .v6 => |*b| {
                b[0] = 0xfd;
                b[1] = r.uintAtMost(u8, 1);
                b[14] = r.int(u8);
                b[15] = r.int(u8);
            },
        }
        const cidr = (ip.Cidr{ .addr = addr, .prefix = prefix }).masked();
        const v: u32 = @intCast(i % 7);
        try t.insert(cidr, v);
        var replaced = false;
        for (ref.items) |*e| if (e.cidr.eql(cidr)) {
            e.v = v;
            replaced = true;
        };
        if (!replaced) try ref.append(testing.allocator, .{ .cidr = cidr, .v = v });

        if (i % 100 == 99) {
            // Drop one peer's prefixes now and then.
            const gone: u32 = r.uintAtMost(u32, 6);
            t.removeValue(gone);
            var j: usize = 0;
            while (j < ref.items.len) {
                if (ref.items[j].v == gone) _ = ref.swapRemove(j) else j += 1;
            }
        }
    }
    for (0..5000) |_| {
        const v6 = r.boolean();
        var addr: ip.Addr = if (v6) .{ .v6 = @splat(0) } else .{ .v4 = @splat(0) };
        switch (addr) {
            .v4 => |*b| {
                b[0] = if (r.uintAtMost(u8, 9) == 0) r.int(u8) else 10;
                b[1] = r.uintAtMost(u8, 3);
                b[2] = r.int(u8);
                b[3] = r.int(u8);
            },
            .v6 => |*b| {
                b[0] = 0xfd;
                b[1] = r.uintAtMost(u8, 1);
                b[14] = r.int(u8);
                b[15] = r.int(u8);
            },
        }
        var best: ?u32 = null;
        var best_len: i16 = -1;
        for (ref.items) |e| {
            if (e.cidr.contains(addr) and e.cidr.prefix > best_len) {
                best = e.v;
                best_len = e.cidr.prefix;
            }
        }
        try testing.expectEqual(best, t.lookup(addr));
    }
    // Node count stays within 2 per prefix.
    try testing.expect(t.nodeCount() <= 2 * ref.items.len);
}

test "exact finds only the very prefix" {
    var t = Table.init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("10.8.0.0/24")));
    try t.insert(cidrOf("10.8.0.0/24"), 1);
    try t.insert(cidrOf("10.8.0.2/32"), 2);
    try t.insert(cidrOf("10.8.4.0/24"), 3); // a branch node at /21
    try t.insert(cidrOf("fd00::/64"), 4);
    try testing.expectEqual(@as(?u32, 1), t.exact(cidrOf("10.8.0.77/24")));
    try testing.expectEqual(@as(?u32, 2), t.exact(cidrOf("10.8.0.2/32")));
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("10.8.0.3/32")));
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("10.8.0.0/23")));
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("10.8.0.0/21"))); // branch only
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("10.0.0.0/8")));
    try testing.expectEqual(@as(?u32, 4), t.exact(cidrOf("fd00::1/64")));
    try testing.expectEqual(@as(?u32, null), t.exact(cidrOf("fd00::/63")));
}

test "forEach lists entries" {
    var t = Table.init(testing.allocator);
    defer t.deinit();
    try t.insert(cidrOf("10.8.0.2/32"), 1);
    try t.insert(cidrOf("::/0"), 1);
    try t.insert(cidrOf("10.8.0.3/32"), 2);
    var n: usize = 0;
    const Ctx = struct {
        n: *usize,
        fn f(ctx: @This(), e: Table.Entry) void {
            if (e.value == 1) ctx.n.* += 1;
        }
    };
    t.forEach(Ctx{ .n = &n }, Ctx.f);
    try testing.expectEqual(@as(usize, 2), n);
}
