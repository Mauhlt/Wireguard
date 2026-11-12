//! Anti-replay sliding window for transport counters (RFC 6479 §2 bitmap
//! ring), identical in behaviour to wireguard-go `replay.Filter` and the
//! Linux kernel `counter_validate` (receive.c):
//!
//! * the ring holds COUNTER_BITS_TOTAL = 8192 bits as 128 u64 blocks;
//! * the usable window is COUNTER_WINDOW_SIZE = 8192 − 64 = 8128 counters
//!   behind the highest counter seen (one block is always "redundant" so that
//!   advancing never has to clear the block that is currently in use);
//! * a counter is rejected if it is ≥ REJECT_AFTER_MESSAGES, more than
//!   COUNTER_WINDOW_SIZE behind the highest, or already seen.
//!
//! Only `update` mutates. The receive path calls `check` before decryption
//! (cheap early drop) and `update` only after the AEAD tag verified, so an
//! attacker cannot advance the window with forged packets.
//! Not thread-safe: one owner (the device's event loop).

const std = @import("std");
const c = @import("constants.zig");

const block_bits = 64;
const block_bit_log = 6;
const ring_blocks: u64 = c.COUNTER_BITS_TOTAL / block_bits; // 128
const block_mask: u64 = ring_blocks - 1;
const bit_mask: u64 = block_bits - 1;

comptime {
    std.debug.assert(ring_blocks == 128);
    std.debug.assert((ring_blocks - 1) * block_bits == c.COUNTER_WINDOW_SIZE);
}

pub const ReplayWindow = struct {
    /// Highest counter accepted so far (0 before any packet).
    last: u64 = 0,
    ring: [ring_blocks]u64 = @splat(0),

    /// Would `counter` be accepted? Does not modify the window.
    pub fn check(self: *const ReplayWindow, counter: u64) bool {
        if (counter >= c.REJECT_AFTER_MESSAGES) return false;
        if (counter > self.last) return true;
        if (self.last - counter > c.COUNTER_WINDOW_SIZE) return false;
        const block = (counter >> block_bit_log) & block_mask;
        const bit: u64 = @as(u64, 1) << @intCast(counter & bit_mask);
        return self.ring[block] & bit == 0;
    }

    /// Accept `counter` and mark it seen, or return false (replayed, too old,
    /// or beyond REJECT_AFTER_MESSAGES). Call only for authenticated packets.
    pub fn update(self: *ReplayWindow, counter: u64) bool {
        if (counter >= c.REJECT_AFTER_MESSAGES) return false;
        var index_block = counter >> block_bit_log;
        if (counter > self.last) {
            // Move the window forward, clearing the blocks we skip over (at
            // most the whole ring).
            const current = self.last >> block_bit_log;
            const diff = @min(index_block - current, ring_blocks);
            var i: u64 = current + 1;
            while (i <= current + diff) : (i += 1) self.ring[i & block_mask] = 0;
            self.last = counter;
        } else if (self.last - counter > c.COUNTER_WINDOW_SIZE) {
            return false;
        }
        index_block &= block_mask;
        const bit: u64 = @as(u64, 1) << @intCast(counter & bit_mask);
        const old = self.ring[index_block];
        self.ring[index_block] = old | bit;
        return old & bit == 0;
    }

    pub fn reset(self: *ReplayWindow) void {
        self.* = .{};
    }
};

const testing = std.testing;
const W = c.COUNTER_WINDOW_SIZE;

test "in-order sequence accepted once" {
    var w: ReplayWindow = .{};
    var i: u64 = 0;
    while (i < 20000) : (i += 1) {
        try testing.expect(w.check(i));
        try testing.expect(w.update(i));
        try testing.expect(!w.check(i));
        try testing.expect(!w.update(i));
    }
}

test "counter 0 then duplicate" {
    var w: ReplayWindow = .{};
    try testing.expect(w.update(0));
    try testing.expect(!w.update(0));
    try testing.expect(w.update(1));
    try testing.expect(!w.update(0));
}

test "out of order within window" {
    var w: ReplayWindow = .{};
    try testing.expect(w.update(100));
    try testing.expect(w.update(50));
    try testing.expect(w.update(99));
    try testing.expect(!w.update(50));
    try testing.expect(w.update(0));
    try testing.expect(!w.update(100));
}

test "window boundary: exactly WINDOW behind accepted, WINDOW+1 rejected" {
    var w: ReplayWindow = .{};
    const top: u64 = W + 1000;
    try testing.expect(w.update(top));
    try testing.expect(!w.check(top - W - 1));
    try testing.expect(!w.update(top - W - 1));
    try testing.expect(w.check(top - W));
    try testing.expect(w.update(top - W));
    try testing.expect(!w.update(top - W));
    try testing.expect(w.update(top - 1));
}

test "every counter in the window accepted exactly once (reverse order)" {
    var w: ReplayWindow = .{};
    const top: u64 = 3 * W + 17;
    try testing.expect(w.update(top));
    var k: u64 = 1;
    while (k <= W) : (k += 1) try testing.expect(w.update(top - k));
    k = 0;
    while (k <= W) : (k += 1) try testing.expect(!w.update(top - k));
    try testing.expect(!w.update(top - W - 1));
}

test "large jump clears whole ring" {
    var w: ReplayWindow = .{};
    var i: u64 = 0;
    while (i < 200) : (i += 1) try testing.expect(w.update(i));
    const far: u64 = 1 << 40;
    try testing.expect(w.update(far));
    // Old counters are now far out of window.
    try testing.expect(!w.update(5));
    // Counters just behind `far` in the same ring slots as old ones are fresh.
    try testing.expect(w.update(far - 1));
    try testing.expect(w.update(far - 64));
    try testing.expect(w.update(far - W));
    try testing.expect(!w.update(far - W - 1));
}

test "jump by exactly one ring and by partial ring" {
    var w: ReplayWindow = .{};
    try testing.expect(w.update(10));
    try testing.expect(w.update(10 + c.COUNTER_BITS_TOTAL)); // same ring slot, new lap
    try testing.expect(!w.update(10)); // out of window
    try testing.expect(w.update(10 + c.COUNTER_BITS_TOTAL - 64)); // block reused, cleared
    var w2: ReplayWindow = .{};
    try testing.expect(w2.update(63));
    try testing.expect(w2.update(64)); // next block
    try testing.expect(!w2.update(63));
    try testing.expect(w2.update(62));
}

test "REJECT_AFTER_MESSAGES boundary" {
    var w: ReplayWindow = .{};
    const lim = c.REJECT_AFTER_MESSAGES;
    try testing.expect(!w.check(lim));
    try testing.expect(!w.update(lim));
    try testing.expect(!w.update(std.math.maxInt(u64)));
    try testing.expect(w.update(lim - 1));
    try testing.expect(!w.update(lim - 1));
    try testing.expect(w.update(lim - 2));
    try testing.expect(w.update(lim - 1 - W));
    try testing.expect(!w.update(lim - 2 - W));
}

test "reset" {
    var w: ReplayWindow = .{};
    try testing.expect(w.update(7));
    w.reset();
    try testing.expect(w.update(7));
}

test "randomised against a reference model" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var w: ReplayWindow = .{};
    // Reference: set of seen counters (bounded) and highest.
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(testing.allocator);
    var highest: ?u64 = null;
    var n: usize = 0;
    while (n < 50000) : (n += 1) {
        const base = highest orelse 0;
        const delta = r.intRangeAtMost(i64, -9000, 300);
        const ctr: u64 = if (delta < 0)
            (if (@as(u64, @intCast(-delta)) > base) 0 else base - @as(u64, @intCast(-delta)))
        else
            base + @as(u64, @intCast(delta));
        const too_old = if (highest) |h| (ctr < h and h - ctr > W) else false;
        const expect_ok = !too_old and !seen.contains(ctr);
        try testing.expectEqual(expect_ok, w.check(ctr));
        try testing.expectEqual(expect_ok, w.update(ctr));
        if (expect_ok) {
            try seen.put(testing.allocator, ctr, {});
            if (highest == null or ctr > highest.?) highest = ctr;
        }
    }
}
