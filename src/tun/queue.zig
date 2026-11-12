//! Bounded single-producer / single-consumer packet queue plus an OS-level
//! wake handle, used by `FakeTun` (tests) and the iOS packetFlow adapter.
//!
//! The consumer is the device's event loop: it waits on `Channel.handle()`
//! together with its sockets and its next timer deadline, then calls `recv`
//! until it returns null. The producer may live on another thread (iOS
//! packetFlow callbacks, a test driver). No polling anywhere: an empty queue
//! means the handle is (eventually) unsignaled and the loop sleeps.
//!
//! Wake protocol (`signaled` flag + handle):
//!   producer: push; if signaled.swap(true) == false -> signal handle
//!   consumer, on empty: clear handle; signaled.store(false); re-check queue
//! A producer that pushes before the consumer's store is seen by the re-check;
//! one that pushes after it signals the handle again. Spurious wakeups are
//! possible and harmless (recv just returns null).
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const root = @import("root.zig");
const WaitHandle = root.WaitHandle;

/// Fixed-slot SPSC ring. Memory is allocated once in `init` (capacity *
/// slot_size bytes); nothing grows afterwards.
pub const PacketRing = struct {
    storage: []u8,
    lens: []u32,
    slot_size: u32,
    mask: u32,
    /// Next slot to read (consumer-owned).
    head: Atomic(u32) = .init(0),
    /// Next slot to write (producer-owned).
    tail: Atomic(u32) = .init(0),

    pub const PushError = error{ QueueFull, PacketTooLarge };

    /// `capacity` is rounded up to a power of two.
    pub fn init(gpa: Allocator, min_capacity: u32, slot_size: u32) Allocator.Error!PacketRing {
        std.debug.assert(min_capacity > 0 and slot_size > 0);
        const cap = std.math.ceilPowerOfTwoAssert(u32, min_capacity);
        const storage = try gpa.alloc(u8, @as(usize, cap) * slot_size);
        errdefer gpa.free(storage);
        const lens = try gpa.alloc(u32, cap);
        return .{ .storage = storage, .lens = lens, .slot_size = slot_size, .mask = cap - 1 };
    }

    pub fn deinit(r: *PacketRing, gpa: Allocator) void {
        gpa.free(r.storage);
        gpa.free(r.lens);
        r.* = undefined;
    }

    pub fn capacity(r: *const PacketRing) u32 {
        return r.mask + 1;
    }

    /// Producer side.
    pub fn push(r: *PacketRing, packet: []const u8) PushError!void {
        if (packet.len > r.slot_size) return error.PacketTooLarge;
        const tail = r.tail.raw; // only the producer writes tail
        const head = r.head.load(.acquire);
        if (tail -% head > r.mask) return error.QueueFull;
        const i = tail & r.mask;
        @memcpy(r.slot(i)[0..packet.len], packet);
        r.lens[i] = @intCast(packet.len);
        r.tail.store(tail +% 1, .release);
    }

    /// Consumer side. Copies the oldest packet into `out`. A packet longer
    /// than `out` is dropped and reported as `error.BufferTooSmall`.
    pub fn pop(r: *PacketRing, out: []u8) error{BufferTooSmall}!?[]u8 {
        const head = r.head.raw; // only the consumer writes head
        const tail = r.tail.load(.acquire);
        if (head == tail) return null;
        const i = head & r.mask;
        const n = r.lens[i];
        defer r.head.store(head +% 1, .release);
        if (n > out.len) return error.BufferTooSmall;
        @memcpy(out[0..n], r.slot(i)[0..n]);
        return out[0..n];
    }

    pub fn isEmpty(r: *PacketRing) bool {
        return r.head.load(.acquire) == r.tail.load(.acquire);
    }

    fn slot(r: *PacketRing, i: u32) []u8 {
        const start = @as(usize, i) * r.slot_size;
        return r.storage[start..][0..r.slot_size];
    }
};

/// An OS object the event loop can wait on: a manual-reset event on Windows,
/// the read end of a non-blocking pipe elsewhere.
pub const Waker = struct {
    handle: WaitHandle,
    /// POSIX only: write end of the pipe.
    write_fd: if (builtin.os.tag == .windows) void else std.posix.fd_t,

    pub const InitError = error{SystemResources};

    pub fn init() InitError!Waker {
        if (builtin.os.tag == .windows) {
            const h = win.CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
            return .{ .handle = h, .write_fd = {} };
        } else {
            const fds = try posixPipe();
            return .{ .handle = fds[0], .write_fd = fds[1] };
        }
    }

    pub fn deinit(w: *Waker) void {
        if (builtin.os.tag == .windows) {
            std.os.windows.CloseHandle(w.handle);
        } else {
            _ = std.posix.system.close(w.handle);
            _ = std.posix.system.close(w.write_fd);
        }
        w.* = undefined;
    }

    /// Make the handle ready.
    pub fn signal(w: *Waker) void {
        if (builtin.os.tag == .windows) {
            _ = win.SetEvent(w.handle);
        } else {
            const one = [1]u8{1};
            // EAGAIN means the pipe is already full of wakeups: fine.
            _ = std.posix.system.write(w.write_fd, &one, 1);
        }
    }

    /// Make the handle not ready.
    pub fn clear(w: *Waker) void {
        if (builtin.os.tag == .windows) {
            _ = win.ResetEvent(w.handle);
        } else {
            var buf: [64]u8 = undefined;
            while (true) {
                const n = std.posix.read(w.handle, &buf) catch return;
                if (n < buf.len) return;
            }
        }
    }

    /// Test helper: is the handle ready right now? (Zero-timeout check.)
    pub fn isSignaled(w: *Waker) bool {
        if (builtin.os.tag == .windows) {
            return win.WaitForSingleObject(w.handle, 0) == win.WAIT_OBJECT_0;
        } else {
            var pfd = [1]std.posix.pollfd{.{ .fd = w.handle, .events = std.posix.POLL.IN, .revents = 0 }};
            const n = std.posix.poll(&pfd, 0) catch return false;
            return n > 0;
        }
    }

    fn posixPipe() InitError![2]std.posix.fd_t {
        var fds: [2]std.posix.fd_t = undefined;
        if (builtin.os.tag == .linux and !builtin.link_libc) {
            const linux = std.os.linux;
            if (linux.errno(linux.pipe2(&fds, .{ .NONBLOCK = true, .CLOEXEC = true })) != .SUCCESS)
                return error.SystemResources;
            return fds;
        }
        const c = std.c;
        if (c.pipe(&fds) != 0) return error.SystemResources;
        const nonblock: c_int = @bitCast(@as(u32, @bitCast(c.O{ .NONBLOCK = true })));
        for (fds) |fd| {
            if (c.fcntl(fd, c.F.SETFL, nonblock) == -1 or c.fcntl(fd, c.F.SETFD, @as(c_int, 1)) == -1) {
                _ = c.close(fds[0]);
                _ = c.close(fds[1]);
                return error.SystemResources;
            }
        }
        return fds;
    }
};

/// Ring + waker + the wake protocol described at the top of this file.
pub const Channel = struct {
    ring: PacketRing,
    waker: Waker,
    signaled: Atomic(bool) = .init(false),

    pub fn init(gpa: Allocator, capacity: u32, slot_size: u32) (Allocator.Error || Waker.InitError)!Channel {
        var ring = try PacketRing.init(gpa, capacity, slot_size);
        errdefer ring.deinit(gpa);
        return .{ .ring = ring, .waker = try Waker.init() };
    }

    pub fn deinit(ch: *Channel, gpa: Allocator) void {
        ch.ring.deinit(gpa);
        ch.waker.deinit();
        ch.* = undefined;
    }

    pub fn handle(ch: *const Channel) WaitHandle {
        return ch.waker.handle;
    }

    /// Producer side.
    pub fn send(ch: *Channel, packet: []const u8) PacketRing.PushError!void {
        try ch.ring.push(packet);
        if (!ch.signaled.swap(true, .seq_cst)) ch.waker.signal();
    }

    /// Consumer side: next packet, or null when empty (then wait on handle()).
    pub fn recv(ch: *Channel, out: []u8) error{BufferTooSmall}!?[]u8 {
        if (try ch.ring.pop(out)) |p| return p;
        ch.waker.clear();
        ch.signaled.store(false, .seq_cst);
        return ch.ring.pop(out);
    }
};

/// Minimal kernel32 surface for the Windows waker (std no longer declares it).
pub const win = struct {
    const HANDLE = std.os.windows.HANDLE;
    pub extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual_reset: c_int, initial: c_int, name: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
    pub extern "kernel32" fn SetEvent(h: HANDLE) callconv(.winapi) c_int;
    pub extern "kernel32" fn ResetEvent(h: HANDLE) callconv(.winapi) c_int;
    pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: u32) callconv(.winapi) u32;
    pub extern "kernel32" fn WaitForMultipleObjects(n: u32, handles: [*]const HANDLE, wait_all: c_int, ms: u32) callconv(.winapi) u32;
    pub const INFINITE: u32 = 0xFFFF_FFFF;
    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 258;
};

/// Block until `h` is ready or `timeout_ms` passes (tests and simple drivers;
/// the real device waits on all its handles at once).
pub fn waitReadable(h: WaitHandle, timeout_ms: u32) error{Timeout}!void {
    if (builtin.os.tag == .windows) {
        if (win.WaitForSingleObject(h, timeout_ms) != win.WAIT_OBJECT_0) return error.Timeout;
    } else {
        var pfd = [1]std.posix.pollfd{.{ .fd = h, .events = std.posix.POLL.IN, .revents = 0 }};
        const n = std.posix.poll(&pfd, @intCast(timeout_ms)) catch return error.Timeout;
        if (n == 0) return error.Timeout;
    }
}

test "ring push/pop order, full, too large" {
    const gpa = std.testing.allocator;
    var r = try PacketRing.init(gpa, 3, 8); // rounds to 4
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 4), r.capacity());
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try r.pop(&out));
    for (0..4) |i| try r.push(&.{@intCast(i)});
    try std.testing.expectError(error.QueueFull, r.push("x"));
    try std.testing.expectError(error.PacketTooLarge, r.push("123456789"));
    for (0..4) |i| try std.testing.expectEqualSlices(u8, &.{@intCast(i)}, (try r.pop(&out)).?);
    try std.testing.expect(r.isEmpty());
    // wraparound
    for (0..10) |i| {
        try r.push(&.{ @intCast(i), 7 });
        try std.testing.expectEqualSlices(u8, &.{ @intCast(i), 7 }, (try r.pop(&out)).?);
    }
    try r.push("12345678");
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, r.pop(&small));
    try std.testing.expect(r.isEmpty()); // dropped
}

test "channel wake protocol" {
    const gpa = std.testing.allocator;
    var ch = try Channel.init(gpa, 4, 64);
    defer ch.deinit(gpa);
    var out: [64]u8 = undefined;
    try std.testing.expect(!ch.waker.isSignaled());
    try ch.send("a");
    try ch.send("b");
    try std.testing.expect(ch.waker.isSignaled());
    try std.testing.expectEqualStrings("a", (try ch.recv(&out)).?);
    try std.testing.expectEqualStrings("b", (try ch.recv(&out)).?);
    try std.testing.expectEqual(@as(?[]u8, null), try ch.recv(&out));
    try std.testing.expect(!ch.waker.isSignaled());
    try ch.send("c");
    try std.testing.expect(ch.waker.isSignaled());
    try std.testing.expectEqualStrings("c", (try ch.recv(&out)).?);
}

test "channel cross-thread: consumer sleeps on the handle" {
    const gpa = std.testing.allocator;
    var ch = try Channel.init(gpa, 8, 16);
    defer ch.deinit(gpa);
    const n_packets = 2000;
    const Producer = struct {
        fn run(c: *Channel, space: *Waker) void {
            var i: u32 = 0;
            while (i < n_packets) {
                var b: [4]u8 = undefined;
                std.mem.writeInt(u32, &b, i, .little);
                c.send(&b) catch |e| switch (e) {
                    // Bounded queue: a real producer drops on full; this
                    // one waits for the consumer to report free space.
                    error.QueueFull => {
                        waitReadable(space.handle, 5000) catch return;
                        space.clear();
                        continue;
                    },
                    error.PacketTooLarge => unreachable,
                };
                i += 1;
            }
        }
    };
    var space = try Waker.init();
    defer space.deinit();
    const t = try std.Thread.spawn(.{}, Producer.run, .{ &ch, &space });
    var expect: u32 = 0;
    var out: [16]u8 = undefined;
    while (expect < n_packets) {
        while (try ch.recv(&out)) |p| {
            try std.testing.expectEqual(expect, std.mem.readInt(u32, p[0..4], .little));
            expect += 1;
            space.signal();
        }
        if (expect < n_packets) try waitReadable(ch.handle(), 5000);
    }
    t.join();
}
