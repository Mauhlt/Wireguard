//! The stack size to ask std.Thread.spawn for, for a thread that needs
//! `want` bytes of its own.
//!
//! Linux with glibc carves a thread's static TLS out of the stack it is
//! given, and Zig's std keeps a 256 KiB alternate signal stack in TLS
//! (std.options.signal_stack_size). So a 256 KiB request leaves no room:
//! pthread_create fails with EINVAL, which std.Thread.spawn treats as
//! unreachable (a panic). On Linux that amount and a margin are added;
//! Windows and macOS keep TLS apart from the stack, so `want` is asked for
//! as is. (The same rule as Portal's platform.threadStack.)

const std = @import("std");
const builtin = @import("builtin");

pub fn threadStack(want: usize) usize {
    if (builtin.os.tag != .linux) return want;
    return want + @as(usize, @intCast(std.options.signal_stack_size orelse 0)) + 64 * 1024;
}

test "threadStack: on Linux the static TLS the stack must also hold is added" {
    if (builtin.os.tag == .linux) {
        try std.testing.expect(threadStack(256 << 10) > (256 << 10) + (std.options.signal_stack_size orelse 0));
    } else try std.testing.expectEqual(@as(usize, 256 << 10), threadStack(256 << 10));
}

test "threadStack: a thread with a 256 KiB stack of its own starts and runs" {
    const T = struct {
        fn work(out: *u32) void {
            var buf: [128 << 10]u8 = undefined;
            @memset(&buf, 1);
            out.* = buf[buf.len - 1];
        }
    };
    var got: u32 = 0;
    const t = try std.Thread.spawn(.{ .stack_size = threadStack(256 << 10) }, T.work, .{&got});
    t.join();
    try std.testing.expectEqual(@as(u32, 1), got);
}
