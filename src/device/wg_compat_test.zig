//! Cross-checks key text against the official `wg` tool, when installed
//! (WireGuard for Windows puts it at C:\Program Files\WireGuard\wg.exe;
//! elsewhere `wg` on PATH is tried). Skipped when absent.

const std = @import("std");
const builtin = @import("builtin");
const keys = @import("keys.zig");

const testing = std.testing;
const io = testing.io;

fn wgPath() ?[]const u8 {
    const candidates: []const []const u8 = if (builtin.os.tag == .windows)
        &.{"C:\\Program Files\\WireGuard\\wg.exe"}
    else
        &.{ "/usr/bin/wg", "/usr/local/bin/wg", "/opt/homebrew/bin/wg" };
    for (candidates) |p| {
        std.Io.Dir.accessAbsolute(io, p, .{}) catch continue;
        return p;
    }
    return null;
}

/// Runs `wg <arg>` with `input` on stdin; returns its stdout, trimmed.
fn runWg(gpa: std.mem.Allocator, wg: []const u8, arg: []const u8, input: []const u8) ![]u8 {
    var child = try std.process.spawn(io, .{
        .argv = &.{ wg, arg },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
        .create_no_window = true,
    });
    defer child.kill(io);
    try child.stdin.?.writeStreamingAll(io, input);
    child.stdin.?.close(io);
    child.stdin = null;
    var buf: [256]u8 = undefined;
    var r = child.stdout.?.readerStreaming(io, &buf);
    const out = try r.interface.allocRemaining(gpa, .limited(4096));
    errdefer gpa.free(out);
    const term = try child.wait(io);
    if (!term.success()) return error.WgFailed;
    const t = std.mem.trimEnd(u8, out, "\r\n");
    return gpa.realloc(out, t.len);
}

test "keys agree with wg genkey / wg pubkey" {
    const wg = wgPath() orelse return error.SkipZigTest;
    const gpa = testing.allocator;

    // wg's private key -> our decode, our public key == wg pubkey.
    for (0..3) |_| {
        const priv_text = try runWg(gpa, wg, "genkey", "");
        defer gpa.free(priv_text);
        const priv = try keys.decode(priv_text);
        try testing.expectEqualStrings(priv_text, &keys.encode(&priv));
        const pub_text = try runWg(gpa, wg, "pubkey", priv_text);
        defer gpa.free(pub_text);
        try testing.expectEqualStrings(pub_text, &keys.encode(&keys.publicFromPrivate(&priv)));
    }

    // Our private key -> wg pubkey agrees with ours.
    const mine = keys.generatePrivate(io);
    const mine_text = keys.encode(&mine);
    const theirs = try runWg(gpa, wg, "pubkey", &mine_text);
    defer gpa.free(theirs);
    try testing.expectEqualStrings(theirs, &keys.encode(&keys.publicFromPrivate(&mine)));

    // wg rejects what we reject (non-canonical last character).
    const bad = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBml=";
    try testing.expectError(error.InvalidKey, keys.decode(bad));
    try testing.expectError(error.WgFailed, runWg(gpa, wg, "pubkey", bad));
}
