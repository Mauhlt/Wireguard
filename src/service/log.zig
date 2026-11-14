//! The tunnel service's log: one bounded file per tunnel under
//! %ProgramFiles%\zwg\logs (protected directory), rotated to `<name>.log.old`
//! when it reaches `store.max_log_bytes`, so at most twice that on disk.
//! Messages are zwg's own text: configuration values that could be secret
//! (keys) are never formatted into them. Thread-safe (the service thread,
//! the pipe thread and the SCM handler all log). Windows only.

const std = @import("std");
const win = @import("win32.zig");
const store = @import("store.zig");

var lock: win.SRWLOCK = .{};
var handle: ?win.HANDLE = null;
var written: u64 = 0;
var path_w: [300]u16 = undefined;
/// The installer and the service it starts append to the same file
/// (FILE_APPEND_DATA writes are atomic appends); rotation renames it.
const share = win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE;
var old_w: [304]u16 = undefined;

/// Start logging to `path` (UTF-8). Without a successful `open`, `print`
/// is a no-op and `logFn` goes to stderr.
pub fn open(path: []const u8) store.Error!void {
    win.AcquireSRWLockExclusive(&lock);
    defer win.ReleaseSRWLockExclusive(&lock);
    const p = win.W(&path_w, path) catch return error.NameTooLong;
    var old_buf: [310]u8 = undefined;
    const old = std.fmt.bufPrint(&old_buf, "{s}.old", .{path}) catch return error.NameTooLong;
    _ = win.W(&old_w, old) catch return error.NameTooLong;
    _ = p;
    try reopen();
}

pub fn close() void {
    win.AcquireSRWLockExclusive(&lock);
    defer win.ReleaseSRWLockExclusive(&lock);
    if (handle) |h| _ = win.CloseHandle(h);
    handle = null;
}

pub fn isOpen() bool {
    return handle != null;
}

fn reopen() store.Error!void {
    const h = win.CreateFileW(@ptrCast(&path_w), win.FILE_APPEND_DATA | win.SYNCHRONIZE, share, null, win.OPEN_ALWAYS, win.FILE_ATTRIBUTE_NORMAL, null);
    if (h == win.INVALID_HANDLE_VALUE) return if (win.GetLastError() == win.ERROR_ACCESS_DENIED) error.AccessDenied else error.Unexpected;
    var size: i64 = 0;
    _ = win.GetFileSizeEx(h, &size);
    handle = h;
    written = @intCast(@max(size, 0));
    if (written >= store.max_log_bytes) rotate();
}

fn rotate() void {
    if (handle) |h| _ = win.CloseHandle(h);
    handle = null;
    _ = win.MoveFileExW(@ptrCast(&path_w), @ptrCast(&old_w), win.MOVEFILE_REPLACE_EXISTING);
    const h = win.CreateFileW(@ptrCast(&path_w), win.FILE_APPEND_DATA | win.SYNCHRONIZE, share, null, win.OPEN_ALWAYS, win.FILE_ATTRIBUTE_NORMAL, null);
    if (h == win.INVALID_HANDLE_VALUE) return;
    handle = h;
    written = 0;
}

/// One line: "2026-11-12 10:00:00Z <message>". Longer than 1 KiB: cut.
pub fn print(comptime fmt: []const u8, args: anytype) void {
    if (handle == null) return;
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 2]);
    writeTimestamp(&w) catch {};
    w.print(fmt, args) catch {};
    var line = w.buffered();
    const n = line.len;
    buf[n] = '\r';
    buf[n + 1] = '\n';
    line = buf[0 .. n + 2];

    win.AcquireSRWLockExclusive(&lock);
    defer win.ReleaseSRWLockExclusive(&lock);
    if (handle == null) return;
    if (written + line.len > store.max_log_bytes) rotate();
    const h = handle orelse return;
    var done: u32 = 0;
    if (win.WriteFile(h, line.ptr, @intCast(line.len), &done, null) != 0) written += done;
}

fn writeTimestamp(w: *std.Io.Writer) !void {
    var ft: u64 = 0;
    win.GetSystemTimeAsFileTime(&ft);
    const unix: u64 = ft / 10_000_000 -| 11_644_473_600;
    const es: std.time.epoch.EpochSeconds = .{ .secs = unix };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}Z ", .{
        yd.year,                   md.month.numeric(),           md.day_index + 1,
        ds.getHoursIntoDay(),      ds.getMinutesIntoHour(),      ds.getSecondsIntoMinute(),
    });
}

/// For `std_options.logFn`: std.log output (device, Wintun) goes to the
/// service log when one is open, else to stderr as usual.
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (handle == null) return std.log.defaultLog(level, scope, format, args);
    print("[" ++ comptime level.asText() ++ "] (" ++ @tagName(scope) ++ ") " ++ format, args);
}

test "log file is bounded and rotates" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [300]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buf);
    var path_buf: [400]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}\\t.log", .{dir_buf[0..dir_len]});
    try open(path);
    defer close();
    const line: [1000]u8 = @splat(0x78);
    for (0..(store.max_log_bytes / 1000) + 50) |i| print("{d} {s}", .{ i, &line });
    close();
    const cur = try store.readAll(std.testing.allocator, path, store.max_log_bytes);
    defer std.testing.allocator.free(cur);
    try std.testing.expect(cur.len > 0 and cur.len <= store.max_log_bytes);
    var old_buf: [410]u8 = undefined;
    const old = try std.fmt.bufPrint(&old_buf, "{s}.old", .{path});
    const prev = try store.readAll(std.testing.allocator, old, store.max_log_bytes);
    defer std.testing.allocator.free(prev);
    try std.testing.expect(prev.len > store.max_log_bytes - 1100);
    try std.testing.expect(std.mem.endsWith(u8, cur, "\r\n"));
    try std.testing.expect(cur[4] == '-' and cur[19] == 'Z');
}
