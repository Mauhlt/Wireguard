//! The tunnel service's control pipe (Windows only).
//!
//! Server: one pipe instance, `\\.\pipe\ProtectedPrefix\Administrators\zwg\<name>`
//! (only an administrator/SYSTEM process can create it, so its name cannot
//! be squatted; FILE_FLAG_FIRST_PIPE_INSTANCE makes the service fail rather
//! than join someone else's pipe), DACL from `sddl.pipe` (SYSTEM,
//! Administrators, the installing user; no remote clients). It runs on its
//! own thread, so a slow or stuck client never touches the data path: all
//! I/O is overlapped with a 5 s deadline per client, waiting on {I/O event,
//! stop event}. One client at a time; others wait in WaitNamedPipe.
//!
//! The device's state is read on the device's loop thread: the pipe thread
//! signals the request event (the device's `Control` handle), the loop
//! encodes a `get` snapshot into a fixed buffer and signals done.
//!
//! Protocol: uapi.zig (get=1 only; set=1 refused; no secrets ever sent).
//!
//! Client: `query` connects (identification-level impersonation only, so a
//! server could never act as the caller), sends get=1 and reads the bounded
//! response, all with deadlines.

const std = @import("std");
const win = @import("win32.zig");
const names = @import("names.zig");
const sddl = @import("sddl.zig");
const uapi = @import("uapi.zig");
const log = @import("log.zig");
const config = @import("../device/config.zig");
const keys = @import("../device/keys.zig");
const Device = @import("../device/device.zig").Device;

pub const client_deadline_ms: u32 = 5000;
const pipe_out_buffer = 64 << 10;
const pipe_in_buffer = uapi.max_request;

pub const Server = struct {
    gpa: std.mem.Allocator,
    pipe: win.HANDLE,
    io_event: win.HANDLE,
    stop_event: win.HANDLE,
    request_event: win.HANDLE,
    done_event: win.HANDLE,
    thread: ?std.Thread = null,

    conf: *const config.Config,
    public_key: [32]u8,
    lock: win.SRWLOCK = .{},
    /// Written by the loop thread under `lock`.
    snapshot: []u8,
    snapshot_len: usize = 0,
    snapshot_ok: bool = false,
    /// What the pipe thread sends (a copy of the snapshot).
    out: []u8,
    peers: []uapi.Peer,

    pub const InitError = error{ PipeCreateFailed, InvalidSid, OutOfMemory, SystemResources, NameTooLong };

    /// Creates the pipe (so a failure stops the service start); `start`
    /// runs it.
    pub fn init(gpa: std.mem.Allocator, tunnel: []const u8, user_sid: []const u8, conf: *const config.Config) InitError!*Server {
        var nb: [names.max_pipe_name]u8 = undefined;
        return initNamed(gpa, names.pipeName(&nb, tunnel), user_sid, conf);
    }

    /// `init` with an explicit pipe path (tests use one outside
    /// ProtectedPrefix, which an unelevated process cannot create).
    fn initNamed(gpa: std.mem.Allocator, pipe_name: []const u8, user_sid: []const u8, conf: *const config.Config) InitError!*Server {
        var sd_buf: [512]u8 = undefined;
        const sd_text = sddl.pipe(&sd_buf, user_sid) catch return error.InvalidSid;
        var sd = win.SecurityDescriptor.fromSddl(sd_text) catch return error.InvalidSid;
        defer sd.deinit();
        var sa = sd.attributes();
        var wb: [128]u16 = undefined;
        const name_w = win.W(&wb, pipe_name) catch return error.NameTooLong;
        const pipe = win.CreateNamedPipeW(
            name_w.ptr,
            win.PIPE_ACCESS_DUPLEX | win.FILE_FLAG_OVERLAPPED | win.FILE_FLAG_FIRST_PIPE_INSTANCE,
            win.PIPE_TYPE_BYTE | win.PIPE_READMODE_BYTE | win.PIPE_WAIT | win.PIPE_REJECT_REMOTE_CLIENTS,
            1,
            pipe_out_buffer,
            pipe_in_buffer,
            0,
            &sa,
        );
        if (pipe == win.INVALID_HANDLE_VALUE) {
            log.print("control pipe: CreateNamedPipeW failed, Win32 error {d}", .{win.GetLastError()});
            return error.PipeCreateFailed;
        }
        errdefer _ = win.CloseHandle(pipe);

        var total_ips: usize = 0;
        for (conf.peers) |p| total_ips += p.allowed_ips.len;
        const cap = uapi.maxGetLen(conf.peers.len, total_ips);

        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        const snapshot = try gpa.alloc(u8, cap);
        errdefer gpa.free(snapshot);
        const out = try gpa.alloc(u8, cap);
        errdefer gpa.free(out);
        const peers = try gpa.alloc(uapi.Peer, conf.peers.len);
        errdefer gpa.free(peers);
        const io_event = win.CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
        errdefer _ = win.CloseHandle(io_event);
        const stop_event = win.CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
        errdefer _ = win.CloseHandle(stop_event);
        const request_event = win.CreateEventW(null, 0, 0, null) orelse return error.SystemResources; // auto-reset
        errdefer _ = win.CloseHandle(request_event);
        const done_event = win.CreateEventW(null, 0, 0, null) orelse return error.SystemResources;

        s.* = .{
            .gpa = gpa,
            .pipe = pipe,
            .io_event = io_event,
            .stop_event = stop_event,
            .request_event = request_event,
            .done_event = done_event,
            .conf = conf,
            .public_key = keys.publicFromPrivate(&conf.interface.private_key),
            .snapshot = snapshot,
            .out = out,
            .peers = peers,
        };
        return s;
    }

    /// The device's hook: `ready` runs on the loop thread.
    pub fn control(s: *Server) Device.Control {
        return .{ .handle = s.request_event, .ctx = s, .ready = ready };
    }

    pub fn start(s: *Server) std.Thread.SpawnError!void {
        s.thread = try std.Thread.spawn(.{ .stack_size = 256 << 10 }, run, .{s});
    }

    pub fn deinit(s: *Server) void {
        _ = win.SetEvent(s.stop_event);
        if (s.thread) |t| t.join();
        _ = win.CloseHandle(s.pipe);
        _ = win.CloseHandle(s.io_event);
        _ = win.CloseHandle(s.stop_event);
        _ = win.CloseHandle(s.request_event);
        _ = win.CloseHandle(s.done_event);
        const gpa = s.gpa;
        gpa.free(s.snapshot);
        gpa.free(s.out);
        gpa.free(s.peers);
        gpa.destroy(s);
    }

    /// Loop thread: encode the current state. (The request event is
    /// auto-reset: the wait that woke the loop already reset it.)
    fn ready(ctx: *anyopaque, d: *Device) void {
        const s: *Server = @ptrCast(@alignCast(ctx));
        win.AcquireSRWLockExclusive(&s.lock);
        defer win.ReleaseSRWLockExclusive(&s.lock);
        const n = livePeers(s.peers, s.conf.peers, d);
        var w: std.Io.Writer = .fixed(s.snapshot);
        if (uapi.encodeGet(&w, .{ .public_key = s.public_key, .listen_port = d.listen_port }, s.peers[0..n])) |_| {
            s.snapshot_len = w.buffered().len;
            s.snapshot_ok = true;
        } else |_| {
            s.snapshot_ok = false;
        }
        _ = win.SetEvent(s.done_event);
    }

    fn run(s: *Server) void {
        while (true) {
            switch (s.accept()) {
                .connected => {
                    s.serve();
                    _ = win.DisconnectNamedPipe(s.pipe);
                },
                .retry => _ = win.DisconnectNamedPipe(s.pipe),
                .stop => return,
            }
        }
    }

    fn accept(s: *Server) enum { connected, retry, stop } {
        var ov: win.OVERLAPPED = .{ .event = s.io_event };
        _ = win.ResetEvent(s.io_event);
        if (win.ConnectNamedPipe(s.pipe, &ov) != 0) return .connected;
        switch (win.GetLastError()) {
            win.ERROR_PIPE_CONNECTED => return .connected,
            win.ERROR_NO_DATA => return .retry, // the client already left
            win.ERROR_IO_PENDING => {},
            else => |e| {
                log.print("control pipe: ConnectNamedPipe failed, Win32 error {d}; pipe closed", .{e});
                return .stop;
            },
        }
        const handles = [_]win.HANDLE{ s.io_event, s.stop_event };
        const r = win.WaitForMultipleObjects(2, &handles, 0, win.INFINITE);
        var n: u32 = 0;
        if (r != win.WAIT_OBJECT_0) {
            _ = win.CancelIoEx(s.pipe, &ov);
            _ = win.GetOverlappedResult(s.pipe, &ov, &n, 1);
            return .stop;
        }
        return if (win.GetOverlappedResult(s.pipe, &ov, &n, 0) != 0) .connected else .retry;
    }

    fn serve(s: *Server) void {
        const deadline = win.GetTickCount64() + client_deadline_ms;
        var req: [uapi.max_request]u8 = undefined;
        var len: usize = 0;
        const request: ?uapi.Request = while (true) {
            if (len == req.len) break null;
            const n = io(s.pipe, s.io_event, s.stop_event, .read, req[len..], deadline) catch return;
            if (n == 0) return;
            len += n;
            if (uapi.parseRequest(req[0..len])) |maybe| {
                if (maybe) |r| break r;
            } else |_| break null;
        };
        var small: [32]u8 = undefined;
        var w: std.Io.Writer = .fixed(&small);
        const reply: []const u8 = if (request) |r| switch (r) {
            .set => blk: {
                uapi.writeErrno(&w, uapi.errno_perm) catch unreachable;
                break :blk w.buffered();
            },
            .get => s.fetch(deadline) orelse blk: {
                uapi.writeErrno(&w, uapi.errno_io) catch unreachable;
                break :blk w.buffered();
            },
        } else blk: {
            uapi.writeErrno(&w, uapi.errno_invalid) catch unreachable;
            break :blk w.buffered();
        };
        var off: usize = 0;
        while (off < reply.len) {
            const n = io(s.pipe, s.io_event, s.stop_event, .write, @constCast(reply[off..]), deadline) catch return;
            if (n == 0) return;
            off += n;
        }
        // Let the client read everything before the instance is
        // disconnected (DisconnectNamedPipe discards unread data): wait for
        // it to close its end, bounded by the same deadline.
        var sink: [256]u8 = undefined;
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            const n = io(s.pipe, s.io_event, s.stop_event, .read, &sink, deadline) catch return;
            if (n == 0) return;
        }
    }

    /// Ask the loop thread for a snapshot and copy it into `out`.
    fn fetch(s: *Server, deadline: u64) ?[]const u8 {
        _ = win.ResetEvent(s.done_event);
        _ = win.SetEvent(s.request_event);
        const now = win.GetTickCount64();
        if (now >= deadline) return null;
        const handles = [_]win.HANDLE{ s.done_event, s.stop_event };
        if (win.WaitForMultipleObjects(2, &handles, 0, @intCast(deadline - now)) != win.WAIT_OBJECT_0) return null;
        win.AcquireSRWLockExclusive(&s.lock);
        defer win.ReleaseSRWLockExclusive(&s.lock);
        if (!s.snapshot_ok) return null;
        @memcpy(s.out[0..s.snapshot_len], s.snapshot[0..s.snapshot_len]);
        return s.out[0..s.snapshot_len];
    }
};

/// The configured peers the device has now, matched by public key (a
/// peer's position changes when `Device.setPeers` adds, removes or reorders
/// peers), in configuration order. Allowed IPs come from the configuration
/// (the device keeps only its routing table). A peer added later that the
/// configuration does not list is not reported: the snapshot buffers are
/// sized for the configuration. Returns how many entries of `out` are set.
fn livePeers(out: []uapi.Peer, conf_peers: []const config.Peer, d: *const Device) usize {
    var n: usize = 0;
    for (conf_peers) |*c| {
        if (n == out.len) break;
        const p = d.peerByKey(c.public_key) orelse continue;
        out[n] = .{
            .public_key = p.public_key,
            .endpoint = p.endpoint,
            .last_handshake_ns = p.last_handshake_wall_ns,
            .tx_bytes = p.tx_bytes,
            .rx_bytes = p.rx_bytes,
            .persistent_keepalive = p.persistent_keepalive,
            .allowed_ips = c.allowed_ips,
        };
        n += 1;
    }
    return n;
}

const IoError = error{ Timeout, Stopped, Failed };

/// One overlapped read or write on `h`, waited for until `deadline` (tick
/// ms) or `stop` (optional). 0 = end of stream (the other side closed).
fn io(h: win.HANDLE, event: win.HANDLE, stop: ?win.HANDLE, comptime dir: enum { read, write }, buf: []u8, deadline: u64) IoError!usize {
    var ov: win.OVERLAPPED = .{ .event = event };
    _ = win.ResetEvent(event);
    const len: u32 = @intCast(@min(buf.len, 1 << 20));
    var n: u32 = 0;
    const ok = switch (dir) {
        .read => win.ReadFile(h, buf.ptr, len, null, &ov),
        .write => win.WriteFile(h, buf.ptr, len, null, &ov),
    };
    if (ok == 0) switch (win.GetLastError()) {
        win.ERROR_IO_PENDING => {
            const now = win.GetTickCount64();
            const ms: u32 = if (now >= deadline) 0 else @intCast(deadline - now);
            var handles = [_]win.HANDLE{ event, undefined };
            var count: u32 = 1;
            if (stop) |s| {
                handles[1] = s;
                count = 2;
            }
            const r = win.WaitForMultipleObjects(count, &handles, 0, ms);
            if (r != win.WAIT_OBJECT_0) {
                _ = win.CancelIoEx(h, &ov);
                _ = win.GetOverlappedResult(h, &ov, &n, 1); // the buffer is ours again
                return if (r == win.WAIT_TIMEOUT) error.Timeout else error.Stopped;
            }
        },
        win.ERROR_BROKEN_PIPE, win.ERROR_PIPE_NOT_CONNECTED, win.ERROR_NO_DATA => return 0,
        else => return error.Failed,
    };
    if (win.GetOverlappedResult(h, &ov, &n, 0) == 0) return switch (win.GetLastError()) {
        win.ERROR_BROKEN_PIPE, win.ERROR_PIPE_NOT_CONNECTED, win.ERROR_NO_DATA => 0,
        win.ERROR_MORE_DATA => n,
        else => error.Failed,
    };
    return n;
}

// ---- client ----------------------------------------------------------------------

pub const QueryError = error{
    /// No pipe: the service is not running (or not ours).
    NotRunning,
    /// The pipe's DACL refused us (another user's tunnel).
    AccessDenied,
    Busy,
    Timeout,
    InvalidResponse,
    OutOfMemory,
    Unexpected,
};

/// Send `get=1` to the tunnel's service and return the raw response
/// (complete, ends "errno=N\n\n"). Caller frees.
pub fn query(gpa: std.mem.Allocator, tunnel: []const u8) QueryError![]u8 {
    var nb: [names.max_pipe_name]u8 = undefined;
    return queryNamed(gpa, names.pipeName(&nb, tunnel), client_deadline_ms);
}

fn queryNamed(gpa: std.mem.Allocator, pipe_name: []const u8, timeout_ms: u32) QueryError![]u8 {
    var wb: [128]u16 = undefined;
    const name_w = win.W(&wb, pipe_name) catch return error.Unexpected;
    const deadline = win.GetTickCount64() + timeout_ms;

    const h = try open(name_w, win.FILE_FLAG_OVERLAPPED | win.SECURITY_SQOS_PRESENT | win.SECURITY_IDENTIFICATION, deadline);
    defer _ = win.CloseHandle(h);
    const event = win.CreateEventW(null, 1, 0, null) orelse return error.Unexpected;
    defer _ = win.CloseHandle(event);

    var req = "get=1\n\n".*;
    var off: usize = 0;
    while (off < req.len) {
        const n = io(h, event, null, .write, req[off..], deadline) catch |e| return mapIo(e);
        if (n == 0) return error.InvalidResponse;
        off += n;
    }
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    var chunk: [16 << 10]u8 = undefined;
    while (true) {
        const n = io(h, event, null, .read, &chunk, deadline) catch |e| return mapIo(e);
        if (n == 0) return error.InvalidResponse; // closed before the end
        if (buf.items.len + n > uapi.max_response) return error.InvalidResponse;
        try buf.appendSlice(gpa, chunk[0..n]);
        if (complete(buf.items)) break;
    }
    return buf.toOwnedSlice(gpa);
}

/// Open the server's pipe instance, waiting (in WaitNamedPipe, until
/// `deadline`, tick ms) while it is busy. The server has one instance, so
/// it is busy not only while another client is served but also in the
/// short gap after a client leaves, before the server has disconnected and
/// re-armed it: ERROR_PIPE_BUSY is a normal answer, not a failure.
fn open(name_w: [:0]const u16, flags: u32, deadline: u64) QueryError!win.HANDLE {
    while (true) {
        const h = win.CreateFileW(name_w.ptr, win.FILE_READ_DATA | win.FILE_WRITE_DATA | win.SYNCHRONIZE, 0, null, win.OPEN_EXISTING, flags, null);
        if (h != win.INVALID_HANDLE_VALUE) return h;
        switch (win.GetLastError()) {
            win.ERROR_FILE_NOT_FOUND, win.ERROR_PATH_NOT_FOUND => return error.NotRunning,
            win.ERROR_ACCESS_DENIED => return error.AccessDenied,
            // The kernel wakes us when the instance is listening again (no
            // polling); another client may win it, so retry until the deadline.
            win.ERROR_PIPE_BUSY => {
                const now = win.GetTickCount64();
                if (now >= deadline) return error.Busy;
                _ = win.WaitNamedPipeW(name_w.ptr, @intCast(deadline - now));
            },
            else => return error.Unexpected,
        }
    }
}

/// A response is complete when it ends with an "errno=..." line and a blank line.
fn complete(b: []const u8) bool {
    if (!std.mem.endsWith(u8, b, "\n\n")) return false;
    const body = b[0 .. b.len - 1]; // drop the blank line
    const start = if (std.mem.findScalarLast(u8, body[0 .. body.len - 1], '\n')) |i| i + 1 else 0;
    return std.mem.startsWith(u8, body[start..], "errno=");
}

fn mapIo(e: IoError) QueryError {
    return switch (e) {
        error.Timeout => error.Timeout,
        error.Stopped, error.Failed => error.Unexpected,
    };
}

test "response completeness" {
    try std.testing.expect(complete("errno=0\n\n"));
    try std.testing.expect(complete("listen_port=1\nerrno=0\n\n"));
    try std.testing.expect(!complete("listen_port=1\n"));
    try std.testing.expect(!complete("errno=0\n"));
    try std.testing.expect(!complete("listen_port=1\n\n"));
}

test "query: no such tunnel" {
    try std.testing.expectError(error.NotRunning, query(std.testing.allocator, "zwg-test-none"));
}

// ---- integration test: device loop + pipe server + client, unelevated ----------

const testing = std.testing;
const tun = @import("../tun/root.zig");
const dev = @import("../device/device.zig");
const Cidr = @import("../ip.zig").Cidr;

/// Raw exchange for protocol tests: send `request`, read to EOF or "\n\n".
fn exchange(gpa: std.mem.Allocator, pipe_name: []const u8, request: []const u8) ![]u8 {
    var wb: [128]u16 = undefined;
    const name_w = try win.W(&wb, pipe_name);
    const deadline = win.GetTickCount64() + 3000;
    const h = try open(name_w, win.FILE_FLAG_OVERLAPPED, deadline);
    defer _ = win.CloseHandle(h);
    const ev = win.CreateEventW(null, 1, 0, null).?;
    defer _ = win.CloseHandle(ev);
    var req_buf: [8192]u8 = undefined;
    @memcpy(req_buf[0..request.len], request);
    var off: usize = 0;
    while (off < request.len) {
        const n = try io(h, ev, null, .write, req_buf[off..request.len], deadline);
        if (n == 0) break;
        off += n;
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [4096]u8 = undefined;
    while (!std.mem.endsWith(u8, out.items, "\n\n")) {
        const n = try io(h, ev, null, .read, &chunk, deadline);
        if (n == 0) break;
        try out.appendSlice(gpa, chunk[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

test "control pipe end to end: device state over get=1, set refused, garbage refused, DACL" {
    const gpa = testing.allocator;
    const conf_text =
        \\[Interface]
        \\PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
        \\[Peer]
        \\PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        \\AllowedIPs = 10.20.0.2/32, fd00::2/128
        \\Endpoint = 127.0.0.1:9
    ;
    var diag: config.Diagnostic = .{};
    var conf = try config.parse(gpa, conf_text, &diag);
    defer conf.deinit();

    var clock: dev.Clock = .{ .io = testing.io };
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{
        .private_key = conf.interface.private_key,
        .peers = &.{.{
            .public_key = conf.peers[0].public_key,
            .allowed_ips = conf.peers[0].allowed_ips,
            .endpoint = conf.peers[0].endpoint.?.literal(),
        }},
    });
    defer d.destroy();

    var sid_buf: [184]u8 = undefined;
    const sid = try win.currentUserSid(&sid_buf);
    var name_buf: [64]u8 = undefined;
    var rnd: [4]u8 = undefined;
    testing.io.random(&rnd);
    const pipe_name = try std.fmt.bufPrint(&name_buf, "\\\\.\\pipe\\zwg-test-{x}", .{std.mem.readInt(u32, &rnd, .little)});

    const server = try Server.initNamed(gpa, pipe_name, sid, &conf);
    defer server.deinit();
    // A second server on the same name fails (FILE_FLAG_FIRST_PIPE_INSTANCE).
    try testing.expectError(error.PipeCreateFailed, Server.initNamed(gpa, pipe_name, sid, &conf));
    d.control = server.control();
    try server.start();
    const loop = try std.Thread.spawn(.{}, Device.run, .{d});
    defer {
        d.stop();
        loop.join();
    }

    // get=1 through the real client, decoded.
    const raw = try queryNamed(gpa, pipe_name, client_deadline_ms);
    defer gpa.free(raw);
    try testing.expect(std.mem.indexOf(u8, raw, "private_key") == null);
    try testing.expect(std.mem.indexOf(u8, raw, "preshared_key") == null);
    var st = try uapi.decode(gpa, raw, null);
    defer st.deinit();
    try testing.expectEqual(keys.publicFromPrivate(&conf.interface.private_key), st.public_key.?);
    try testing.expectEqual(@as(?u16, d.listen_port), st.listen_port);
    try testing.expectEqual(@as(usize, 1), st.peers.len);
    try testing.expectEqual(conf.peers[0].public_key, st.peers[0].public_key);
    try testing.expectEqual(@as(usize, 2), st.peers[0].allowed_ips.len);
    try testing.expectEqual(@as(u16, 9), st.peers[0].endpoint.?.getPort());

    // Again (the instance is reused after a disconnect).
    const raw2 = try queryNamed(gpa, pipe_name, client_deadline_ms);
    gpa.free(raw2);

    // set=1 is refused; garbage gets EINVAL; neither kills the server.
    const set = try exchange(gpa, pipe_name, "set=1\nprivate_key=" ++ &@as([64]u8, @splat('0')) ++ "\n\n");
    defer gpa.free(set);
    try testing.expectEqualStrings("errno=-1\n\n", set);
    const junk = try exchange(gpa, pipe_name, "hello\n\n");
    defer gpa.free(junk);
    try testing.expectEqualStrings("errno=-22\n\n", junk);
    const huge = try exchange(gpa, pipe_name, "get=1" ++ &@as([5000]u8, @splat('1')));
    defer gpa.free(huge);
    try testing.expectEqualStrings("errno=-22\n\n", huge);

    // The DACL: an ordinary-user token for this user gets in, a token
    // without this user's SID (some other user) does not.
    {
        const t = try win.restrictedToken(false);
        defer _ = win.CloseHandle(t);
        try testing.expect(win.ImpersonateLoggedOnUser(t) != 0);
        defer _ = win.RevertToSelf();
        const r = try queryNamed(gpa, pipe_name, client_deadline_ms);
        gpa.free(r);
    }
    {
        const t = try win.restrictedToken(true);
        defer _ = win.CloseHandle(t);
        try testing.expect(win.ImpersonateLoggedOnUser(t) != 0);
        defer _ = win.RevertToSelf();
        try testing.expectError(error.AccessDenied, queryNamed(gpa, pipe_name, client_deadline_ms));
    }

    // A client that connects and says nothing is dropped at the deadline,
    // and the next client is served. (It opens like a real client: right
    // after the previous client left, the single instance may not be
    // listening yet, and a bare CreateFileW then gets ERROR_PIPE_BUSY.)
    {
        var wb: [128]u16 = undefined;
        const silent = try open(try win.W(&wb, pipe_name), 0, win.GetTickCount64() + client_deadline_ms);
        defer _ = win.CloseHandle(silent);
        const r = try queryNamed(gpa, pipe_name, 3 * client_deadline_ms); // waits in WaitNamedPipe, then served
        gpa.free(r);
    }
}

test "livePeers matches the device's peers to the configuration by public key after setPeers" {
    const gpa = testing.allocator;
    const ka = keys.publicFromPrivate(&keys.generatePrivate(testing.io));
    const kb = keys.publicFromPrivate(&keys.generatePrivate(testing.io));
    const kc = keys.publicFromPrivate(&keys.generatePrivate(testing.io));
    var a_ips = [_]Cidr{try .parse("10.20.0.1/32")};
    var b_ips = [_]Cidr{ try .parse("10.20.0.2/32"), try .parse("fd00::2/128") };
    const conf_peers = [_]config.Peer{
        .{ .public_key = ka, .allowed_ips = &a_ips },
        .{ .public_key = kb, .allowed_ips = &b_ips },
    };

    var clock: dev.Clock = .{ .io = testing.io };
    var fake: tun.FakeTun = try .init(gpa, .{});
    defer fake.deinit();
    const d = try Device.create(gpa, &clock, fake.tun(), .{
        .private_key = keys.generatePrivate(testing.io),
        .peers = &.{
            .{ .public_key = ka, .allowed_ips = &a_ips, .persistent_keepalive = 1 },
            .{ .public_key = kb, .allowed_ips = &b_ips, .persistent_keepalive = 2 },
        },
    });
    defer d.destroy();

    var out: [conf_peers.len]uapi.Peer = undefined;
    try testing.expectEqual(@as(usize, 2), livePeers(&out, &conf_peers, d));
    try testing.expectEqual(ka, out[0].public_key);
    try testing.expectEqual(@as(usize, 1), out[0].allowed_ips.len);
    try testing.expectEqual(kb, out[1].public_key);
    try testing.expectEqual(@as(usize, 2), out[1].allowed_ips.len);

    // a removed, c added (not configured), b moved to the front: each
    // reported peer still carries its own state and allowed IPs.
    try d.setPeers(&.{
        .{ .public_key = kb, .allowed_ips = &b_ips, .persistent_keepalive = 2 },
        .{ .public_key = kc, .persistent_keepalive = 3 },
    });
    try testing.expectEqual(@as(usize, 1), livePeers(&out, &conf_peers, d));
    try testing.expectEqual(kb, out[0].public_key);
    try testing.expectEqual(@as(u16, 2), out[0].persistent_keepalive);
    try testing.expectEqual(@as(usize, 2), out[0].allowed_ips.len);

    // a back, after c and b.
    try d.setPeers(&.{
        .{ .public_key = kc, .persistent_keepalive = 3 },
        .{ .public_key = kb, .allowed_ips = &b_ips, .persistent_keepalive = 2 },
        .{ .public_key = ka, .allowed_ips = &a_ips, .persistent_keepalive = 1 },
    });
    try testing.expectEqual(@as(usize, 2), livePeers(&out, &conf_peers, d));
    try testing.expectEqual(ka, out[0].public_key);
    try testing.expectEqual(@as(u16, 1), out[0].persistent_keepalive);
    try testing.expectEqual(@as(usize, 1), out[0].allowed_ips.len);
    try testing.expectEqual(kb, out[1].public_key);
    try testing.expectEqual(@as(u16, 2), out[1].persistent_keepalive);
}
