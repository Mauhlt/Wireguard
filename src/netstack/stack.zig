//! The stack: connection table, listeners, locking, the stack thread and
//! the Tun the device sees. TCP per-connection logic lives in tcp.zig.
//! (Phase 1: API stub; the signatures are final.)
const std = @import("std");
const root = @import("root.zig");
const wg_tun = @import("../tun/root.zig");
const dev = @import("../device/root.zig");

const Options = root.Options;
const Endpoint = root.Endpoint;

fn todo() noreturn {
    @panic("netstack: not implemented yet");
}

pub const Stack = struct {
    /// Allocates the connection table and the two rings. `clock` is the
    /// device's clock (all deadlines are on it) and must outlive the stack.
    pub fn create(gpa: std.mem.Allocator, clock: *root.Clock, options: Options) root.CreateError!*Stack {
        _ = .{ gpa, clock, options };
        todo();
    }

    /// Stops the stack thread (if started), resets every connection,
    /// wakes every blocked call (they return Closed), wipes and frees all
    /// buffers. The device using `tun()` must be stopped first.
    pub fn destroy(s: *Stack) void {
        _ = s;
        todo();
    }

    /// The Tun to pass to `Device.create`. read/write never block.
    pub fn tun(s: *Stack) wg_tun.Tun {
        _ = s;
        todo();
    }

    /// Spawns the stack thread (it waits on the inbound ring, a kick event
    /// and a deadline timer; nothing ticks).
    pub fn start(s: *Stack) root.StartError!void {
        _ = s;
        todo();
    }

    /// Stops and joins the stack thread (idempotent).
    pub fn stop(s: *Stack) void {
        _ = s;
        todo();
    }

    // ---- manual drive (tests; or hosts that run no stack thread) --------
    // Do not mix with start(): with the thread running these are its job.

    /// Processes one IP packet from the peer (as the device would deliver
    /// it). Malformed packets are counted and dropped.
    pub fn input(s: *Stack, packet: []const u8) void {
        _ = .{ s, packet };
        todo();
    }

    /// The next IP packet to send toward the peer, built into `buf`
    /// (`buf.len >= mtu`), or null when there is nothing to send now.
    pub fn output(s: *Stack, buf: []u8) ?[]u8 {
        _ = .{ s, buf };
        todo();
    }

    /// Fires every timer due at `clock.now()` and returns the next
    /// deadline (device clock, ns), or null when no timer is armed.
    pub fn runTimers(s: *Stack) ?i64 {
        _ = s;
        todo();
    }

    // ---- host API (thread-safe) ------------------------------------------

    /// Listen on `Options.address`:`port`.
    pub fn listen(s: *Stack, port: u16) root.ListenError!Listener {
        _ = .{ s, port };
        todo();
    }

    /// Starts connecting (SYN sent from an ephemeral port); returns at once.
    /// Use `Stream.waitConnected`, or just read/write (they wait for the
    /// connection, or fail with its error).
    pub fn dial(s: *Stack, to: Endpoint) root.DialError!Stream {
        _ = .{ s, to };
        todo();
    }

    /// dial + waitConnected; on failure the stream is released.
    pub fn dialWait(s: *Stack, to: Endpoint, timeout_ns: ?u64) (root.DialError || root.ConnectError)!Stream {
        _ = .{ s, to, timeout_ns };
        todo();
    }

    /// Manual-reset handle, signalled whenever any stream or listener may
    /// have become readable, writable, acceptable, connected or closed.
    /// Event-loop hosts wait on it, call `clearReady()`, then retry their
    /// non-blocking calls (or check `Stream.status()`). Spurious wakeups
    /// are possible.
    pub fn readyHandle(s: *Stack) root.WaitHandle {
        _ = s;
        todo();
    }

    pub fn clearReady(s: *Stack) void {
        _ = s;
        todo();
    }

    pub fn stats(s: *Stack) root.Stats {
        _ = s;
        todo();
    }
};

pub const Listener = struct {
    stack: *Stack,
    id: u32,

    pub fn port(l: Listener) u16 {
        _ = l;
        todo();
    }

    /// Non-blocking: an established connection, or error.WouldBlock.
    pub fn accept(l: Listener) root.AcceptError!Stream {
        _ = l;
        todo();
    }

    /// Blocks until a connection is established (null timeout: forever).
    pub fn acceptWait(l: Listener, timeout_ns: ?u64) root.AcceptError!Stream {
        _ = .{ l, timeout_ns };
        todo();
    }

    /// Stops listening; queued, unaccepted connections are reset; blocked
    /// acceptWait calls return Closed.
    pub fn close(l: Listener) void {
        _ = l;
        todo();
    }
};

pub const Stream = struct {
    stack: *Stack,
    id: u32,

    /// Non-blocking. Bytes copied (> 0), 0 at end of stream (peer FIN),
    /// error.WouldBlock when nothing is buffered yet.
    pub fn read(st: Stream, buf: []u8) root.ReadError!usize {
        _ = .{ st, buf };
        todo();
    }

    /// Blocks until at least one byte, end of stream, an error or the
    /// timeout (null: forever).
    pub fn readWait(st: Stream, buf: []u8, timeout_ns: ?u64) root.ReadError!usize {
        _ = .{ st, buf, timeout_ns };
        todo();
    }

    /// Non-blocking. Bytes accepted into the send buffer (> 0), or
    /// error.WouldBlock when it is full (backpressure). Sent with no
    /// Nagle delay.
    pub fn write(st: Stream, data: []const u8) root.WriteError!usize {
        _ = .{ st, data };
        todo();
    }

    /// Blocks until all of `data` is in the send buffer (or error /
    /// timeout; on Timeout some prefix may have been accepted: the count
    /// is lost, so treat Timeout on a write as fatal for the stream).
    pub fn writeAll(st: Stream, data: []const u8, timeout_ns: ?u64) root.WriteError!void {
        _ = .{ st, data, timeout_ns };
        todo();
    }

    pub fn waitConnected(st: Stream, timeout_ns: ?u64) root.ConnectError!void {
        _ = .{ st, timeout_ns };
        todo();
    }

    /// Half-close: FIN after the buffered data. Reads continue.
    pub fn shutdown(st: Stream) void {
        _ = st;
        todo();
    }

    /// Graceful close and release of the handle: FIN after buffered data;
    /// the connection finishes in the background (bounded by
    /// user_timeout_ns / time_wait_ns). Unread received data -> RST
    /// instead (RFC 1122 4.2.2.13). Blocked calls return Closed.
    pub fn close(st: Stream) void {
        _ = st;
        todo();
    }

    /// RST now and release the handle.
    pub fn abort(st: Stream) void {
        _ = st;
        todo();
    }

    pub fn status(st: Stream) root.Status {
        _ = st;
        todo();
    }

    pub fn local(st: Stream) Endpoint {
        _ = st;
        todo();
    }

    pub fn remote(st: Stream) Endpoint {
        _ = st;
        todo();
    }

    /// Blocking std.Io.Reader over readWait with `timeout_ns` per fill
    /// (null: forever). On failure the interface returns ReadFailed and
    /// `err` holds the cause. Hand `&r.interface` to std.crypto.tls etc.
    pub fn reader(st: Stream, buffer: []u8, timeout_ns: ?u64) Reader {
        _ = .{ st, buffer, timeout_ns };
        todo();
    }

    /// Blocking std.Io.Writer over writeAll; `flush()` pushes buffered
    /// bytes into the send buffer (TCP sends them at once).
    pub fn writer(st: Stream, buffer: []u8, timeout_ns: ?u64) Writer {
        _ = .{ st, buffer, timeout_ns };
        todo();
    }

    pub const Reader = struct {
        interface: std.Io.Reader,
        stream: Stream,
        timeout_ns: ?u64,
        err: ?root.ReadError = null,
    };

    pub const Writer = struct {
        interface: std.Io.Writer,
        stream: Stream,
        timeout_ns: ?u64,
        err: ?root.WriteError = null,
    };
};

pub const Node = struct {
    stack: *Stack,
    device: *dev.Device,

    pub const StartError = root.CreateError || root.StartError || dev.Device.InitError || error{ThreadSpawnFailed};

    /// Creates the stack (tun = stack.tun()), then the device with
    /// `device_options`, then starts the stack thread and a device thread
    /// running `Device.run`.
    pub fn start(gpa: std.mem.Allocator, clock: *root.Clock, device_options: dev.device.Options, stack_options: Options) StartError!*Node {
        _ = .{ gpa, clock, device_options, stack_options };
        todo();
    }

    /// Stops the device thread, then the stack thread; destroys both.
    pub fn destroy(n: *Node) void {
        _ = n;
        todo();
    }
};