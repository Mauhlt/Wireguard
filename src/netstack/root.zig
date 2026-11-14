//! netstack: a minimal userspace TCP/IP stack (IPv4 and IPv6) that plugs into a zwg
//! `Device` as its Tun, so a process can run WireGuard in-process (no
//! Wintun adapter, no driver, no admin, no service) and still accept and
//! dial TCP connections inside the tunnel. Contract: DESIGN.md,
//! "Userspace netstack".
//!
//! Threads (no polling, no ticks anywhere):
//!
//!   device thread  Device.run(): UDP <-> crypto <-> Tun.read/write
//!   stack thread   Stack.start(): waits on {inbound ring, kick, deadline
//!                  timer}; runs TCP input, timers and output
//!   host threads   Stream / Listener calls, thread-safe, blocking with a
//!                  timeout or non-blocking (error.WouldBlock) plus
//!                  `readyHandle()` for an event loop
//!
//!   Device --Tun.write--> [inbound Channel]  --> stack thread
//!   Device <--Tun.read--- [outbound Channel] <-- stack thread
//!
//! The rings are `tun.queue.Channel` (the same SPSC ring + Waker FakeTun
//! and PacketFlowTun use); the device needs no changes. Memory is bounded
//! by `Limits`; network input never allocates beyond those bounds.
const std = @import("std");
const wg_tun = @import("../tun/root.zig");
const dev = @import("../device/root.zig");

pub const wire = @import("wire.zig");
pub const testing = @import("testing.zig");
const stack_impl = @import("stack.zig");

/// Interface addresses are the device's own type (raw network-order bytes).
pub const Addr = dev.ip.Addr;
pub const Clock = dev.device.Clock;
pub const WaitHandle = wg_tun.WaitHandle;

pub const Endpoint = struct {
    addr: Addr,
    port: u16,

    pub fn format(e: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}:{d}", .{ e.addr, e.port });
    }
};

/// Hard bounds. Worst-case memory is about
///   max_connections * (send_buffer + recv_buffer)       stream buffers
/// + 2 * ring_packets * mtu                               the two rings
/// + max_connections * small fixed state (< 1 KiB)
/// (64 * 512 KiB + 2 * 512 * 1420 = ~33.4 MiB with the defaults; buffers
/// are allocated when a connection is established and freed when it ends,
/// so an idle stack holds only the rings).
pub const Limits = struct {
    /// Connections in any state except LISTEN (half-open ones included).
    max_connections: u16 = 64,
    max_listeners: u8 = 8,
    /// Per-connection send buffer: unacknowledged + not yet sent bytes.
    send_buffer: u32 = 256 * 1024,
    /// Per-connection receive buffer: in order, not yet read by the host,
    /// plus out-of-order data (the advertised window is what is left).
    recv_buffer: u32 = 256 * 1024,
    /// Half-open (SYN-RECEIVED) connections per listener. A SYN beyond it
    /// is dropped (the peer retransmits). ISNs are a keyed hash (RFC 6528).
    syn_backlog: u16 = 16,
    /// Established connections waiting for `accept`, per listener.
    accept_backlog: u16 = 16,
    /// Out-of-order segments held per connection (each a byte range of
    /// the receive buffer; only the range bookkeeping is capped here).
    max_ooo_segments: u16 = 32,
    /// Packets per direction in the rings between device and stack.
    ring_packets: u32 = 512,
    /// TIME-WAIT duration (2*MSL; short: both ends are ours, one hop).
    time_wait_ns: u64 = 2 * std.time.ns_per_s,
    /// An orphaned FIN-WAIT-2 (the application closed, the peer ACKed our
    /// FIN but never sends its own) is freed after this long (like Linux
    /// tcp_fin_timeout). A half-closed stream the application still holds
    /// (shutdown) keeps waiting.
    fin_wait2_ns: u64 = 30 * std.time.ns_per_s,
    /// A connect or a retransmission that gets no answer for this long
    /// fails the connection with error.ConnectionTimedOut.
    user_timeout_ns: u64 = 60 * std.time.ns_per_s,
    /// A bulk stream accepts writes only while it has fewer unsent bytes
    /// than this (like TCP_NOTSENT_LOWAT): its backlog stays in the
    /// application, not in front of other traffic.
    bulk_unsent_lowat: u32 = 64 * 1024,
};

/// Scheduling class of a stream. Interactive segments (data, ACKs,
/// retransmissions) always go out before any bulk data; bulk data may
/// fill at most half of the stack -> device ring; bulk control segments
/// (ACKs, window updates, SYN, FIN) are never queued behind bulk data.
/// Within one stream bytes stay ordered: put keystrokes and bulk
/// transfers on separate connections.
pub const Priority = enum { interactive, bulk };

pub const Options = struct {
    /// The stack's own tunnel address (e.g. 10.8.0.1, or an IPv6 address
    /// for a v6-only stack). Listeners bind to the configured addresses
    /// only; packets to any other destination are dropped.
    address: Addr,
    /// Optional IPv6 address next to an IPv4 `address` (e.g. fd0a:8::1):
    /// listeners then accept on both, dial picks by the destination's
    /// family. No v4-mapped IPv6: each family uses its own address.
    address6: ?Addr = null,
    /// Tunnel MTU (the device's). MSS = mtu - 40 for IPv4 (1420 -> 1380),
    /// mtu - 60 for IPv6 (1420 -> 1360).
    mtu: u16 = wg_tun.default_mtu,
    limits: Limits = .{},
    /// Send TCP keepalives after this much idle time (null: never).
    keepalive_idle_ns: ?u64 = null,
    /// Answer ICMP / ICMPv6 echo requests to our addresses ("ping 10.8.0.1").
    icmp_echo: bool = true,
};

pub const CreateError = error{ OutOfMemory, SystemResources, AddressFamilyUnsupported, InvalidMtu, InvalidLimits };
pub const StartError = error{ SystemResources, AlreadyStarted };
pub const ListenError = error{ AddressInUse, TooManyListeners, Closed };
pub const DialError = error{ TooManyConnections, NoPortsAvailable, AddressFamilyUnsupported, Closed };

/// Errors from stream / listener operations.
///   WouldBlock          non-blocking call, nothing to do yet
///   Timeout             a blocking call's own timeout passed (the stream
///                       is still usable)
///   Closed              the handle was closed (or the stack destroyed)
///   ConnectionRefused   the peer answered our SYN with RST
///   ConnectionReset     the peer reset an established connection
///   ConnectionTimedOut  no answer within Limits.user_timeout_ns
///   BrokenPipe          write after shutdown()/close()
pub const AcceptError = error{ WouldBlock, Timeout, Closed };
pub const ReadError = error{ WouldBlock, Timeout, Closed, ConnectionRefused, ConnectionReset, ConnectionTimedOut };
pub const WriteError = error{ WouldBlock, Timeout, Closed, ConnectionRefused, ConnectionReset, ConnectionTimedOut, BrokenPipe };
pub const ConnectError = error{ WouldBlock, Timeout, Closed, ConnectionRefused, ConnectionReset, ConnectionTimedOut };

pub const State = enum { closed, listen, syn_sent, syn_received, established, fin_wait_1, fin_wait_2, closing, time_wait, close_wait, last_ack };

/// Snapshot for event-loop hosts (non-blocking API).
pub const Status = struct {
    state: State,
    /// read() would return data or 0 (end of stream) or an error.
    readable: bool,
    /// write() would accept at least one byte (or return an error).
    writable: bool,
    /// Bytes buffered for read().
    read_available: usize,
    /// Free bytes in the send buffer.
    write_available: usize,
};

pub const Stats = struct {
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    dropped_malformed: u64 = 0,
    dropped_not_for_us: u64 = 0,
    dropped_ring_full: u64 = 0,
    dropped_syn_backlog: u64 = 0,
    dropped_ooo: u64 = 0,
    rst_sent: u64 = 0,
    retransmits: u64 = 0,
    fast_retransmits: u64 = 0,
    /// Retransmission timer expirations (each a go-back-N restart).
    rto_expirations: u64 = 0,
    /// SACK blocks rejected (outside [snd_una, snd_max], malformed) or
    /// dropped because the scoreboard was full.
    sack_blocks_ignored: u64 = 0,
    /// Tail loss probes sent (interactive streams, RFC 8985).
    tail_loss_probes: u64 = 0,
    timeouts: u64 = 0,
    /// ICMP and ICMPv6 echo replies sent.
    icmp_echo_replies: u64 = 0,
    connections: u16 = 0,
};

/// The stack. Heap-allocated; it must outlive every Stream and Listener
/// handle (handles are generation-checked: a stale one returns Closed).
pub const Stack = stack_impl.Stack;

/// A listening port on `Options.address`. A value handle (copyable).
pub const Listener = stack_impl.Listener;

/// One TCP connection. A value handle (copyable); `close()` releases it.
/// Every method is thread-safe; one reader thread and one writer thread
/// per stream at a time.
pub const Stream = stack_impl.Stream;

/// Device + Stack + both threads in one object: what Portal embeds.
/// `start` creates the stack, creates the device with `stack.tun()` as its
/// Tun, starts the stack thread and the device thread. `destroy` stops
/// both, joins them, destroys the device (keys wiped) and the stack
/// (buffers wiped).
pub const Node = stack_impl.Node;

test {
    std.testing.refAllDecls(@This());
    _ = wire;
    _ = testing;
    _ = stack_impl;
    _ = @import("tcp.zig");
    _ = @import("stack_test.zig");
    _ = @import("fuzz.zig");
}