//! The stack: connection table, listeners, locking, the stack thread, the
//! output scheduler and the Tun the device sees. Per-connection TCP logic
//! lives in tcp.zig; wire formats in wire.zig.
//!
//! Locking: one mutex (`std.Io.Mutex`) guards everything except the two
//! rings (SPSC, lock-free, see tun/queue.zig) and `out_stalled`. Host calls
//! block on a per-slot `std.Io.Condition` with a deadline; nothing polls.
//!
//! Output scheduler (each packet, in this order): control replies (RST,
//! ICMP), then interactive connections (any segment), then bulk
//! connections' control-only segments (ACKs, window updates, SYN, bare
//! FIN), then bulk data, round-robin within each class. Bulk data may fill
//! at most half of the stack -> device ring, so interactive packets
//! always find room.
const std = @import("std");
const root = @import("root.zig");
const wire = @import("wire.zig");
const tcp = @import("tcp.zig");
const wg_tun = @import("../tun/root.zig");
const Cidr = @import("../ip.zig").Cidr;
const dev = @import("../device/root.zig");
const queue = wg_tun.queue;
const os = dev.os;

const Options = root.Options;
const Endpoint = root.Endpoint;
const Addr = root.Addr;
const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);

/// Control replies (RSTs to strays, ICMP echo replies) queued at once.
const ctl_packets = 16;
/// RFC 6335 dynamic port range.
const ephemeral_lo: u16 = 49152;
const ephemeral_count: u32 = 65536 - @as(u32, ephemeral_lo);
/// Inbound packets handled per stack-loop turn before timers and output
/// run again (the loop comes straight back if more are waiting).
const inbound_batch = 64;
/// Smallest tunnel MTU accepted (IPv6 minimum; also leaves room for MSS).
const min_mtu = 576;

const Slot = struct {
    used: bool = false,
    /// Bumped on every allocation and on handle release: a stale handle
    /// never matches.
    gen: u16 = 0,
    /// The host holds a Stream handle for it.
    handle_open: bool = false,
    /// Passive connection not yet accepted (half-open or queued).
    listener: ?u8 = null,
    /// Established, waiting in the listener's accept queue.
    queued: bool = false,
    /// Opened by a SYN to one of our listeners (stays set after accept):
    /// what the per-source limits count.
    passive: bool = false,
    /// Allocation order (oldest first when evicting).
    born: u64 = 0,
    accept_seq: u64 = 0,
    conn: tcp.Conn = .{ .local = undefined, .remote = undefined },
    /// Never reinitialised (a woken waiter may still touch it).
    cond: std.Io.Condition = .init,
};

const ListenSlot = struct {
    open: bool = false,
    gen: u16 = 0,
    port: u16 = 0,
    cond: std.Io.Condition = .init,
};

/// ::ffff:0:0/96 (IPv4-mapped IPv6): never used, each family has its own.
fn isV4Mapped(a: Addr) bool {
    return switch (a) {
        .v4 => false,
        .v6 => |b| std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff,
    };
}

/// IPv6 addresses that are never a unicast peer on the tunnel: the
/// unspecified address (::), loopback (::1), multicast (ff00::/8) and
/// v4-mapped (::ffff:0:0/96). False for IPv4 (Stack.bogusSource holds the
/// IPv4 side). Packets from them are dropped before TCP or ICMPv6 see
/// them (so no RST and no echo reply goes to such an address), and dial
/// refuses them.
fn notUnicastPeer6(a: Addr) bool {
    const b = switch (a) {
        .v4 => return false,
        .v6 => |b| b,
    };
    if (b[0] == 0xff) return true;
    if (isV4Mapped(a)) return true;
    return std.mem.allEqual(u8, b[0..15], 0) and b[15] <= 1;
}

fn handleId(index: usize, gen: u16) u32 {
    return (@as(u32, gen) << 16) | @as(u32, @intCast(index));
}

/// How long the stack loop waits per pass after its event wait failed.
const wait_failed_pace_ns: u64 = 20 * std.time.ns_per_ms;

fn timeoutFrom(io: std.Io, timeout_ns: ?u64) std.Io.Timeout {
    const ns = timeout_ns orelse return .none;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromNanoseconds(@intCast(@min(ns, std.math.maxInt(i64)))), .clock = .awake } };
    return t.toDeadline(io);
}

pub const Stack = struct {
    gpa: std.mem.Allocator,
    clock: *root.Clock,
    io: std.Io,
    options: Options,

    mutex: std.Io.Mutex = .init,
    slots: []Slot,
    listeners: []ListenSlot,

    /// device -> stack (consumer: stack thread).
    inbound: queue.Channel,
    /// stack -> device (consumer: device thread; its wait handle is the Tun's).
    outbound: queue.Channel,
    ctl: queue.PacketRing,
    kick: queue.Waker,
    ready: queue.Waker,
    timer: os.DeadlineTimer,
    armed: ?i64 = null,
    /// The stack stopped filling the outbound ring (full, or bulk at its
    /// share): the device's read kicks the stack once it drains.
    out_stalled: std.atomic.Value(bool) = .init(false),
    inbound_drops: std.atomic.Value(u64) = .init(0),

    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    /// The loop's wait failed once (logged; see `loop`).
    wait_failed: bool = false,

    isn_key: [SipHash.key_length]u8,
    ip_id: u16 = 0,
    accept_counter: u64 = 0,
    alloc_counter: u64 = 0,
    next_port: u32,
    rr: usize = 0,
    st: root.Stats = .{},
    notify_host: bool = false,
    ready_ctx: ?*anyopaque = null,
    ready_fn: ?*const fn (?*anyopaque) void = null,

    in_buf: []u8,
    out_buf: []u8,
    scratch: []u8,

    // ---- lifecycle -------------------------------------------------------

    pub fn create(gpa: std.mem.Allocator, clock: *root.Clock, options: Options) root.CreateError!*Stack {
        // At most one address per family: `address` (either), `address6`
        // (IPv6, only next to an IPv4 `address`). No v4-mapped addresses.
        if (options.address6) |a6| {
            if (a6 != .v6 or options.address != .v4) return error.AddressFamilyUnsupported;
            if (isV4Mapped(a6)) return error.AddressFamilyUnsupported;
        }
        if (isV4Mapped(options.address)) return error.AddressFamilyUnsupported;
        if (options.mtu < min_mtu) return error.InvalidMtu;
        const l = options.limits;
        if (l.max_connections == 0 or l.send_buffer == 0 or l.recv_buffer == 0 or
            l.syn_backlog_per_source == 0 or l.max_connections_per_source == 0 or
            l.max_ooo_segments > tcp.max_ooo_ranges or l.ring_packets < 4 or l.recv_buffer > (0xffff << wire.max_window_scale))
            return error.InvalidLimits;

        const s = try gpa.create(Stack);
        errdefer gpa.destroy(s);
        const slots = try gpa.alloc(Slot, l.max_connections);
        errdefer gpa.free(slots);
        @memset(slots, .{});
        const listeners = try gpa.alloc(ListenSlot, l.max_listeners);
        errdefer gpa.free(listeners);
        @memset(listeners, .{});
        var inbound = try queue.Channel.init(gpa, l.ring_packets, options.mtu);
        errdefer inbound.deinit(gpa);
        var outbound = try queue.Channel.init(gpa, l.ring_packets, options.mtu);
        errdefer outbound.deinit(gpa);
        var ctl = try queue.PacketRing.init(gpa, ctl_packets, options.mtu);
        errdefer ctl.deinit(gpa);
        var kick = try queue.Waker.init();
        errdefer kick.deinit();
        var ready = try queue.Waker.init();
        errdefer ready.deinit();
        var timer = os.DeadlineTimer.init() catch return error.SystemResources;
        errdefer timer.deinit();
        const bufs = try gpa.alloc(u8, 3 * @as(usize, options.mtu));
        errdefer gpa.free(bufs);

        var key: [SipHash.key_length]u8 = undefined;
        clock.io.random(&key);
        var port_seed: [4]u8 = undefined;
        clock.io.random(&port_seed);

        s.* = .{
            .gpa = gpa,
            .clock = clock,
            .io = clock.io,
            .options = options,
            .slots = slots,
            .listeners = listeners,
            .inbound = inbound,
            .outbound = outbound,
            .ctl = ctl,
            .kick = kick,
            .ready = ready,
            .timer = timer,
            .isn_key = key,
            .next_port = std.mem.readInt(u32, &port_seed, .little) % ephemeral_count,
            .in_buf = bufs[0..options.mtu],
            .out_buf = bufs[options.mtu..][0..options.mtu],
            .scratch = bufs[2 * @as(usize, options.mtu) ..],
        };
        std.crypto.secureZero(u8, &key);
        return s;
    }

    /// Stops the stack thread (if started), wipes and frees everything.
    /// Stop the device first, and make sure no host call is still running
    /// (`abortAll` wakes blocked ones; join the host threads after it).
    pub fn destroy(s: *Stack) void {
        s.stop();
        const gpa = s.gpa;
        for (s.slots) |*sl| sl.conn.freeBuffers(gpa);
        gpa.free(s.slots);
        gpa.free(s.listeners);
        // Plaintext packets may sit in the rings: zero, not just free.
        std.crypto.secureZero(u8, s.inbound.ring.storage);
        std.crypto.secureZero(u8, s.outbound.ring.storage);
        std.crypto.secureZero(u8, s.ctl.storage);
        s.inbound.deinit(gpa);
        s.outbound.deinit(gpa);
        s.ctl.deinit(gpa);
        s.kick.deinit();
        s.ready.deinit();
        s.timer.deinit();
        const bufs = s.in_buf.ptr[0 .. 3 * @as(usize, s.options.mtu)];
        std.crypto.secureZero(u8, bufs);
        gpa.free(bufs);
        std.crypto.secureZero(u8, &s.isn_key);
        gpa.destroy(s);
    }

    pub fn tun(s: *Stack) wg_tun.Tun {
        return .{ .ptr = s, .vtable = &tun_vtable };
    }

    pub fn start(s: *Stack) root.StartError!void {
        if (s.thread != null) return error.AlreadyStarted;
        s.stopping.store(false, .release);
        s.thread = std.Thread.spawn(.{}, loop, .{s}) catch return error.SystemResources;
    }

    pub fn stop(s: *Stack) void {
        const t = s.thread orelse return;
        s.stopping.store(true, .release);
        s.kick.signal();
        t.join();
        s.thread = null;
    }

    /// Resets every connection (the peer gets RSTs), closes every
    /// listener and wakes every blocked call (they fail with
    /// ConnectionReset or Closed). Handles stay valid until closed.
    pub fn abortAll(s: *Stack) void {
        s.lock();
        defer s.unlock();
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used) continue;
            const c = &sl.conn;
            if (c.state != .closed and c.state != .syn_sent) s.sendRst(c.local, c.remote, .{ .seq = c.snd_max, .ack = null });
            if (c.state != .closed) c.fail(error.ConnectionReset);
            sl.queued = false;
            sl.listener = null;
            s.notifySlot(sl);
            s.maybeRelease(i);
        }
        for (s.listeners) |*l| {
            if (!l.open) continue;
            l.open = false;
            l.gen +%= 1;
            l.cond.broadcast(s.io);
        }
        s.kickThread();
    }

    // ---- locking and wakeups ------------------------------------------------

    fn lock(s: *Stack) void {
        s.mutex.lockUncancelable(s.io);
    }

    fn unlock(s: *Stack) void {
        const notify = s.notify_host;
        s.notify_host = false;
        const f = s.ready_fn;
        const ctx = s.ready_ctx;
        if (notify) s.ready.signal();
        s.mutex.unlock(s.io);
        if (notify) if (f) |cb| cb(ctx);
    }

    fn notifySlot(s: *Stack, sl: *Slot) void {
        sl.cond.broadcast(s.io);
        s.notify_host = true;
    }

    /// The stack thread has output to produce (host side changed state).
    fn kickThread(s: *Stack) void {
        if (s.thread != null) s.kick.signal();
    }

    /// Our address for `family_of`'s family, if configured.
    fn localFor(s: *const Stack, family_of: Addr) ?Addr {
        if (std.meta.activeTag(s.options.address) == std.meta.activeTag(family_of)) return s.options.address;
        if (s.options.address6) |a6| if (family_of == .v6) return a6;
        return null;
    }

    fn isOurs(s: *const Stack, a: Addr) bool {
        const mine = s.localFor(a) orelse return false;
        return mine.eql(a);
    }

    /// The one source filter, either family (RFC 1122 3.2.1.3, RFC 9293
    /// 3.10.7.2: a SYN from such a source gets no SYN-ACK, nothing else
    /// gets a reply either): one of our own addresses; IPv4 0.0.0.0,
    /// 255.255.255.255 and 224.0.0.0/4; IPv6 per notUnicastPeer6. No
    /// prefix is configured (the device's tunSetAddress is a no-op), so
    /// there is no subnet broadcast to know.
    fn bogusSource(s: *const Stack, a: Addr) bool {
        if (s.isOurs(a)) return true;
        return switch (a) {
            .v4 => |b| std.mem.allEqual(u8, &b, 0) or std.mem.allEqual(u8, &b, 0xff) or
                b[0] & 0xf0 == 224, // 224.0.0.0/4
            .v6 => notUnicastPeer6(a),
        };
    }

    test bogusSource {
        var clock: root.Clock = .{ .io = std.testing.io };
        const own6: Addr = .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
        const s = try Stack.create(std.testing.allocator, &clock, .{ .address = .{ .v4 = .{ 10, 8, 0, 1 } }, .address6 = own6 });
        defer s.destroy();
        for ([_]Addr{
            .{ .v4 = .{ 0, 0, 0, 0 } },                                           .{ .v4 = .{ 255, 255, 255, 255 } },
            .{ .v4 = .{ 224, 0, 0, 5 } },                                         .{ .v4 = .{ 239, 255, 255, 250 } },
            .{ .v4 = .{ 10, 8, 0, 1 } },                                          .{ .v6 = @splat(0) },
            .{ .v6 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, own6,
        }) |a| try std.testing.expect(s.bogusSource(a));
        for ([_]Addr{
            .{ .v4 = .{ 10, 8, 0, 2 } },  .{ .v4 = .{ 223, 255, 255, 255 } },
            .{ .v4 = .{ 240, 0, 0, 1 } }, .{ .v6 = .{ 0xfd, 0x0a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } },
        }) |a| try std.testing.expect(!s.bogusSource(a));
    }

    fn env(s: *Stack, now: i64) tcp.Env {
        return .{
            .now = now,
            .gpa = s.gpa,
            .limits = &s.options.limits,
            .mtu = s.options.mtu,
            .keepalive_idle_ns = s.options.keepalive_idle_ns,
            .stats = &s.st,
        };
    }

    // ---- the stack thread ---------------------------------------------------

    fn loop(s: *Stack) void {
        var busy = false;
        while (!s.stopping.load(.acquire)) {
            s.kick.clear();
            s.lock();
            var n: usize = 0;
            while (n < inbound_batch) : (n += 1) {
                const p = (s.inbound.recv(s.in_buf) catch continue) orelse break;
                s.inputLocked(p);
            }
            busy = n == inbound_batch;
            const now = s.clock.now();
            _ = s.timersLocked(now);
            s.flushLocked();
            // After the flush: sending arms retransmission timers.
            const deadline = s.earliestDeadline();
            s.unlock();

            var handles: [3]os.WaitHandle = undefined;
            var hn: usize = 0;
            handles[hn] = s.kick.handle;
            hn += 1;
            handles[hn] = s.inbound.handle();
            hn += 1;
            const timer_index = hn;
            if (s.timer.waitHandle()) |h| {
                handles[hn] = h;
                hn += 1;
            }
            const timeout: ?u64 = if (busy) 0 else if (deadline) |d| @intCast(@max(d - now, 0)) else null;
            if (!busy and deadline != s.armed) {
                if (deadline) |d| s.timer.arm(@intCast(@max(d - now, 0))) else s.timer.disarm();
                s.armed = deadline;
            }
            const r = os.wait(handles[0..hn], timeout) catch blk: {
                // Only a broken handle makes the wait fail, and it stays
                // broken: say so once, then pace the loop to its deadline
                // (at most 20 ms) instead of spinning a core.
                if (!s.wait_failed) std.log.scoped(.netstack).err("stack wait failed; pacing the loop to its deadlines", .{});
                s.wait_failed = true;
                const pace: u64 = @min(timeout orelse wait_failed_pace_ns, wait_failed_pace_ns);
                if (pace > 0) s.io.sleep(.fromNanoseconds(@intCast(pace)), .awake) catch {};
                break :blk null;
            };
            if (r) |i| if (i == timer_index and hn > timer_index) {
                s.timer.clear();
                s.armed = null;
            };
        }
    }

    /// Moves packets into the outbound ring while the scheduler has any
    /// and the ring has room for them.
    fn flushLocked(s: *Stack) void {
        const ring = &s.outbound.ring;
        const cap = ring.capacity();
        while (true) {
            const occupancy = ring.tail.raw -% ring.head.load(.acquire);
            if (occupancy >= cap) {
                if (s.stallRecheck(cap)) continue;
                return;
            }
            const bulk_ok = occupancy < bulkRingShare(cap);
            const p = s.nextPacket(s.out_buf, bulk_ok) orelse {
                if (!bulk_ok and s.stallRecheck(cap)) continue;
                return;
            };
            s.outbound.send(p) catch {
                s.st.dropped_ring_full += 1;
                return;
            };
        }
    }

    /// Marks the ring stalled (the device's read kicks us once it has
    /// drained to a quarter), then re-checks: if the device drained it
    /// before seeing the mark, nobody would wake us. True = go on now.
    fn stallRecheck(s: *Stack, cap: u32) bool {
        s.out_stalled.store(true, .seq_cst);
        const ring = &s.outbound.ring;
        const occupancy = ring.tail.raw -% ring.head.load(.seq_cst);
        if (occupancy <= cap / 4) {
            s.out_stalled.store(false, .seq_cst);
            return true;
        }
        return false;
    }

    /// The most packets bulk data may have in the outbound ring.
    fn bulkRingShare(cap: u32) u32 {
        return cap / 2;
    }

    // ---- manual drive --------------------------------------------------------

    pub fn input(s: *Stack, packet: []const u8) void {
        s.lock();
        defer s.unlock();
        s.inputLocked(packet);
    }

    pub fn output(s: *Stack, buf: []u8) ?[]u8 {
        s.lock();
        defer s.unlock();
        return s.nextPacket(buf, true);
    }

    pub fn runTimers(s: *Stack) ?i64 {
        s.lock();
        defer s.unlock();
        return s.timersLocked(s.clock.now());
    }

    // ---- input ----------------------------------------------------------------

    fn inputLocked(s: *Stack, pkt: []const u8) void {
        s.st.rx_packets += 1;
        const ip = wire.parseIp(pkt) catch {
            s.st.dropped_malformed += 1;
            return;
        };
        if (!s.isOurs(ip.dst)) {
            s.st.dropped_not_for_us += 1;
            return;
        }
        // A source that cannot be a peer, or our own address: spoofed or
        // looped (either family, see bogusSource).
        if (s.bogusSource(ip.src)) {
            s.st.dropped_not_for_us += 1;
            return;
        }
        switch (ip.protocol) {
            wire.proto_tcp => {
                const seg = wire.Tcp.parse(ip.src, ip.dst, ip.payload) catch {
                    s.st.dropped_malformed += 1;
                    return;
                };
                s.handleTcp(.{ .addr = ip.dst, .port = seg.dst_port }, .{ .addr = ip.src, .port = seg.src_port }, seg);
            },
            wire.proto_icmp => if (ip.src == .v4) s.handleIcmp(ip.src, ip.dst, ip.payload) else {
                s.st.dropped_not_for_us += 1;
            },
            wire.proto_icmp6 => if (ip.src == .v6) s.handleIcmp(ip.src, ip.dst, ip.payload) else {
                s.st.dropped_not_for_us += 1;
            },
            else => s.st.dropped_not_for_us += 1,
        }
    }

    /// Echo request -> echo reply, ICMPv4 or ICMPv6 (same layout: type,
    /// code, checksum, identifier, sequence, data). Anything else is
    /// ignored (no NDP: a point-to-point tunnel with configured addresses).
    fn handleIcmp(s: *Stack, src: Addr, dst: Addr, msg: []const u8) void {
        const v6 = src == .v6;
        const kind = (if (v6) wire.icmp6Type(src, dst, msg) else wire.icmp4Type(msg)) catch {
            s.st.dropped_malformed += 1;
            return;
        };
        if (kind != (if (v6) wire.icmp6_echo_request else wire.icmp_echo_request) or !s.options.icmp_echo) return;
        const hl = wire.ipHeaderLen(src);
        if (hl + msg.len > s.scratch.len) return;
        const reply = s.scratch[hl..][0..msg.len];
        @memcpy(reply, msg);
        reply[0] = if (v6) wire.icmp6_echo_reply else wire.icmp_echo_reply;
        @memset(reply[2..4], 0);
        const sum = if (v6) wire.icmp6Checksum(dst, src, reply) else wire.checksum(reply);
        std.mem.writeInt(u16, reply[2..4], sum, .big);
        s.ip_id +%= 1;
        _ = wire.writeIpHeader(s.scratch, dst, src, if (v6) wire.proto_icmp6 else wire.proto_icmp, s.ip_id, msg.len) catch return;
        s.ctl.push(s.scratch[0 .. hl + msg.len]) catch return;
        s.st.icmp_echo_replies += 1;
    }

    fn handleTcp(s: *Stack, local: Endpoint, remote: Endpoint, seg: wire.Tcp) void {
        const now = s.clock.now();
        var e = s.env(now);
        if (s.findConn(local, remote)) |i| {
            if (s.acceptQueueFull(i, seg)) {
                s.st.dropped_accept_backlog += 1;
                return;
            }
            const out = s.slots[i].conn.input(&e, seg);
            s.afterOutcome(i, out);
            return;
        }
        if (seg.flags.rst) return;
        if (seg.flags.syn and !seg.flags.ack) {
            if (s.findListener(seg.dst_port)) |li| {
                const lim = s.options.limits;
                // Per-source caps first, so that one remote address can
                // only use up its own share of the listener's backlog and
                // of the connection table.
                if (s.countFromSource(remote.addr, .half_open) >= lim.syn_backlog_per_source) {
                    if (s.oldestFromSource(remote.addr, .half_open)) |old| s.evict(old);
                }
                if (s.countFromSource(remote.addr, .past_handshake) >= lim.max_connections_per_source) {
                    const old = s.oldestFromSource(remote.addr, .time_wait) orelse {
                        s.st.dropped_source_limit += 1;
                        return;
                    };
                    s.evict(old);
                }
                if (s.countForListener(li) >= @as(usize, s.options.limits.syn_backlog) + s.options.limits.accept_backlog or
                    s.countHalfOpen(li) >= s.options.limits.syn_backlog)
                {
                    s.st.dropped_syn_backlog += 1;
                    return;
                }
                const i = s.allocSlot() orelse {
                    s.st.dropped_syn_backlog += 1;
                    return;
                };
                const sl = &s.slots[i];
                sl.listener = li;
                sl.passive = true;
                sl.conn = .{ .local = local, .remote = remote };
                sl.conn.acceptSyn(&e, seg, s.isn(local, remote, now));
                return;
            }
        }
        s.sendRst(local, remote, tcp.rstFor(seg));
    }

    fn afterOutcome(s: *Stack, i: usize, out: tcp.Outcome) void {
        const sl = &s.slots[i];
        if (out.rst) |r| s.sendRst(sl.conn.local, sl.conn.remote, r);
        if (out.established) {
            if (sl.listener) |li| {
                sl.queued = true;
                s.accept_counter += 1;
                sl.accept_seq = s.accept_counter;
                s.listeners[li].cond.broadcast(s.io);
                s.notify_host = true;
            }
        }
        if (out.notify) s.notifySlot(sl);
        s.orphanTimers(sl);
        s.maybeRelease(i);
    }

    /// Arms the orphan deadlines (tcp.Conn.orphan) once the host has let go.
    fn orphanTimers(s: *Stack, sl: *Slot) void {
        if (sl.handle_open) return;
        switch (sl.conn.state) {
            .fin_wait_1, .fin_wait_2, .closing, .last_ack => {},
            else => return,
        }
        const e = s.env(s.clock.now());
        sl.conn.orphan(&e);
    }

    /// RST the peer (if it knows the connection) and fail it locally.
    fn resetLocked(s: *Stack, sl: *Slot) void {
        const c = &sl.conn;
        switch (c.state) {
            .closed, .syn_sent => {},
            else => s.sendRst(c.local, c.remote, .{ .seq = c.snd_max, .ack = null }),
        }
        if (c.state != .closed) c.fail(error.ConnectionReset);
    }

    fn maybeRelease(s: *Stack, i: usize) void {
        const sl = &s.slots[i];
        if (!sl.used or sl.conn.state != .closed or sl.handle_open) return;
        sl.conn.freeBuffers(s.gpa);
        sl.used = false;
        sl.queued = false;
        sl.listener = null;
        s.st.connections -|= 1;
    }

    fn sendRst(s: *Stack, local: Endpoint, remote: Endpoint, r: tcp.Rst) void {
        s.ip_id +%= 1;
        const p = wire.buildTcp(s.scratch, local.addr, remote.addr, s.ip_id, .{
            .src_port = local.port,
            .dst_port = remote.port,
            .seq = r.seq,
            .ack = r.ack orelse 0,
            .flags = .{ .rst = true, .ack = r.ack != null },
            .window = 0,
        }) catch return;
        s.ctl.push(p) catch return;
        s.st.rst_sent += 1;
    }

    /// RFC 6528: ISN = M + F(4-tuple, secret), M a 4 microsecond clock.
    fn isn(s: *Stack, local: Endpoint, remote: Endpoint, now: i64) u32 {
        var h = SipHash.init(&s.isn_key);
        var port: [2]u8 = undefined;
        h.update(local.addr.bytes());
        std.mem.writeInt(u16, &port, local.port, .big);
        h.update(&port);
        h.update(remote.addr.bytes());
        std.mem.writeInt(u16, &port, remote.port, .big);
        h.update(&port);
        const f: u32 = @truncate(h.finalInt());
        const m: u32 = @truncate(@as(u64, @bitCast(now)) / 4000);
        return f +% m;
    }

    // ---- table lookups (linear: max_connections is small) ---------------------

    fn findConn(s: *Stack, local: Endpoint, remote: Endpoint) ?usize {
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used or sl.conn.state == .closed) continue;
            const c = &sl.conn;
            if (c.local.port == local.port and c.remote.port == remote.port and
                c.remote.addr.eql(remote.addr) and c.local.addr.eql(local.addr)) return i;
        }
        return null;
    }

    fn findListener(s: *Stack, port: u16) ?u8 {
        for (s.listeners, 0..) |*l, i| if (l.open and l.port == port) return @intCast(i);
        return null;
    }

    fn countForListener(s: *Stack, li: u8) usize {
        var n: usize = 0;
        for (s.slots) |*sl| if (sl.used and sl.listener == li) {
            n += 1;
        };
        return n;
    }

    fn countHalfOpen(s: *Stack, li: u8) usize {
        var n: usize = 0;
        for (s.slots) |*sl| if (sl.used and sl.listener == li and sl.conn.state == .syn_received) {
            n += 1;
        };
        return n;
    }

    /// Limits.accept_backlog: an ACK that would complete a passive
    /// handshake while the listener's accept queue is full is dropped, so
    /// the connection stays SYN-RECEIVED (no buffers) and the SYN-ACK
    /// retransmission retries it.
    fn acceptQueueFull(s: *Stack, i: usize, seg: wire.Tcp) bool {
        const sl = &s.slots[i];
        const li = sl.listener orelse return false;
        if (sl.conn.state != .syn_received or !seg.flags.ack or seg.flags.rst or seg.flags.syn) return false;
        var n: usize = 0;
        for (s.slots) |*o| if (o.used and o.queued and o.listener == li) {
            n += 1;
        };
        return n >= s.options.limits.accept_backlog;
    }

    /// A free slot; when the table is full, the oldest TIME-WAIT slot the
    /// host has released is reclaimed for it (TIME-WAIT churn must not
    /// lock out new connections; both ends are ours, one hop away).
    fn allocSlot(s: *Stack) ?usize {
        const i = for (s.slots, 0..) |*sl, i| {
            if (!sl.used) break i;
        } else blk: {
            const old = s.oldestReleasedTimeWait() orelse return null;
            s.evict(old);
            break :blk old;
        };
        const sl = &s.slots[i];
        std.debug.assert(!sl.used);
        sl.used = true;
        sl.gen +%= 1;
        sl.handle_open = false;
        sl.listener = null;
        sl.queued = false;
        sl.passive = false;
        s.alloc_counter += 1;
        sl.born = s.alloc_counter;
        s.st.connections += 1;
        return i;
    }

    const SourceClass = enum {
        /// Passive SYN-RECEIVED, never handed to the host.
        half_open,
        /// Passive, past SYN-RECEIVED (TIME-WAIT and held handles too).
        past_handshake,
        /// Passive TIME-WAIT the host has released.
        time_wait,
    };

    fn inClass(sl: *const Slot, class: SourceClass) bool {
        if (!sl.used or !sl.passive) return false;
        return switch (class) {
            .half_open => sl.conn.state == .syn_received and !sl.handle_open,
            .past_handshake => sl.conn.state != .syn_received,
            .time_wait => sl.conn.state == .time_wait and !sl.handle_open,
        };
    }

    fn countFromSource(s: *Stack, addr: Addr, class: SourceClass) usize {
        var n: usize = 0;
        for (s.slots) |*sl| if (inClass(sl, class) and sl.conn.remote.addr.eql(addr)) {
            n += 1;
        };
        return n;
    }

    fn oldestFromSource(s: *Stack, addr: Addr, class: SourceClass) ?usize {
        var best: ?usize = null;
        for (s.slots, 0..) |*sl, i| {
            if (!inClass(sl, class) or !sl.conn.remote.addr.eql(addr)) continue;
            if (best == null or sl.born < s.slots[best.?].born) best = i;
        }
        return best;
    }

    /// Oldest TIME-WAIT slot (any direction) the host no longer holds.
    fn oldestReleasedTimeWait(s: *Stack) ?usize {
        var best: ?usize = null;
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used or sl.handle_open or sl.conn.state != .time_wait) continue;
            if (best == null or sl.born < s.slots[best.?].born) best = i;
        }
        return best;
    }

    /// Frees a half-open slot (RST to the peer) or a released TIME-WAIT
    /// one (silently) to make room.
    fn evict(s: *Stack, i: usize) void {
        const sl = &s.slots[i];
        std.debug.assert(sl.used and !sl.handle_open);
        if (sl.conn.state == .syn_received) s.resetLocked(sl) else sl.conn.fail(error.ConnectionReset);
        sl.queued = false;
        sl.listener = null;
        s.maybeRelease(i);
        std.debug.assert(!sl.used);
        s.st.evicted += 1;
    }

    fn portInUse(s: *Stack, port: u16) bool {
        for (s.slots) |*sl| if (sl.used and sl.conn.local.port == port) return true;
        for (s.listeners) |*l| if (l.open and l.port == port) return true;
        return false;
    }

    // ---- timers -----------------------------------------------------------------

    fn earliestDeadline(s: *Stack) ?i64 {
        var earliest: ?i64 = null;
        for (s.slots) |*sl| {
            if (!sl.used) continue;
            if (sl.conn.nextDeadline()) |d| earliest = if (earliest) |x| @min(x, d) else d;
        }
        return earliest;
    }

    fn timersLocked(s: *Stack, now: i64) ?i64 {
        var e = s.env(now);
        var earliest: ?i64 = null;
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used) continue;
            if (sl.conn.nextDeadline()) |d| if (d <= now) {
                const out = sl.conn.onTimers(&e);
                s.afterOutcome(i, out);
                if (!sl.used) continue;
            };
            if (sl.conn.nextDeadline()) |d| earliest = if (earliest) |x| @min(x, d) else d;
        }
        return earliest;
    }

    // ---- output scheduler -------------------------------------------------------

    fn nextPacket(s: *Stack, buf: []u8, bulk_ok: bool) ?[]u8 {
        if (s.ctl.pop(buf) catch null) |p| {
            s.st.tx_packets += 1;
            return p;
        }
        const e = s.env(s.clock.now());
        const passes = [_]struct { prio: root.Priority, class: tcp.OutputClass }{
            .{ .prio = .interactive, .class = .any },
            .{ .prio = .bulk, .class = .control },
            .{ .prio = .bulk, .class = .any },
        };
        for (passes) |pass| {
            if (pass.prio == .bulk and pass.class == .any and !bulk_ok) break;
            const n = s.slots.len;
            for (0..n) |k| {
                const i = (s.rr + k) % n;
                const sl = &s.slots[i];
                if (!sl.used or sl.conn.priority != pass.prio) continue;
                const was_full = sl.handle_open and sl.conn.writeRoom(&s.options.limits) == 0;
                s.ip_id +%= 1;
                const p = sl.conn.output(&e, buf, s.ip_id, pass.class) orelse continue;
                s.rr = i + 1;
                s.st.tx_packets += 1;
                // A writer blocked on the unsent low-watermark may go on.
                if (was_full and sl.conn.writeRoom(&s.options.limits) > 0) s.notifySlot(sl);
                return p;
            }
        }
        return null;
    }

    // ---- host API ---------------------------------------------------------------

    pub fn listen(s: *Stack, port: u16) root.ListenError!Listener {
        s.lock();
        defer s.unlock();
        if (port == 0 or s.findListener(port) != null) return error.AddressInUse;
        for (s.listeners, 0..) |*l, i| {
            if (l.open) continue;
            l.open = true;
            l.gen +%= 1;
            l.port = port;
            return .{ .stack = s, .id = handleId(i, l.gen) };
        }
        return error.TooManyListeners;
    }

    pub fn dial(s: *Stack, to: Endpoint) root.DialError!Stream {
        return s.dialWith(to, .interactive);
    }

    /// dial with a priority from the first byte on.
    pub fn dialWith(s: *Stack, to: Endpoint, priority: root.Priority) root.DialError!Stream {
        // The destination's family picks our address; no v4-mapped IPv6.
        const local_addr = s.localFor(to.addr) orelse return error.AddressFamilyUnsupported;
        if (to.port == 0 or notUnicastPeer6(to.addr) or local_addr.eql(to.addr)) return error.AddressFamilyUnsupported;
        s.lock();
        defer s.unlock();
        const port = s.pickPort() orelse return error.NoPortsAvailable;
        const i = s.allocSlot() orelse return error.TooManyConnections;
        const sl = &s.slots[i];
        const local: Endpoint = .{ .addr = local_addr, .port = port };
        sl.conn = .{ .local = local, .remote = to, .priority = priority };
        const now = s.clock.now();
        const e = s.env(now);
        sl.conn.connect(&e, s.isn(local, to, now)) catch {
            sl.conn.state = .closed;
            s.maybeRelease(i);
            return error.TooManyConnections; // buffer allocation failed
        };
        sl.handle_open = true;
        s.kickThread();
        return .{ .stack = s, .id = handleId(i, sl.gen) };
    }

    fn pickPort(s: *Stack) ?u16 {
        var k: u32 = 0;
        while (k < ephemeral_count) : (k += 1) {
            s.next_port = (s.next_port + 1) % ephemeral_count;
            const p: u16 = @intCast(ephemeral_lo + s.next_port);
            if (!s.portInUse(p)) return p;
        }
        return null;
    }

    pub fn dialWait(s: *Stack, to: Endpoint, timeout_ns: ?u64) (root.DialError || root.ConnectError)!Stream {
        const st = try s.dial(to);
        st.waitConnected(timeout_ns) catch |e| {
            st.abort();
            return e;
        };
        return st;
    }

    pub fn readyHandle(s: *Stack) root.WaitHandle {
        return s.ready.handle;
    }

    /// Calls `f(ctx)` whenever `readyHandle` is signalled (a stream or
    /// listener may have become readable, writable, acceptable, connected
    /// or closed). It runs on the stack thread, or on a host thread whose
    /// call changed state (e.g. close), after the stack's lock is released.
    /// It must be quick and must not block; it should only wake the host
    /// (signal a condition / event) and not call back into the stack.
    /// null removes it.
    pub fn setReadyCallback(s: *Stack, ctx: ?*anyopaque, f: ?*const fn (?*anyopaque) void) void {
        s.lock();
        defer s.unlock();
        s.ready_ctx = ctx;
        s.ready_fn = f;
    }

    pub fn clearReady(s: *Stack) void {
        s.ready.clear();
    }

    pub fn stats(s: *Stack) root.Stats {
        s.lock();
        defer s.unlock();
        var r = s.st;
        r.dropped_ring_full += s.inbound_drops.load(.monotonic);
        return r;
    }

    // ---- handle validation ------------------------------------------------------

    fn slotOf(s: *Stack, id: u32) ?*Slot {
        const i: usize = id & 0xffff;
        if (i >= s.slots.len) return null;
        const sl = &s.slots[i];
        if (!sl.used or !sl.handle_open or sl.gen != @as(u16, @truncate(id >> 16))) return null;
        return sl;
    }

    fn listenerOf(s: *Stack, id: u32) ?*ListenSlot {
        const i: usize = id & 0xffff;
        if (i >= s.listeners.len) return null;
        const l = &s.listeners[i];
        if (!l.open or l.gen != @as(u16, @truncate(id >> 16))) return null;
        return l;
    }

    /// Waits on `cond`; Timeout when `deadline` passes.
    fn waitOn(s: *Stack, cond: *std.Io.Condition, deadline: std.Io.Timeout) error{ Timeout, Closed }!void {
        cond.waitTimeout(s.io, &s.mutex, deadline) catch |e| switch (e) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Closed,
        };
    }

    // ---- tun --------------------------------------------------------------------

    const tun_vtable: wg_tun.Tun.VTable = .{
        .waitHandle = tunWaitHandle,
        .read = tunRead,
        .write = tunWrite,
        .mtu = tunMtu,
        .setAddress = tunSetAddress,
        .addRoute = tunAddRoute,
    };

    fn fromPtr(ptr: *anyopaque) *Stack {
        return @ptrCast(@alignCast(ptr));
    }

    fn tunWaitHandle(ptr: *anyopaque) wg_tun.WaitHandle {
        return fromPtr(ptr).outbound.handle();
    }

    /// Device thread. After taking packets, wake the stack if it stopped
    /// filling the ring and the ring has drained to a quarter.
    fn tunRead(ptr: *anyopaque, buf: []u8) wg_tun.ReadError!?[]u8 {
        const s = fromPtr(ptr);
        const p = s.outbound.recv(buf) catch return error.BufferTooSmall;
        if (s.out_stalled.load(.seq_cst)) {
            const ring = &s.outbound.ring;
            const occupancy = ring.tail.load(.seq_cst) -% ring.head.raw;
            if (occupancy <= ring.capacity() / 4 and s.out_stalled.swap(false, .seq_cst)) s.kick.signal();
        }
        return p;
    }

    /// Device thread: hand the packet to the stack thread.
    fn tunWrite(ptr: *anyopaque, packet: []const u8) wg_tun.WriteError!void {
        const s = fromPtr(ptr);
        s.inbound.send(packet) catch |e| {
            _ = s.inbound_drops.fetchAdd(1, .monotonic);
            return switch (e) {
                error.QueueFull => error.QueueFull,
                error.PacketTooLarge => error.PacketTooLarge,
            };
        };
    }

    fn tunMtu(ptr: *anyopaque) u16 {
        return fromPtr(ptr).options.mtu;
    }

    /// The address is Options.address; nothing to configure.
    fn tunSetAddress(_: *anyopaque, _: Cidr) wg_tun.ConfigError!void {}
    fn tunAddRoute(_: *anyopaque, _: Cidr) wg_tun.ConfigError!void {}
};

pub const Listener = struct {
    stack: *Stack,
    id: u32,

    pub fn port(l: Listener) u16 {
        const s = l.stack;
        s.lock();
        defer s.unlock();
        const ls = s.listenerOf(l.id) orelse return 0;
        return ls.port;
    }

    pub fn accept(l: Listener) root.AcceptError!Stream {
        const s = l.stack;
        s.lock();
        defer s.unlock();
        return l.acceptLocked();
    }

    fn acceptLocked(l: Listener) root.AcceptError!Stream {
        const s = l.stack;
        _ = s.listenerOf(l.id) orelse return error.Closed;
        const li: u8 = @intCast(l.id & 0xffff);
        var best: ?usize = null;
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used or !sl.queued or sl.listener != li) continue;
            if (best == null or sl.accept_seq < s.slots[best.?].accept_seq) best = i;
        }
        const i = best orelse return error.WouldBlock;
        const sl = &s.slots[i];
        sl.queued = false;
        sl.listener = null;
        sl.handle_open = true;
        return .{ .stack = s, .id = handleId(i, sl.gen) };
    }

    pub fn acceptWait(l: Listener, timeout_ns: ?u64) root.AcceptError!Stream {
        const s = l.stack;
        const deadline = timeoutFrom(s.io, timeout_ns);
        s.lock();
        defer s.unlock();
        while (true) {
            return l.acceptLocked() catch |e| switch (e) {
                error.WouldBlock => {
                    const ls = s.listenerOf(l.id) orelse return error.Closed;
                    try s.waitOn(&ls.cond, deadline);
                    continue;
                },
                else => return e,
            };
        }
    }

    pub fn close(l: Listener) void {
        const s = l.stack;
        s.lock();
        defer s.unlock();
        const ls = s.listenerOf(l.id) orelse return;
        const li: u8 = @intCast(l.id & 0xffff);
        ls.open = false;
        ls.gen +%= 1;
        ls.cond.broadcast(s.io);
        for (s.slots, 0..) |*sl, i| {
            if (!sl.used or sl.listener != li) continue;
            const c = &sl.conn;
            s.sendRst(c.local, c.remote, .{ .seq = c.snd_max, .ack = c.rcv_nxt });
            c.fail(error.ConnectionReset);
            sl.queued = false;
            sl.listener = null;
            s.maybeRelease(i);
        }
        s.kickThread();
    }
};

pub const Stream = struct {
    stack: *Stack,
    id: u32,

    fn connError(c: *const tcp.Conn) ?root.ReadError {
        const e = c.err orelse return null;
        return switch (e) {
            error.ConnectionRefused => error.ConnectionRefused,
            error.ConnectionReset => error.ConnectionReset,
            error.ConnectionTimedOut => error.ConnectionTimedOut,
        };
    }

    fn readLocked(st: Stream, buf: []u8) root.ReadError!usize {
        const s = st.stack;
        const sl = s.slotOf(st.id) orelse return error.Closed;
        const c = &sl.conn;
        if (c.rcv.len > 0 and buf.len > 0) {
            const e = s.env(s.clock.now());
            const n = c.hostRead(&e, buf);
            if (c.ack_now) s.kickThread();
            return n;
        }
        if (connError(c)) |e| return e;
        if (c.eof or c.state == .closed or buf.len == 0) return 0;
        return error.WouldBlock;
    }

    pub fn read(st: Stream, buf: []u8) root.ReadError!usize {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        return st.readLocked(buf);
    }

    pub fn readWait(st: Stream, buf: []u8, timeout_ns: ?u64) root.ReadError!usize {
        const s = st.stack;
        const deadline = timeoutFrom(s.io, timeout_ns);
        s.lock();
        defer s.unlock();
        while (true) {
            return st.readLocked(buf) catch |e| switch (e) {
                error.WouldBlock => {
                    const sl = s.slotOf(st.id) orelse return error.Closed;
                    try s.waitOn(&sl.cond, deadline);
                    continue;
                },
                else => return e,
            };
        }
    }

    fn writeLocked(st: Stream, data: []const u8) root.WriteError!usize {
        const s = st.stack;
        const sl = s.slotOf(st.id) orelse return error.Closed;
        const c = &sl.conn;
        if (connError(c)) |e| return switch (e) {
            error.ConnectionRefused => error.ConnectionRefused,
            error.ConnectionReset => error.ConnectionReset,
            error.ConnectionTimedOut => error.ConnectionTimedOut,
            else => error.Closed,
        };
        switch (c.state) {
            .syn_sent, .established, .close_wait => {},
            else => return error.BrokenPipe,
        }
        if (c.fin_queued) return error.BrokenPipe;
        if (data.len == 0) return 0;
        const n = c.hostWrite(&s.options.limits, data);
        if (n == 0) return error.WouldBlock;
        s.kickThread();
        return n;
    }

    pub fn write(st: Stream, data: []const u8) root.WriteError!usize {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        return st.writeLocked(data);
    }

    pub fn writeAll(st: Stream, data: []const u8, timeout_ns: ?u64) root.WriteError!void {
        const s = st.stack;
        const deadline = timeoutFrom(s.io, timeout_ns);
        s.lock();
        defer s.unlock();
        var rest = data;
        while (rest.len > 0) {
            const n = st.writeLocked(rest) catch |e| switch (e) {
                error.WouldBlock => {
                    const sl = s.slotOf(st.id) orelse return error.Closed;
                    try s.waitOn(&sl.cond, deadline);
                    continue;
                },
                else => return e,
            };
            rest = rest[n..];
        }
    }

    pub fn waitConnected(st: Stream, timeout_ns: ?u64) root.ConnectError!void {
        const s = st.stack;
        const deadline = timeoutFrom(s.io, timeout_ns);
        s.lock();
        defer s.unlock();
        while (true) {
            const sl = s.slotOf(st.id) orelse return error.Closed;
            const c = &sl.conn;
            if (c.err) |e| return e;
            switch (c.state) {
                .syn_sent, .syn_received => try s.waitOn(&sl.cond, deadline),
                .closed => return error.Closed,
                else => return,
            }
        }
    }

    pub fn shutdown(st: Stream) void {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return;
        if (sl.conn.hostShutdown()) s.kickThread();
        s.notifySlot(sl);
    }

    pub fn close(st: Stream) void {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return;
        const i: usize = st.id & 0xffff;
        const c = &sl.conn;
        if (c.rcv.len > 0) {
            // Unread data: reset (RFC 1122 4.2.2.13), the peer must not
            // believe it was all consumed.
            s.resetLocked(sl);
        } else if (!c.fin_queued) {
            _ = c.hostShutdown();
        }
        sl.handle_open = false;
        sl.gen +%= 1;
        s.notifySlot(sl);
        s.orphanTimers(sl);
        s.maybeRelease(i);
        s.kickThread();
    }

    pub fn abort(st: Stream) void {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return;
        const i: usize = st.id & 0xffff;
        s.resetLocked(sl);
        sl.handle_open = false;
        sl.gen +%= 1;
        s.notifySlot(sl);
        s.maybeRelease(i);
        s.kickThread();
    }

    pub fn setPriority(st: Stream, priority: root.Priority) void {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return;
        sl.conn.priority = priority;
        s.notifySlot(sl);
        s.kickThread();
    }

    /// Writes accept bytes only while fewer than `n` are unsent (like
    /// TCP_NOTSENT_LOWAT), so a large message waits in the application
    /// and what it sends next (a keystroke's echo) is never queued behind
    /// more than about `n` bytes. Null: the priority's default (bulk:
    /// Limits.bulk_unsent_lowat; interactive: none, only the send buffer).
    pub fn setUnsentLowat(st: Stream, n: ?u32) void {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return;
        sl.conn.unsent_lowat = n;
        s.notifySlot(sl);
        s.kickThread();
    }

    pub fn status(st: Stream) root.Status {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return .{ .state = .closed, .readable = true, .writable = true, .read_available = 0, .write_available = 0 };
        const c = &sl.conn;
        return .{
            .state = c.state,
            .readable = c.readable(),
            .writable = c.writable(&s.options.limits),
            .read_available = c.rcv.len,
            .write_available = c.writeRoom(&s.options.limits),
        };
    }

    /// A snapshot of the connection's TCP state (tests and diagnostics).
    pub fn debugConn(st: Stream) ?tcp.Conn {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return null;
        return sl.conn;
    }

    pub fn local(st: Stream) Endpoint {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return .{ .addr = s.options.address, .port = 0 };
        return sl.conn.local;
    }

    pub fn remote(st: Stream) Endpoint {
        const s = st.stack;
        s.lock();
        defer s.unlock();
        const sl = s.slotOf(st.id) orelse return .{ .addr = s.options.address, .port = 0 };
        return sl.conn.remote;
    }

    pub fn reader(st: Stream, buffer: []u8, timeout_ns: ?u64) Reader {
        return .{
            .interface = .{ .vtable = &.{ .stream = Reader.streamImpl }, .buffer = buffer, .seek = 0, .end = 0 },
            .stream = st,
            .timeout_ns = timeout_ns,
        };
    }

    pub fn writer(st: Stream, buffer: []u8, timeout_ns: ?u64) Writer {
        return .{
            .interface = .{ .vtable = &.{ .drain = Writer.drain }, .buffer = buffer },
            .stream = st,
            .timeout_ns = timeout_ns,
        };
    }

    pub const Reader = struct {
        interface: std.Io.Reader,
        stream: Stream,
        timeout_ns: ?u64,
        err: ?root.ReadError = null,

        fn streamImpl(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            const n = r.stream.readWait(dest, r.timeout_ns) catch |e| {
                r.err = e;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            io_w.advance(n);
            return n;
        }
    };

    pub const Writer = struct {
        interface: std.Io.Writer,
        stream: Stream,
        timeout_ns: ?u64,
        err: ?root.WriteError = null,

        fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            const buffered = io_w.buffered();
            w.put(buffered) catch return error.WriteFailed;
            var n: usize = buffered.len;
            for (data[0 .. data.len - 1]) |d| {
                w.put(d) catch return error.WriteFailed;
                n += d.len;
            }
            const last = data[data.len - 1];
            for (0..splat) |_| {
                w.put(last) catch return error.WriteFailed;
                n += last.len;
            }
            return io_w.consume(n);
        }

        fn put(w: *Writer, bytes: []const u8) root.WriteError!void {
            w.stream.writeAll(bytes, w.timeout_ns) catch |e| {
                w.err = e;
                return e;
            };
        }
    };
};

pub const Node = struct {
    stack: *Stack,
    device: *dev.Device,
    gpa: std.mem.Allocator,
    device_thread: ?std.Thread = null,

    pub const StartError = root.CreateError || root.StartError || dev.Device.InitError || error{ThreadSpawnFailed};

    pub fn start(gpa: std.mem.Allocator, clock: *root.Clock, device_options: dev.device.Options, stack_options: Options) StartError!*Node {
        const n = try gpa.create(Node);
        errdefer gpa.destroy(n);
        const stack = try Stack.create(gpa, clock, stack_options);
        errdefer stack.destroy();
        const device = try dev.Device.create(gpa, clock, stack.tun(), device_options);
        errdefer device.destroy();
        n.* = .{ .stack = stack, .device = device, .gpa = gpa };
        try stack.start();
        n.device_thread = std.Thread.spawn(.{}, runDevice, .{device}) catch return error.ThreadSpawnFailed;
        return n;
    }

    fn runDevice(d: *dev.Device) void {
        d.run() catch |err| std.log.scoped(.netstack).err("device loop ended: {s}", .{@errorName(err)});
    }

    /// Resets all connections, stops the device thread, then the stack
    /// thread, and destroys both (device keys and stack buffers wiped).
    /// Join host threads that use streams before calling this.
    pub fn destroy(n: *Node) void {
        n.stack.abortAll();
        if (n.device_thread) |t| {
            n.device.stop();
            t.join();
        }
        n.stack.stop();
        n.device.destroy();
        n.stack.destroy();
        n.gpa.destroy(n);
    }
};
