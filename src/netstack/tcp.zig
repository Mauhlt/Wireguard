//! Per-connection TCP (RFC 9293): the state machine, sequence / window
//! bookkeeping, RTO (RFC 6298, Karn), NewReno (RFC 5681 / 6582), zero
//! window probing, delayed ACK, keepalive, TIME-WAIT. Pure: no locking,
//! no I/O, no clock reads (the caller passes `Env.now`). The stack owns
//! the table, the locking and the packets; this file decides what a
//! connection does with a segment, which segment it sends next, and when
//! its timers are due.
const std = @import("std");
const root = @import("root.zig");
const wire = @import("wire.zig");

const Endpoint = root.Endpoint;
const State = root.State;
const ms = std.time.ns_per_ms;
const sec = std.time.ns_per_s;

// ---- constants (one definition each) -------------------------------------

/// RFC 6298 2.1.
pub const initial_rto_ns: i64 = 1 * sec;
/// RFC 6298 says 1 s; like Linux we use 200 ms (one-hop tunnel, and a
/// 1 s floor makes every loss stall the stream for a second).
pub const min_rto_ns: i64 = 200 * ms;
pub const max_rto_ns: i64 = 60 * sec;
/// Clock granularity G in RFC 6298 (our clock is ns; 1 ms is generous).
const rto_granularity_ns: i64 = 1 * ms;
pub const delayed_ack_ns: i64 = 40 * ms;
/// SYN-ACK retransmissions before a half-open connection is dropped.
pub const max_synack_retries = 3;
pub const keepalive_interval_ns: i64 = 10 * sec;
pub const keepalive_probes = 6;
/// RFC 9293 3.7.1 default when the peer sends no MSS option.
pub const default_peer_mss: u16 = 536;
/// Smallest MSS we accept from a peer (RFC 9293 3.7.1: IPv4 minimum 536,
/// but some stacks go lower; below 64 the header overhead is absurd).
const min_peer_mss: u16 = 64;
/// RFC 6928 initial window.
pub const initial_cwnd_segments = 10;
/// Storage bound for out-of-order ranges (Limits.max_ooo_segments <= this).
pub const max_ooo_ranges = 64;
/// Duplicate ACKs owed at most (one per out-of-order segment): enough for
/// the sender's fast retransmit (3) and some NewReno window inflation.
const max_dup_acks_owed = 8;

pub const ConnError = error{ ConnectionRefused, ConnectionReset, ConnectionTimedOut };

// ---- sequence arithmetic (32-bit wrap) -----------------------------------

pub fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}
pub fn seqLe(a: u32, b: u32) bool {
    return !seqLt(b, a);
}

/// usize -> u32, saturating (lengths here are bounded by buffers anyway).
pub fn len32(n: usize) u32 {
    return std.math.cast(u32, n) orelse std.math.maxInt(u32);
}

/// ns (u64 from Limits) -> i64 deadline offset, saturating.
pub fn nsI64(n: u64) i64 {
    return std.math.cast(i64, n) orelse std.math.maxInt(i64);
}

// ---- byte ring --------------------------------------------------------------

/// Fixed-capacity byte ring. Logical offset 0 is the oldest byte.
pub const ByteRing = struct {
    buf: []u8 = &.{},
    head: usize = 0,
    len: usize = 0,

    pub fn cap(r: *const ByteRing) usize {
        return r.buf.len;
    }
    pub fn free(r: *const ByteRing) usize {
        return r.buf.len - r.len;
    }

    /// Copies `data` to logical offset `off` (may lie beyond `len`: the
    /// out-of-order area). Caller guarantees off + data.len <= cap.
    pub fn writeAt(r: *ByteRing, off: usize, data: []const u8) void {
        if (data.len == 0) return;
        std.debug.assert(off + data.len <= r.buf.len);
        const start = (r.head + off) % r.buf.len;
        const first = @min(data.len, r.buf.len - start);
        @memcpy(r.buf[start..][0..first], data[0..first]);
        @memcpy(r.buf[0 .. data.len - first], data[first..]);
    }

    pub fn append(r: *ByteRing, data: []const u8) usize {
        const n = @min(data.len, r.free());
        r.writeAt(r.len, data[0..n]);
        r.len += n;
        return n;
    }

    /// Copies out bytes [off, off + out.len) (caller: off + out.len <= cap).
    pub fn readAt(r: *const ByteRing, off: usize, out: []u8) void {
        if (out.len == 0) return;
        const start = (r.head + off) % r.buf.len;
        const first = @min(out.len, r.buf.len - start);
        @memcpy(out[0..first], r.buf[start..][0..first]);
        @memcpy(out[first..], r.buf[0 .. out.len - first]);
    }

    pub fn consume(r: *ByteRing, n: usize) void {
        std.debug.assert(n <= r.len);
        if (r.buf.len == 0) return;
        r.head = (r.head + n) % r.buf.len;
        r.len -= n;
    }
};

// ---- environment passed in by the stack ----------------------------------

pub const Env = struct {
    now: i64,
    gpa: std.mem.Allocator,
    limits: *const root.Limits,
    /// Our MSS (from the MTU).
    mss: u16,
    keepalive_idle_ns: ?u64,
    stats: *root.Stats,
};

/// What the stack must do after `input` / `onTimers`.
pub const Outcome = struct {
    /// Connection-less RST reply (no connection state involved).
    rst: ?Rst = null,
    /// A passive connection just became ESTABLISHED: queue it for accept.
    established: bool = false,
    /// Host-visible change: wake waiters / the ready handle.
    notify: bool = false,
    /// The connection may have something to send now.
    output: bool = false,
};

pub const Rst = struct { seq: u32, ack: ?u32 };

/// What `output` may emit (the stack's two-class scheduler).
pub const OutputClass = enum {
    /// Anything: SYN, data, retransmissions, FIN, ACKs, probes.
    any,
    /// Only segments without new data: SYN / SYN-ACK, pure ACKs and
    /// window updates, probes, a bare FIN. Never queued behind bulk data.
    control,
};

const Range = struct { start: u32, end: u32 };

pub const Conn = struct {
    state: State = .closed,
    local: Endpoint,
    remote: Endpoint,
    priority: root.Priority = .interactive,

    /// One allocation: send buffer ++ receive buffer (empty until needed).
    mem: []u8 = &.{},
    snd: ByteRing = .{},
    rcv: ByteRing = .{},

    // send sequence space
    iss: u32 = 0,
    snd_una: u32 = 0,
    snd_nxt: u32 = 0,
    /// Highest sequence number sent + 1 (snd_nxt drops back on RTO).
    snd_max: u32 = 0,
    /// Sequence number of snd byte 0.
    snd_base: u32 = 0,
    snd_wnd: u32 = 0,
    snd_wl1: u32 = 0,
    snd_wl2: u32 = 0,
    /// Peer's window shift (applied to windows it sends) / ours.
    snd_shift: u4 = 0,
    rcv_shift: u4 = 0,
    /// Effective send MSS.
    mss: u16 = default_peer_mss,
    fin_queued: bool = false,

    // receive sequence space
    irs: u32 = 0,
    rcv_nxt: u32 = 0,
    /// Right edge of the window last advertised.
    rcv_adv: u32 = 0,
    ooo: [max_ooo_ranges]Range = undefined,
    ooo_len: u8 = 0,
    /// Peer's FIN, seen at this sequence number but not yet in order.
    fin_seq: ?u32 = null,
    /// The peer's FIN was consumed: reads end once rcv is drained.
    eof: bool = false,

    // what to send
    send_syn: bool = false,
    ack_now: bool = false,
    /// Separate duplicate ACKs to send (RFC 5681 4.2: one per out-of-order
    /// segment, at once). A flag would merge a burst of them into one and
    /// the sender would never see three.
    dup_acks_owed: u8 = 0,
    unacked_segs: u8 = 0,
    probe_now: bool = false,
    retransmit_one: bool = false,

    // timers (device clock ns; null = off)
    rto_at: ?i64 = null,
    delack_at: ?i64 = null,
    persist_at: ?i64 = null,
    keepalive_at: ?i64 = null,
    timewait_at: ?i64 = null,

    // RTT (RFC 6298)
    srtt: i64 = 0,
    rttvar: i64 = 0,
    rto: i64 = initial_rto_ns,
    backoff: u8 = 0,
    rtt_seq: ?u32 = null,
    rtt_start: i64 = 0,
    /// When the oldest unanswered retransmission started (user timeout).
    stalled_since: ?i64 = null,
    persist_backoff: u8 = 0,

    // congestion control
    cwnd: u32 = 0,
    ssthresh: u32 = std.math.maxInt(u32),
    dupacks: u32 = 0,
    recover: u32 = 0,
    in_recovery: bool = false,

    keepalive_sent: u8 = 0,
    err: ?ConnError = null,

    // ---- setup -----------------------------------------------------------

    fn ourShift(limits: *const root.Limits) u4 {
        var sh: u4 = 0;
        while (sh < wire.max_window_scale and (limits.recv_buffer >> sh) > 0xffff) sh += 1;
        return sh;
    }

    pub fn allocBuffers(c: *Conn, env: *const Env) error{OutOfMemory}!void {
        if (c.mem.len != 0) return;
        const sb = env.limits.send_buffer;
        const rb = env.limits.recv_buffer;
        c.mem = try env.gpa.alloc(u8, @as(usize, sb) + rb);
        c.snd = .{ .buf = c.mem[0..sb] };
        c.rcv = .{ .buf = c.mem[sb..] };
    }

    pub fn freeBuffers(c: *Conn, gpa: std.mem.Allocator) void {
        if (c.mem.len == 0) return;
        std.crypto.secureZero(u8, c.mem);
        gpa.free(c.mem);
        c.mem = &.{};
        c.snd = .{};
        c.rcv = .{};
    }

    /// Active open: buffers allocated, SYN queued.
    pub fn connect(c: *Conn, env: *const Env, iss: u32) error{OutOfMemory}!void {
        try c.allocBuffers(env);
        c.iss = iss;
        c.snd_una = iss;
        c.snd_nxt = iss;
        c.snd_max = iss;
        c.snd_base = iss +% 1;
        c.recover = iss;
        c.rcv_shift = ourShift(env.limits);
        c.state = .syn_sent;
        c.send_syn = true;
        c.cwnd = initial_cwnd_segments * @as(u32, env.mss);
        c.armKeepalive(env);
    }

    /// Passive open from a valid SYN (no buffers yet: SYN-flood bound).
    pub fn acceptSyn(c: *Conn, env: *const Env, syn: wire.Tcp, iss: u32) void {
        c.iss = iss;
        c.snd_una = iss;
        c.snd_nxt = iss;
        c.snd_max = iss;
        c.snd_base = iss +% 1;
        c.recover = iss;
        c.irs = syn.seq;
        c.rcv_nxt = syn.seq +% 1;
        c.state = .syn_received;
        c.applySynOptions(env, syn);
        c.snd_wnd = syn.window; // never scaled in a SYN
        c.snd_wl1 = syn.seq;
        c.send_syn = true;
        c.cwnd = initial_cwnd_segments * @as(u32, c.mss);
    }

    fn applySynOptions(c: *Conn, env: *const Env, syn: wire.Tcp) void {
        const peer_mss = syn.options.mss orelse default_peer_mss;
        c.mss = @max(@min(peer_mss, env.mss), min_peer_mss);
        if (syn.options.window_scale) |sh| {
            c.snd_shift = @intCast(@min(sh, wire.max_window_scale));
            if (c.state == .syn_received) c.rcv_shift = ourShift(env.limits);
        } else {
            // RFC 7323 1.3: both sides must offer it, or neither scales.
            c.snd_shift = 0;
            c.rcv_shift = 0;
        }
    }

    fn armKeepalive(c: *Conn, env: *const Env) void {
        if (env.keepalive_idle_ns) |idle| c.keepalive_at = env.now +| nsI64(idle);
    }

    // ---- derived values ------------------------------------------------------

    fn finSeq(c: *const Conn) u32 {
        return c.snd_base +% len32(c.snd.len);
    }
    fn finAcked(c: *const Conn) bool {
        return c.fin_queued and seqLt(c.finSeq(), c.snd_una);
    }
    fn flight(c: *const Conn) u32 {
        return c.snd_nxt -% c.snd_una;
    }
    /// Bytes in the send buffer not yet sent (at snd_nxt or later).
    pub fn unsent(c: *const Conn) usize {
        const off = c.snd_nxt -% c.snd_base;
        if (!seqLe(c.snd_base, c.snd_nxt) or off > c.snd.len) return 0;
        return c.snd.len - off;
    }
    /// Receive space: what the window may cover from rcv_nxt.
    fn rcvSpace(c: *const Conn, env: *const Env) u32 {
        if (c.rcv.cap() == 0) return env.limits.recv_buffer;
        return len32(c.rcv.free());
    }
    fn synchronized(c: *const Conn) bool {
        return switch (c.state) {
            .established, .fin_wait_1, .fin_wait_2, .close_wait, .closing, .last_ack, .time_wait => true,
            else => false,
        };
    }
    fn canReceiveData(c: *const Conn) bool {
        return c.state == .established or c.state == .fin_wait_1 or c.state == .fin_wait_2;
    }
    fn canSendData(c: *const Conn) bool {
        return switch (c.state) {
            .established, .close_wait, .fin_wait_1, .closing, .last_ack => true,
            else => false,
        };
    }

    pub fn readable(c: *const Conn) bool {
        return c.rcv.len > 0 or c.eof or c.err != null or c.state == .closed;
    }

    /// Bytes `hostWrite` would accept now. Bulk streams stop at
    /// Limits.bulk_unsent_lowat unsent bytes (TCP_NOTSENT_LOWAT): the
    /// backlog stays in the application, not in front of other traffic.
    pub fn writeRoom(c: *const Conn, limits: *const root.Limits) usize {
        if (c.fin_queued) return 0;
        switch (c.state) {
            .syn_sent, .established, .close_wait => {},
            else => return 0,
        }
        var room = c.snd.free();
        if (c.priority == .bulk) room = @min(room, limits.bulk_unsent_lowat -| c.unsent());
        return room;
    }

    pub fn writable(c: *const Conn, limits: *const root.Limits) bool {
        return c.err != null or c.fin_queued or c.state == .closed or c.writeRoom(limits) > 0;
    }

    // ---- host operations (stack holds the lock) -----------------------------

    /// Host read: copies in-order bytes out. Returns bytes copied; sets
    /// ack_now when a window update is due.
    pub fn hostRead(c: *Conn, env: *const Env, out: []u8) usize {
        const n = @min(out.len, c.rcv.len);
        c.rcv.readAt(0, out[0..n]);
        c.rcv.consume(n);
        // Window update when the right edge moved by >= min(half the
        // buffer, 2 MSS) (RFC 9293 3.8.6.2.2, receiver SWS avoidance).
        if (n > 0 and c.synchronized()) {
            const edge = c.rcv_nxt +% len32(c.rcv.free());
            const threshold = @min(len32(c.rcv.cap()) / 2, 2 * @as(u32, env.mss));
            if (seqLe(c.rcv_adv, edge) and edge -% c.rcv_adv >= threshold) c.ack_now = true;
        }
        return n;
    }

    pub fn hostWrite(c: *Conn, limits: *const root.Limits, data: []const u8) usize {
        const room = c.writeRoom(limits);
        return c.snd.append(data[0..@min(data.len, room)]);
    }

    /// FIN after the buffered data. Returns true if a FIN was queued.
    pub fn hostShutdown(c: *Conn) bool {
        if (c.fin_queued) return false;
        switch (c.state) {
            .established, .syn_received => c.state = .fin_wait_1,
            .close_wait => c.state = .last_ack,
            .syn_sent => {
                c.state = .closed;
                c.clearTimers();
                return false;
            },
            else => return false,
        }
        c.fin_queued = true;
        return true;
    }

    // ---- input ---------------------------------------------------------------

    /// Processes one segment addressed to this connection.
    pub fn input(c: *Conn, env: *const Env, seg_in: wire.Tcp) Outcome {
        var out: Outcome = .{};
        var seg = seg_in;
        if (c.state == .closed) return out;
        c.keepalive_sent = 0;
        if (c.keepalive_at != null) c.armKeepalive(env);

        if (c.state == .syn_sent) return c.inputSynSent(env, seg);

        // 1. Sequence acceptability (RFC 9293 3.10.7.4).
        const wnd = c.rcvSpace(env);
        const seg_len = seg.segLen();
        const ok = if (seg_len == 0)
            (if (wnd == 0) seg.seq == c.rcv_nxt else inWindow(seg.seq, c.rcv_nxt, wnd))
        else if (wnd == 0)
            false
        else
            inWindow(seg.seq, c.rcv_nxt, wnd) or inWindow(seg.seq +% seg_len -% 1, c.rcv_nxt, wnd);
        if (!ok) {
            // A zero-window probe or a duplicate: answer with an ACK.
            if (!seg.flags.rst) {
                c.ack_now = true;
                out.output = true;
            }
            return out;
        }

        // 2. RST (RFC 5961 3.2: exact match resets, in-window -> challenge ACK).
        if (seg.flags.rst) {
            if (seg.seq != c.rcv_nxt) {
                c.ack_now = true;
                out.output = true;
                return out;
            }
            switch (c.state) {
                // Back to LISTEN (RFC 9293): the stack frees it.
                .syn_received => {
                    c.state = .closed;
                    c.clearTimers();
                },
                .time_wait, .closing, .last_ack => {
                    c.state = .closed;
                    c.clearTimers();
                },
                else => c.fail(error.ConnectionReset),
            }
            out.notify = true;
            return out;
        }

        // 3. SYN in a synchronized state: challenge ACK (RFC 5961 4).
        if (seg.flags.syn) {
            if (c.state == .syn_received and seg.seq == c.irs) {
                c.send_syn = true; // retransmitted SYN: resend the SYN-ACK
            } else {
                c.ack_now = true;
            }
            out.output = true;
            return out;
        }

        // Trim to the window.
        if (seqLt(seg.seq, c.rcv_nxt)) {
            const d = c.rcv_nxt -% seg.seq;
            if (d >= seg.payload.len) {
                if (seg.flags.fin and d > seg.payload.len) seg.flags.fin = false;
                seg.payload = seg.payload[seg.payload.len..];
            } else {
                seg.payload = seg.payload[d..];
            }
            seg.seq = c.rcv_nxt;
        }
        const room = wnd -| (seg.seq -% c.rcv_nxt);
        if (seg.payload.len > room) {
            seg.payload = seg.payload[0..room];
            seg.flags.fin = false;
        }

        // 4. ACK.
        if (!seg.flags.ack) return out;
        if (c.state == .syn_received) {
            if (!(seqLt(c.snd_una, seg.ack) and seqLe(seg.ack, c.snd_max))) {
                out.rst = .{ .seq = seg.ack, .ack = null };
                return out;
            }
            c.allocBuffers(env) catch {
                out.rst = .{ .seq = seg.ack, .ack = null };
                c.state = .closed;
                c.clearTimers();
                return out;
            };
            c.state = .established;
            c.send_syn = false;
            c.snd_una = seg.ack;
            if (seqLt(c.snd_nxt, c.snd_una)) c.snd_nxt = c.snd_una;
            c.snd_wnd = @as(u32, seg.window) << c.snd_shift;
            c.snd_wl1 = seg.seq;
            c.snd_wl2 = seg.ack;
            c.rto_at = null;
            c.backoff = 0;
            c.stalled_since = null;
            if (c.rtt_seq) |rs| if (seqLe(rs, seg.ack)) c.sampleRtt(env.now);
            c.armKeepalive(env);
            out.established = true;
            out.notify = true;
        } else {
            if (seqLt(c.snd_max, seg.ack)) {
                c.ack_now = true; // acks something never sent
                out.output = true;
                return out;
            }
            if (c.processAck(env, seg)) {
                out.notify = true;
                out.output = true;
            }
        }

        // Our FIN acknowledged.
        if (c.finAcked()) switch (c.state) {
            .fin_wait_1 => c.state = .fin_wait_2,
            .closing => c.enterTimeWait(env),
            .last_ack => {
                c.state = .closed;
                c.clearTimers();
                out.notify = true;
                return out;
            },
            else => {},
        };
        if (c.state == .time_wait) {
            if (seg.flags.fin) {
                // A retransmitted FIN: ACK it again and restart 2MSL.
                c.ack_now = true;
                out.output = true;
                c.enterTimeWait(env);
            }
            return out;
        }

        // 5. Data.
        if (seg.payload.len > 0) {
            if (c.canReceiveData()) {
                c.receiveData(env, seg.seq, seg.payload);
                out.notify = true;
            } else {
                c.ack_now = true;
            }
            out.output = true;
        }

        // 6. FIN (possibly out of order: remembered until the gap fills).
        if (seg.flags.fin and c.canReceiveData() and c.fin_seq == null) {
            c.fin_seq = seg.seq +% len32(seg.payload.len);
            c.ack_now = true;
            out.output = true;
        }
        if (c.consumeFin(env)) {
            out.notify = true;
            out.output = true;
        }
        return out;
    }

    fn consumeFin(c: *Conn, env: *const Env) bool {
        const fs = c.fin_seq orelse return false;
        if (fs != c.rcv_nxt or c.eof) return false;
        c.rcv_nxt +%= 1;
        c.eof = true;
        c.ack_now = true;
        switch (c.state) {
            .established => c.state = .close_wait,
            .fin_wait_1 => if (c.finAcked()) c.enterTimeWait(env) else {
                c.state = .closing;
            },
            .fin_wait_2 => c.enterTimeWait(env),
            else => {},
        }
        return true;
    }

    fn inWindow(seq: u32, start: u32, wnd: u32) bool {
        return seqLe(start, seq) and seqLt(seq, start +% wnd);
    }

    fn inputSynSent(c: *Conn, env: *const Env, seg: wire.Tcp) Outcome {
        var out: Outcome = .{};
        if (seg.flags.ack and (seqLe(seg.ack, c.iss) or seqLt(c.snd_max, seg.ack))) {
            if (!seg.flags.rst) out.rst = .{ .seq = seg.ack, .ack = null };
            return out;
        }
        if (seg.flags.rst) {
            if (seg.flags.ack) {
                c.fail(error.ConnectionRefused);
                out.notify = true;
            }
            return out;
        }
        if (!seg.flags.syn) return out;
        c.irs = seg.seq;
        c.rcv_nxt = seg.seq +% 1;
        c.applySynOptions(env, seg);
        c.cwnd = initial_cwnd_segments * @as(u32, c.mss);
        c.snd_wnd = seg.window;
        c.snd_wl1 = seg.seq;
        c.snd_wl2 = seg.ack;
        c.ack_now = true;
        out.output = true;
        if (seg.flags.ack) {
            c.snd_una = seg.ack;
            if (seqLt(c.snd_nxt, c.snd_una)) c.snd_nxt = c.snd_una;
            if (c.rtt_seq) |rs| if (seqLe(rs, seg.ack)) c.sampleRtt(env.now);
            c.rto_at = null;
            c.backoff = 0;
            c.stalled_since = null;
            c.send_syn = false;
            c.state = .established;
            out.notify = true;
            // Data on a SYN-ACK is unusual; take what fits.
            if (seg.payload.len > 0) c.receiveData(env, c.rcv_nxt, seg.payload[0..@min(seg.payload.len, c.rcv.free())]);
        } else {
            // Simultaneous open (RFC 9293 3.5).
            c.state = .syn_received;
            c.send_syn = true;
        }
        return out;
    }

    /// Returns true when new data was acknowledged or the window opened.
    fn processAck(c: *Conn, env: *const Env, seg: wire.Tcp) bool {
        const ack = seg.ack;
        const old_wnd = c.snd_wnd;
        // Window update (RFC 9293 3.10.7.4).
        if (seqLt(c.snd_wl1, seg.seq) or (c.snd_wl1 == seg.seq and seqLe(c.snd_wl2, ack))) {
            c.snd_wnd = @as(u32, seg.window) << c.snd_shift;
            c.snd_wl1 = seg.seq;
            c.snd_wl2 = ack;
            if (c.snd_wnd > 0) {
                c.persist_at = null;
                c.persist_backoff = 0;
            }
        }
        if (seqLe(ack, c.snd_una)) {
            // Duplicate ACK (RFC 5681 2): no data, no window change,
            // data outstanding, ack == snd_una.
            if (ack == c.snd_una and seg.payload.len == 0 and !seg.flags.fin and
                c.snd_wnd == old_wnd and c.snd_max != c.snd_una)
            {
                c.dupacks += 1;
                if (c.dupacks == c.dupThreshold() and !c.in_recovery) {
                    // RFC 6582 3.2 step 2: only if this is not a loss we
                    // already recovered from (ack - 1 > recover).
                    if (seqLt(c.recover, ack -% 1) or c.recover == c.iss) {
                        const fl = c.snd_max -% c.snd_una;
                        c.ssthresh = @max(fl / 2, 2 * @as(u32, c.mss));
                        c.recover = c.snd_max;
                        c.cwnd = c.ssthresh + 3 * @as(u32, c.mss);
                        c.in_recovery = true;
                        c.retransmit_one = true;
                        c.rtt_seq = null; // Karn
                        env.stats.fast_retransmits += 1;
                    }
                } else if (c.in_recovery) {
                    c.cwnd +|= c.mss; // inflate
                }
            }
            return c.snd_wnd > old_wnd;
        }

        // New data acknowledged.
        const acked = ack -% c.snd_una;
        if (seqLt(c.snd_base, ack)) {
            const n = @min(ack -% c.snd_base, len32(c.snd.len));
            c.snd.consume(n);
            c.snd_base +%= n;
        }
        c.snd_una = ack;
        if (seqLt(c.snd_nxt, ack)) c.snd_nxt = ack;
        if (c.rtt_seq) |rs| if (seqLe(rs, ack)) c.sampleRtt(env.now);
        c.backoff = 0;
        c.stalled_since = null;

        if (c.in_recovery) {
            if (seqLe(c.recover, ack)) {
                // Full ACK: leave recovery (RFC 6582 3.2 step 3).
                c.cwnd = @min(c.ssthresh, (c.snd_max -% c.snd_una) + c.mss);
                c.in_recovery = false;
                c.dupacks = 0;
            } else {
                // Partial ACK: retransmit the next hole, deflate.
                c.retransmit_one = true;
                c.cwnd = (c.cwnd -| acked) +| c.mss;
            }
        } else {
            c.dupacks = 0;
            if (c.cwnd < c.ssthresh) {
                c.cwnd +|= @min(acked, c.mss); // slow start
            } else {
                c.cwnd +|= @max(1, (@as(u32, c.mss) * c.mss) / @max(c.cwnd, 1)); // congestion avoidance
            }
        }
        // No point growing past what the buffer can ever have in flight.
        const cwnd_cap = len32(c.snd.cap()) +| 2 * @as(u32, c.mss);
        if (c.cwnd > cwnd_cap) c.cwnd = cwnd_cap;

        c.rto_at = if (c.snd_una == c.snd_max) null else env.now + c.rto;
        return true;
    }

    /// Duplicate ACKs that trigger fast retransmit: 3, or fewer when fewer
    /// than 4 segments are outstanding and there is no new data to send
    /// (Early Retransmit, RFC 5827): with so little in flight a single
    /// loss could never produce 3 and would wait for the RTO.
    fn dupThreshold(c: *const Conn) u32 {
        const outstanding = (c.snd_max -% c.snd_una + c.mss - 1) / c.mss;
        if (c.unsent() == 0 and outstanding < 4) return @max(outstanding -| 1, 1);
        return 3;
    }

    fn sampleRtt(c: *Conn, now: i64) void {
        const r = @max(now - c.rtt_start, 0);
        if (c.srtt == 0) {
            c.srtt = @max(r, 1);
            c.rttvar = @divTrunc(r, 2);
        } else {
            const diff: i64 = if (c.srtt > r) c.srtt - r else r - c.srtt;
            c.rttvar = @divTrunc(3 * c.rttvar + diff, 4);
            c.srtt = @max(@divTrunc(7 * c.srtt + r, 8), 1);
        }
        c.rto = std.math.clamp(c.srtt + @max(rto_granularity_ns, 4 * c.rttvar), min_rto_ns, max_rto_ns);
        c.rtt_seq = null;
    }

    fn receiveData(c: *Conn, env: *const Env, seq: u32, data: []const u8) void {
        const off = seq -% c.rcv_nxt;
        if (off == 0) {
            c.rcv.writeAt(c.rcv.len, data);
            c.rcv.len += data.len;
            c.rcv_nxt +%= len32(data.len);
            const had_gap = c.ooo_len > 0;
            c.mergeOoo();
            c.unacked_segs +|= 1;
            // ACK at least every second full segment (RFC 9293 3.8.6.3),
            // at once when a gap was filled, otherwise within 40 ms.
            if (had_gap or c.unacked_segs >= 2 or data.len < c.mss) {
                c.ack_now = true;
            } else if (c.delack_at == null) {
                c.delack_at = env.now + delayed_ack_ns;
            }
        } else {
            // Out of order: store in place, remember the range, ACK now
            // (the duplicate ACK drives the sender's fast retransmit).
            c.ack_now = true;
            if (c.dup_acks_owed < max_dup_acks_owed) c.dup_acks_owed += 1;
            if (!c.addRange(env, seq, seq +% len32(data.len))) {
                env.stats.dropped_ooo += 1;
                return;
            }
            c.rcv.writeAt(c.rcv.len + off, data);
        }
    }

    fn addRange(c: *Conn, env: *const Env, start: u32, end: u32) bool {
        var s = start;
        var e = end;
        var i: usize = 0;
        while (i < c.ooo_len) {
            const r = c.ooo[i];
            if (seqLe(r.start, e) and seqLe(s, r.end)) {
                if (seqLt(r.start, s)) s = r.start;
                if (seqLt(e, r.end)) e = r.end;
                c.ooo[i] = c.ooo[c.ooo_len - 1];
                c.ooo_len -= 1;
                continue;
            }
            i += 1;
        }
        const cap = @min(env.limits.max_ooo_segments, max_ooo_ranges);
        if (c.ooo_len >= cap) return false;
        c.ooo[c.ooo_len] = .{ .start = s, .end = e };
        c.ooo_len += 1;
        return true;
    }

    fn mergeOoo(c: *Conn) void {
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < c.ooo_len) {
                const r = c.ooo[i];
                if (seqLe(r.start, c.rcv_nxt)) {
                    if (seqLt(c.rcv_nxt, r.end)) {
                        c.rcv.len += r.end -% c.rcv_nxt;
                        c.rcv_nxt = r.end;
                    }
                    c.ooo[i] = c.ooo[c.ooo_len - 1];
                    c.ooo_len -= 1;
                    progressed = true;
                    continue;
                }
                i += 1;
            }
        }
    }

    fn enterTimeWait(c: *Conn, env: *const Env) void {
        c.state = .time_wait;
        c.rto_at = null;
        c.persist_at = null;
        c.keepalive_at = null;
        c.delack_at = null;
        c.timewait_at = env.now +| nsI64(env.limits.time_wait_ns);
    }

    pub fn fail(c: *Conn, e: ConnError) void {
        c.err = e;
        c.state = .closed;
        c.snd.consume(c.snd.len);
        c.rcv.consume(c.rcv.len);
        c.clearTimers();
    }

    fn clearTimers(c: *Conn) void {
        c.rto_at = null;
        c.delack_at = null;
        c.persist_at = null;
        c.keepalive_at = null;
        c.timewait_at = null;
        c.ack_now = false;
        c.send_syn = false;
        c.probe_now = false;
        c.retransmit_one = false;
    }

    // ---- timers ----------------------------------------------------------------

    pub fn nextDeadline(c: *const Conn) ?i64 {
        var d: ?i64 = null;
        for ([_]?i64{ c.rto_at, c.delack_at, c.persist_at, c.keepalive_at, c.timewait_at }) |t| {
            if (t) |v| d = if (d) |x| @min(x, v) else v;
        }
        return d;
    }

    pub fn onTimers(c: *Conn, env: *const Env) Outcome {
        var out: Outcome = .{};
        const now = env.now;
        if (c.timewait_at) |t| if (now >= t) {
            c.state = .closed;
            c.clearTimers();
            out.notify = true;
            return out;
        };
        if (c.delack_at) |t| if (now >= t) {
            c.delack_at = null;
            c.ack_now = true;
            out.output = true;
        };
        if (c.rto_at) |t| if (now >= t) {
            c.rto_at = null;
            if (c.stalled_since == null) c.stalled_since = now;
            const given_up = (now - c.stalled_since.? >= nsI64(env.limits.user_timeout_ns)) or
                (c.state == .syn_received and c.backoff >= max_synack_retries);
            if (given_up) {
                env.stats.timeouts += 1;
                if (c.state == .syn_received) {
                    c.state = .closed;
                    c.clearTimers();
                } else c.fail(error.ConnectionTimedOut);
                out.notify = true;
                return out;
            }
            env.stats.rto_expirations += 1;
            // RFC 5681 (4): loss window; RFC 6298 5.5: back off.
            const fl = c.snd_max -% c.snd_una;
            c.ssthresh = @max(fl / 2, 2 * @as(u32, c.mss));
            c.cwnd = c.mss;
            c.in_recovery = false;
            c.recover = c.snd_max;
            c.dupacks = 0;
            c.snd_nxt = c.snd_una; // go back N
            c.rtt_seq = null; // Karn
            c.rto = @min(c.rto * 2, max_rto_ns);
            c.backoff +|= 1;
            if (c.state == .syn_sent or c.state == .syn_received) c.send_syn = true;
            out.output = true;
        };
        if (c.persist_at) |t| if (now >= t) {
            c.persist_at = null;
            c.probe_now = true;
            c.persist_backoff +|= 1;
            out.output = true;
        };
        if (c.keepalive_at) |t| if (now >= t) {
            if (c.keepalive_sent >= keepalive_probes) {
                env.stats.timeouts += 1;
                c.fail(error.ConnectionTimedOut);
                out.notify = true;
                return out;
            }
            c.keepalive_sent += 1;
            c.probe_now = true;
            c.keepalive_at = now + keepalive_interval_ns;
            out.output = true;
        };
        return out;
    }

    // ---- output ----------------------------------------------------------------

    /// Builds the next segment this connection wants to send (an IPv4
    /// packet in `buf`, `buf.len >= mtu`) of the given class, or null.
    pub fn output(c: *Conn, env: *const Env, buf: []u8, ip_id: u16, class: OutputClass) ?[]u8 {
        switch (c.state) {
            .closed, .listen => return null,
            .syn_sent => return if (c.send_syn) c.emitSyn(env, buf, ip_id, false) else null,
            .syn_received => {
                if (c.send_syn) return c.emitSyn(env, buf, ip_id, true);
                if (c.ack_now) return c.pureAck(env, buf, ip_id);
                return null;
            },
            .time_wait, .fin_wait_2 => {
                if (c.ack_now or c.probe_now) {
                    c.probe_now = false;
                    return c.pureAck(env, buf, ip_id);
                }
                return null;
            },
            else => {},
        }

        // Owed duplicate ACKs first: pure ACKs, each one separate.
        if (c.dup_acks_owed > 0) {
            c.dup_acks_owed -= 1;
            const p = c.pureAck(env, buf, ip_id);
            if (c.dup_acks_owed > 0) c.ack_now = true;
            return p;
        }

        if (class == .any) {
            // Fast / partial-ACK retransmission of the first unacked segment.
            if (c.retransmit_one) {
                c.retransmit_one = false;
                if (c.snd_una != c.snd_max) {
                    if (c.segmentAt(env, buf, ip_id, c.snd_una, c.mss, true)) |p| return p;
                }
            }
            if (c.dataSegment(env, buf, ip_id)) |p| return p;
        } else {
            // A bare FIN carries no data: control class.
            if (c.unsent() == 0 and c.fin_queued and seqLe(c.snd_nxt, c.finSeq()) and c.snd_wnd > 0) {
                if (c.segmentAt(env, buf, ip_id, c.snd_nxt, 0, false)) |p| return p;
            }
        }

        // Window probe / keepalive: an old sequence number (snd_una - 1),
        // no data; the peer answers with an ACK carrying its window.
        if (c.probe_now) {
            c.probe_now = false;
            return c.emit(env, buf, ip_id, c.snd_una -% 1, .{}, &.{});
        }
        if (c.ack_now) return c.pureAck(env, buf, ip_id);
        return null;
    }

    /// An ACK without data. Its sequence number is snd_max, not snd_nxt
    /// (BSD tcp_output does the same): after a retransmission timeout
    /// snd_nxt is rolled back to snd_una, and the peer, which may already
    /// hold everything up to snd_max, would find a pure ACK at snd_nxt
    /// "unacceptable" and drop it unprocessed. With both ends in that
    /// state the connection would never recover.
    fn pureAck(c: *Conn, env: *const Env, buf: []u8, ip_id: u16) ?[]u8 {
        return c.emit(env, buf, ip_id, c.snd_max, .{}, &.{});
    }

    /// New (or go-back-N) data within min(snd_wnd, cwnd), or a FIN.
    fn dataSegment(c: *Conn, env: *const Env, buf: []u8, ip_id: u16) ?[]u8 {
        if (!c.canSendData()) return null;
        const left = len32(c.unsent());
        const fin_pending = c.fin_queued and seqLe(c.snd_nxt, c.finSeq());
        if (left == 0 and !fin_pending) return null;
        const fl = c.flight();
        // Limited Transmit (RFC 3042): on the first and second duplicate
        // ACK one new segment each, beyond cwnd, so that a loss in a small
        // window still produces the three duplicates fast retransmit needs.
        const limited: u32 = if (!c.in_recovery and c.dupacks > 0 and c.dupacks < 3) c.dupacks * @as(u32, c.mss) else 0;
        const avail = @min(c.snd_wnd, c.cwnd +| limited) -| fl;
        const n = @min(@min(left, c.mss), avail);
        // Sender SWS avoidance (RFC 9293 3.8.6.2.1): a full segment, all
        // that is left, or nothing in flight. No Nagle: small writes go
        // out at once.
        if (n > 0 and (n == c.mss or n == left or fl == 0)) {
            if (c.segmentAt(env, buf, ip_id, c.snd_nxt, n, false)) |p| return p;
        } else if (left == 0 and fin_pending and (c.snd_wnd > 0 or fl == 0)) {
            if (c.segmentAt(env, buf, ip_id, c.snd_nxt, 0, false)) |p| return p;
        }
        // Zero window, nothing in flight: probe it (RFC 9293 3.8.6.1).
        if (left > 0 and c.snd_wnd == 0 and fl == 0 and c.persist_at == null and c.rto_at == null) {
            const shift: u6 = @intCast(@min(c.persist_backoff, 8));
            c.persist_at = env.now + std.math.clamp(c.rto << shift, min_rto_ns, max_rto_ns);
        }
        return null;
    }

    /// Data (and FIN when it ends the stream) starting at `seq`, at most
    /// `max` bytes.
    fn segmentAt(c: *Conn, env: *const Env, buf: []u8, ip_id: u16, seq: u32, max: u32, retransmit: bool) ?[]u8 {
        const off = seq -% c.snd_base;
        const total = len32(c.snd.len);
        const avail: u32 = if (seqLe(c.snd_base, seq) and off <= total) total - off else 0;
        const n = @min(avail, max);
        const hl = wire.ip4_header_len + wire.tcp_header_len;
        if (buf.len < hl + n) return null;
        const payload = buf[hl..][0..n];
        c.snd.readAt(off, payload);
        var flags: wire.Flags = .{};
        if (n > 0 and n == avail) flags.psh = true;
        if (c.fin_queued and seq +% n == c.finSeq()) flags.fin = true;
        if (n == 0 and !flags.fin) return null;
        const end = seq +% n +% @intFromBool(flags.fin);
        // Anything below snd_max was sent before (go-back-N or fast retransmit).
        if (retransmit or seqLt(seq, c.snd_max)) env.stats.retransmits += 1;
        if (!retransmit) {
            // Karn: time only segments never sent before.
            if (c.rtt_seq == null and c.backoff == 0 and seqLe(c.snd_max, seq)) {
                c.rtt_seq = end;
                c.rtt_start = env.now;
            }
            c.snd_nxt = end;
        }
        if (seqLt(c.snd_max, end)) c.snd_max = end;
        if (c.rto_at == null) c.rto_at = env.now + c.rto;
        return c.emit(env, buf, ip_id, seq, flags, payload);
    }

    fn emitSyn(c: *Conn, env: *const Env, buf: []u8, ip_id: u16, ack: bool) ?[]u8 {
        c.send_syn = false;
        if (c.backoff == 0) {
            c.rtt_seq = c.iss +% 1;
            c.rtt_start = env.now;
        }
        c.snd_nxt = c.iss +% 1;
        if (seqLt(c.snd_max, c.snd_nxt)) c.snd_max = c.snd_nxt;
        if (c.rto_at == null) c.rto_at = env.now + c.rto;
        var opts: wire.TcpOptions = .{ .mss = env.mss };
        // Offer window scaling on our SYN; on a SYN-ACK only if the peer did.
        if (!ack or c.snd_shift != 0 or c.rcv_shift != 0) opts.window_scale = c.rcv_shift;
        const wnd: u16 = @intCast(@min(c.rcvSpace(env), 0xffff)); // never scaled in a SYN
        c.rcv_adv = c.rcv_nxt +% wnd;
        if (ack) {
            c.ack_now = false;
            c.delack_at = null;
        }
        return c.build(buf, ip_id, .{
            .src_port = c.local.port,
            .dst_port = c.remote.port,
            .seq = c.iss,
            .ack = if (ack) c.rcv_nxt else 0,
            .flags = .{ .syn = true, .ack = ack },
            .window = wnd,
            .options = opts,
        });
    }

    /// Every non-SYN segment: carries ACK and the current window.
    fn emit(c: *Conn, env: *const Env, buf: []u8, ip_id: u16, seq: u32, flags_in: wire.Flags, payload: []const u8) ?[]u8 {
        var flags = flags_in;
        flags.ack = true;
        const wnd: u16 = @intCast(@min(c.rcvSpace(env) >> c.rcv_shift, 0xffff));
        const edge = c.rcv_nxt +% (@as(u32, wnd) << c.rcv_shift);
        // Never shrink the advertised right edge (RFC 9293 3.8.6.2.2).
        if (seqLt(c.rcv_adv, edge)) c.rcv_adv = edge;
        c.ack_now = false;
        c.delack_at = null;
        c.unacked_segs = 0;
        return c.build(buf, ip_id, .{
            .src_port = c.local.port,
            .dst_port = c.remote.port,
            .seq = seq,
            .ack = c.rcv_nxt,
            .flags = flags,
            .window = wnd,
            .payload = payload,
        });
    }

    fn build(c: *const Conn, buf: []u8, ip_id: u16, seg: wire.Tcp) ?[]u8 {
        return wire.buildTcp4(buf, .{
            .protocol = wire.proto_tcp,
            .id = ip_id,
            .src = c.local.addr.v4,
            .dst = c.remote.addr.v4,
        }, seg) catch null;
    }
};

/// The RST that answers `seg` when no connection matches (RFC 9293 3.10.7.1).
pub fn rstFor(seg: wire.Tcp) Rst {
    if (seg.flags.ack) return .{ .seq = seg.ack, .ack = null };
    return .{ .seq = 0, .ack = seg.seq +% seg.segLen() };
}

test "seq arithmetic wraps" {
    try std.testing.expect(seqLt(0xffff_fff0, 0x10));
    try std.testing.expect(!seqLt(0x10, 0xffff_fff0));
    try std.testing.expect(seqLe(5, 5));
}

test "byte ring wraps, out-of-order writes" {
    var mem: [8]u8 = undefined;
    var r: ByteRing = .{ .buf = &mem };
    try std.testing.expectEqual(@as(usize, 6), r.append("abcdef"));
    r.consume(4);
    try std.testing.expectEqual(@as(usize, 6), r.append("ghijklmn"));
    var out: [8]u8 = undefined;
    r.readAt(0, out[0..8]);
    try std.testing.expectEqualStrings("efghijkl", &out);
    r.consume(8);
    r.writeAt(3, "xyz");
    r.writeAt(0, "abc");
    r.len = 6;
    r.readAt(0, out[0..6]);
    try std.testing.expectEqualStrings("abcxyz", out[0..6]);
}
