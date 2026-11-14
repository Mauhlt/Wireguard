//! RACK (RFC 8985): time-based loss detection for a SACK connection.
//!
//! A bounded ring of transmit records, one per segment in flight (start,
//! end, last transmit time, flags), in sequence order and covering
//! [snd_una, snd_max). No per-segment allocation: `max_records` per
//! connection; past that, new data is folded into the last record (with
//! the newer timestamp, so detection gets later, never earlier).
//!
//! On every ACK the connection marks records the cumulative ACK or the
//! SACK scoreboard covers as delivered; the most recently *sent* delivered
//! segment becomes RACK.xmit_ts / end_seq / rtt. A record sent before that
//! one is lost once now >= its xmit_ts + RACK.rtt + reo_wnd; until then the
//! earliest such moment is the reorder timer (a deadline). Retransmissions
//! get fresh timestamps, so a lost retransmission is detected the same way
//! instead of waiting for the RTO.
//!
//! The reorder window is min_RTT / 4 * reo_wnd_mult, capped at SRTT, and 0
//! until reordering has been seen while recovering (RFC 8985 6.2 step 4).
//! D-SACKs raise reo_wnd_mult by one at most once per round trip, up to
//! `max_reo_wnd_mult`; after `reo_wnd_persist_episodes` recoveries without
//! one it falls back to 1.
const std = @import("std");
const tcp = @import("tcp.zig");
const seqLt = tcp.seqLt;
const seqLe = tcp.seqLe;

pub const max_records = 256;
pub const max_reo_wnd_mult = 16;
pub const reo_wnd_persist_episodes = 16;

pub const Record = struct {
    start: u32,
    end: u32,
    /// Last (re)transmission time.
    ts: i64,
    rexmit: bool = false,
    /// Delivered: cumulatively ACKed or SACKed.
    sacked: bool = false,
    lost: bool = false,
};

/// [start, end) of a lost record still to be retransmitted.
pub const Hole = struct { seq: u32, len: u32 };

pub const Rack = struct {
    rec: [max_records]Record = undefined,
    head: u16 = 0,
    len: u16 = 0,

    // RACK state (RFC 8985 6.1)
    xmit_ts: i64 = 0,
    end_seq: u32 = 0,
    rtt: i64 = 0,
    valid: bool = false,
    /// Highest delivered end sequence (RACK.fack).
    fack: u32 = 0,
    fack_valid: bool = false,
    min_rtt: i64 = 0,
    reordering_seen: bool = false,
    reo_wnd_mult: u8 = 1,
    reo_wnd_persist: u8 = 0,
    dsack_round: ?u32 = null,
    /// Reorder timer (device clock), part of the connection's deadlines.
    timer_at: ?i64 = null,

    pub fn at(r: *Rack, i: usize) *Record {
        return &r.rec[(r.head + i) % max_records];
    }

    fn atConst(r: *const Rack, i: usize) Record {
        return r.rec[(r.head + i) % max_records];
    }

    /// A transmission of [start, end) at `now`: records it overlaps get the
    /// new time and are no longer lost (split at the edges when there is
    /// room); bytes beyond the last record are new and appended.
    pub fn sent(r: *Rack, start: u32, end: u32, now: i64) void {
        if (!seqLt(start, end)) return;
        var i: usize = 0;
        while (i < r.len) : (i += 1) {
            const cur = r.at(i);
            if (!seqLt(cur.start, end)) break;
            if (!seqLt(start, cur.end)) continue;
            if (seqLt(cur.start, start) and r.split(i, start)) continue; // next: the overlapping half
            if (seqLt(end, r.at(i).end)) _ = r.split(i, end);
            const x = r.at(i);
            x.ts = now;
            x.rexmit = true;
            x.lost = false;
        }
        const tail_end = if (r.len > 0) r.at(r.len - 1).end else start;
        const new_start = if (seqLt(start, tail_end)) tail_end else start;
        if (!seqLt(new_start, end)) return;
        if (r.len == max_records) {
            // Fold into the last record: one longer segment, newer time.
            const last = r.at(r.len - 1);
            last.end = end;
            last.ts = now;
            return;
        }
        r.len += 1;
        r.at(r.len - 1).* = .{ .start = new_start, .end = end, .ts = now };
    }

    /// Splits record i at `seq` (inside it). False when the ring is full.
    fn split(r: *Rack, i: usize, seq: u32) bool {
        if (r.len == max_records) return false;
        var k: usize = r.len;
        while (k > i + 1) : (k -= 1) r.at(k).* = r.at(k - 1).*;
        const orig = r.at(i).*;
        r.at(i + 1).* = orig;
        r.at(i + 1).start = seq;
        r.at(i).end = seq;
        r.len += 1;
        return true;
    }

    /// Marks records covered by the cumulative ACK or a SACKed range as
    /// delivered, updating the RACK state from each newly delivered one,
    /// then drops what the cumulative ACK covers. `sacked` is the sorted
    /// scoreboard (anything with .start / .end).
    pub fn delivered(r: *Rack, ack: u32, sacked: anytype, now: i64) void {
        for (0..r.len) |i| {
            const x = r.at(i);
            if (x.sacked) continue;
            const covered = seqLe(x.end, ack) or blk: {
                for (sacked) |s| if (seqLe(s.start, x.start) and seqLe(x.end, s.end)) break :blk true;
                break :blk false;
            };
            if (!covered) continue;
            x.sacked = true;
            x.lost = false;
            r.update(x.*, now);
        }
        while (r.len > 0 and seqLe(r.at(0).end, ack)) {
            r.head = @intCast((r.head + 1) % max_records);
            r.len -= 1;
        }
        if (r.len > 0 and seqLt(r.at(0).start, ack)) r.at(0).start = ack;
    }

    /// RFC 8985 6.2 steps 1-3 for one newly delivered segment.
    fn update(r: *Rack, x: Record, now: i64) void {
        const rtt = now - x.ts;
        // A retransmission ACKed faster than any RTT seen is the original's
        // ACK: ambiguous, skip it (step 2).
        if (x.rexmit and (r.min_rtt == 0 or rtt < r.min_rtt)) return;
        if (rtt > 0 and (r.min_rtt == 0 or rtt < r.min_rtt)) r.min_rtt = rtt;
        if (r.fack_valid and seqLt(x.end, r.fack)) {
            r.reordering_seen = true;
        } else {
            r.fack = x.end;
            r.fack_valid = true;
        }
        if (!r.valid or sentAfter(x.ts, x.end, r.xmit_ts, r.end_seq)) {
            r.xmit_ts = x.ts;
            r.end_seq = x.end;
            r.rtt = @max(rtt, 0);
            r.valid = true;
        }
    }

    fn sentAfter(t1: i64, s1: u32, t2: i64, s2: u32) bool {
        return t1 > t2 or (t1 == t2 and seqLt(s2, s1));
    }

    /// RFC 8985 6.2 step 4 (with the cap at SRTT).
    pub fn reoWnd(r: *const Rack, srtt: i64, in_recovery: bool, sacked_segments: u32) i64 {
        if (!r.reordering_seen and (in_recovery or sacked_segments >= 3)) return 0;
        const w = @divTrunc(r.min_rtt, 4) * r.reo_wnd_mult;
        return @min(w, srtt);
    }

    /// RFC 8985 6.2 step 5: marks lost records, arms `timer_at` for the
    /// earliest not-yet-lost candidate. Returns how many became lost.
    pub fn detect(r: *Rack, now: i64, reo_wnd: i64) u32 {
        r.timer_at = null;
        if (!r.valid) return 0;
        var lost: u32 = 0;
        for (0..r.len) |i| {
            const x = r.at(i);
            if (x.sacked or x.lost) continue;
            if (!sentAfter(r.xmit_ts, r.end_seq, x.ts, x.end)) continue;
            const due = x.ts +| r.rtt +| reo_wnd;
            if (now >= due) {
                x.lost = true;
                lost += 1;
            } else {
                r.timer_at = if (r.timer_at) |t| @min(t, due) else due;
            }
        }
        return lost;
    }

    /// RTO: everything outstanding is lost and nothing SACKed is trusted
    /// (RFC 8985 6.3; RFC 2018 reneging).
    pub fn onRto(r: *Rack) void {
        for (0..r.len) |i| {
            const x = r.at(i);
            x.lost = true;
            x.sacked = false;
        }
        r.timer_at = null;
    }

    /// RFC 6675 pipe with RACK's view: bytes neither delivered nor lost.
    pub fn pipe(r: *const Rack) u32 {
        var p: u32 = 0;
        for (0..r.len) |i| {
            const x = r.atConst(i);
            if (!x.sacked and !x.lost) p +%= x.end -% x.start;
        }
        return p;
    }

    /// NextSeg: the first lost record still to retransmit.
    pub fn nextLost(r: *const Rack, smss: u32) ?Hole {
        for (0..r.len) |i| {
            const x = r.atConst(i);
            if (x.lost and !x.sacked) return .{ .seq = x.start, .len = @min(x.end -% x.start, smss) };
        }
        return null;
    }

    pub fn anyLost(r: *const Rack) bool {
        for (0..r.len) |i| if (r.atConst(i).lost) return true;
        return false;
    }

    /// A D-SACK arrived: grow the reorder window, at most once per round
    /// trip (RFC 8985 6.2 step 4), capped.
    pub fn onDsack(r: *Rack, snd_una: u32, snd_max: u32) void {
        // Strictly past the previous round's end: with nothing in flight
        // (snd_una == snd_max) a flood must not count again and again.
        if (r.dsack_round) |round| if (!seqLt(round, snd_una)) return;
        r.reo_wnd_mult = @min(r.reo_wnd_mult +| 1, max_reo_wnd_mult);
        r.dsack_round = snd_max;
        r.reo_wnd_persist = reo_wnd_persist_episodes;
    }

    /// A loss recovery ended: after enough of them without a D-SACK the
    /// reorder window shrinks back.
    pub fn onRecoveryEnd(r: *Rack) void {
        if (r.reo_wnd_persist == 0) return;
        r.reo_wnd_persist -= 1;
        if (r.reo_wnd_persist == 0) r.reo_wnd_mult = 1;
    }
};

test "records: append, retransmit splits, delivered pops, fold when full" {
    var r: Rack = .{};
    r.sent(100, 200, 1);
    r.sent(200, 300, 2);
    r.sent(300, 400, 3);
    try std.testing.expectEqual(@as(u16, 3), r.len);
    // Retransmit the middle of the second record: split around it.
    r.sent(220, 260, 10);
    try std.testing.expectEqual(@as(u16, 5), r.len);
    try std.testing.expectEqual(@as(u32, 220), r.at(2).start);
    try std.testing.expectEqual(@as(i64, 10), r.at(2).ts);
    try std.testing.expect(r.at(2).rexmit and !r.at(1).rexmit and !r.at(3).rexmit);
    // Cumulative ACK to 250: the first two pop, the third is trimmed.
    const none: []const Record = &.{};
    r.delivered(250, none, 20);
    try std.testing.expectEqual(@as(u32, 250), r.at(0).start);
    // Fill the ring: later data folds into the last record.
    var s: u32 = 400;
    while (r.len < max_records) : (s += 10) r.sent(s, s + 10, 30);
    r.sent(s, s + 10, 40);
    try std.testing.expectEqual(@as(u16, max_records), r.len);
    try std.testing.expectEqual(s + 10, r.at(r.len - 1).end);
    try std.testing.expectEqual(@as(i64, 40), r.at(r.len - 1).ts);
}

test "detection: lost once sent before the newest delivered + rtt + reo_wnd" {
    var r: Rack = .{};
    r.sent(0, 10, 100);
    r.sent(10, 20, 110);
    r.sent(20, 30, 120);
    // [20,30) SACKed at 150: RACK.rtt = 30, xmit_ts = 120.
    const sb = [_]Record{.{ .start = 20, .end = 30, .ts = 0 }};
    r.delivered(0, &sb, 150);
    try std.testing.expectEqual(@as(i64, 30), r.rtt);
    // With a reorder window of 5: [0,10) is due at 100+30+5 = 135 <= 150:
    // lost; [10,20) at 145 <= 150: lost as well.
    try std.testing.expectEqual(@as(u32, 2), r.detect(150, 5));
    try std.testing.expectEqual(@as(?i64, null), r.timer_at);
    // A wider window arms the timer instead.
    var q: Rack = .{};
    q.sent(0, 10, 100);
    q.sent(10, 20, 110);
    q.delivered(0, &[_]Record{.{ .start = 10, .end = 20, .ts = 0 }}, 120);
    try std.testing.expectEqual(@as(u32, 0), q.detect(120, 50));
    try std.testing.expectEqual(@as(?i64, 100 + 10 + 50), q.timer_at);
    try std.testing.expectEqual(@as(u32, 1), q.detect(160, 50));
}

test "reorder window: zero before reordering is seen in recovery, D-SACK grows it once per round, capped" {
    var r: Rack = .{ .min_rtt = 40 };
    try std.testing.expectEqual(@as(i64, 0), r.reoWnd(100, true, 0));
    try std.testing.expectEqual(@as(i64, 10), r.reoWnd(100, false, 0));
    r.onDsack(1000, 2000);
    try std.testing.expectEqual(@as(u8, 2), r.reo_wnd_mult);
    r.onDsack(1500, 2000); // same round trip: no growth
    try std.testing.expectEqual(@as(u8, 2), r.reo_wnd_mult);
    for (0..100) |k| r.onDsack(2000 + @as(u32, @intCast(k)) * 100, 2100 + @as(u32, @intCast(k)) * 100);
    try std.testing.expectEqual(@as(u8, max_reo_wnd_mult), r.reo_wnd_mult);
    // Capped at SRTT whatever the multiplier.
    try std.testing.expectEqual(@as(i64, 100), r.reoWnd(100, false, 0));
    for (0..reo_wnd_persist_episodes) |_| r.onRecoveryEnd();
    try std.testing.expectEqual(@as(u8, 1), r.reo_wnd_mult);
}
