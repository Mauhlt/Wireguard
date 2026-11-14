//! Fuzz targets for the parsers and network-facing entry points
//! (`std.testing.fuzz`). The noise message parsers / consumers live next to
//! their known-answer tests in noise/tests.zig; everything else is here.
//!
//! Real coverage-guided fuzzing (Linux or macOS; `--fuzz` is not
//! implemented on Windows in this Zig version):
//!
//!     zig build test --fuzz=<runs per target> -Doptimize=ReleaseSafe
//!
//! ReleaseSafe keeps the safety checks (bounds, overflow, unreachable) that
//! turn a bug into a crash; Debug fuzz builds of this Zig version fail with
//! "corrupted coverage file: pcs_len was zero". Without `--fuzz`, `zig build
//! test` runs every target once per corpus entry plus the empty input, so
//! they double as ordinary unit tests and as regression tests (a minimised
//! crashing input goes into the target's corpus).
//!
//! Each target checks properties, not just "does not crash": round trips,
//! agreement between two independent implementations, agreement with a
//! brute-force reference model, and the device's cryptokey-routing
//! invariants on everything it hands to the TUN.
const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const Weight = Smith.Weight;
const net = std.Io.net;

const crypto = @import("crypto.zig");
const noise = @import("noise/root.zig");
const session = @import("session/root.zig");
const dev = @import("device/root.zig");
const tun = @import("tun/root.zig");
const ip = dev.ip;

/// Corpus entry for a target whose first Smith draw is `slice`: Smith's
/// input encoding is a little-endian u32 length followed by the bytes.
pub fn sliceInput(comptime bytes: []const u8) []const u8 {
    const S = struct {
        const data = blk: {
            var len: [4]u8 = undefined;
            std.mem.writeInt(u32, &len, @intCast(bytes.len), .little);
            break :blk len ++ bytes[0..bytes.len].*;
        };
    };
    return &S.data;
}

/// Bytes that make overlapping prefixes and boundary values likely, while
/// still allowing every value.
const interesting_bytes: []const Weight = &.{
    .rangeAtMost(u8, 0, 255, 1),
    .value(u8, 0, 64),
    .value(u8, 0xff, 32),
    .value(u8, 0x80, 16),
    .value(u8, 1, 16),
    .value(u8, 10, 16),
};

/// A few random edits (bit flip, byte set, truncate) to `buf[0..len]`.
pub fn mutate(s: *Smith, buf: []u8, len: usize) usize {
    var n = len;
    var edits: usize = 0;
    while (edits < 4 and s.boolWeighted(3, 1)) : (edits += 1) {
        switch (s.valueRangeAtMost(u8, 0, 2)) {
            0 => if (n != 0) {
                buf[s.index(n)] ^= @as(u8, 1) << s.value(u3);
            },
            1 => if (n != 0) {
                buf[s.index(n)] = s.value(u8);
            },
            else => n = s.index(n + 1),
        }
    }
    return n;
}

// ---------------------------------------------------------------- config

const sample_conf =
    \\[Interface]
    \\PrivateKey = eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w=
    \\ListenPort = 51820
    \\Address = 10.0.0.1/24, fd00::1/64
    \\DNS = 1.1.1.1, example.com
    \\MTU = 1420
    \\
    \\[Peer]
    \\PublicKey = WAdXKvvGG8bEGuj6IXZLtVvvXQ0HM8SNJ+mOhTq4HlQ=
    \\PresharedKey = OCRz6Lf/a9wkeOKKCGHuK/0oUGCUQpd/qz6+v/PQ6Fs=
    \\AllowedIPs = 10.0.0.2/32, ::/0
    \\Endpoint = [2001:db8::1]:51820
    \\PersistentKeepalive = 25
    \\
    \\[Peer]
    \\PublicKey = OCRz6Lf/a9wkeOKKCGHuK/0oUGCUQpd/qz6+v/PQ6Fs=
    \\AllowedIPs = 10.0.0.3/32
    \\Endpoint = vpn.example.com:51820
    \\
;

fn fuzzConfig(_: void, s: *Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    const text = buf[0..s.slice(&buf)];
    var diag: dev.config.Diagnostic = .{};
    var c = dev.config.parse(testing.allocator, text, &diag) catch |err| switch (err) {
        error.InvalidConfig => {
            var sink: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&sink);
            w.print("{f}", .{diag}) catch {};
            return;
        },
        error.OutOfMemory => return err,
    };
    defer c.deinit();
    // What we write back must parse, and write back identically.
    var out1: [16384]u8 = undefined;
    var w1: std.Io.Writer = .fixed(&out1);
    dev.config.write(&c, &w1, true) catch return; // larger than the buffer: fine
    var c2 = dev.config.parse(testing.allocator, w1.buffered(), &diag) catch |err| {
        std.debug.print("re-parse of written config failed ({t}): {f}\n{s}\n", .{ err, diag, w1.buffered() });
        return error.ConfigRoundTrip;
    };
    defer c2.deinit();
    var out2: [16384]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&out2);
    try dev.config.write(&c2, &w2, true);
    try testing.expectEqualStrings(w1.buffered(), w2.buffered());
    try testing.expectEqual(c.peers.len, c2.peers.len);
}

test "fuzz: .conf parser (round trip)" {
    try testing.fuzz({}, fuzzConfig, .{ .corpus = &.{
        sliceInput(sample_conf),
        sliceInput("[Interface]\nPrivateKey = eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w=\n"),
        sliceInput("[Interface]\r\nPrivateKey=eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w= # c\r\nTable = off\r\n"),
    } });
}

// ---------------------------------------------------------- text parsers

fn fuzzTextParsers(_: void, s: *Smith) anyerror!void {
    var buf: [96]u8 = undefined;
    const text = buf[0..s.slice(&buf)];

    // Keys: the one (constant-time) decoder accepts only canonical text
    // and agrees with std.base64, the independent oracle, on what it
    // accepts and what it decodes to.
    const a = dev.keys.decode(text);
    if (a) |ka| {
        try testing.expectEqualStrings(text, &dev.keys.encode(&ka));
        // std.base64 needs the destination sized by calcSizeForSlice.
        try testing.expectEqual(@as(usize, 32), try std.base64.standard.Decoder.calcSizeForSlice(text));
        var std_out: [32]u8 = undefined;
        try std.base64.standard.Decoder.decode(&std_out, text);
        try testing.expectEqualSlices(u8, &ka, &std_out);
    } else |_| {
        // std accepts it and it re-encodes to the same text => we must too.
        const std_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch 0;
        if (text.len == 44 and std_len == 32) {
            var std_out: [32]u8 = undefined;
            if (std.base64.standard.Decoder.decode(&std_out, text)) |_| {
                var again: [44]u8 = undefined;
                _ = std.base64.standard.Encoder.encode(&again, &std_out);
                if (std.mem.eql(u8, &again, text)) return error.CanonicalKeyRejected;
            } else |_| {}
        }
    }

    var fbuf: [128]u8 = undefined;
    if (ip.Addr.parse(text)) |addr| {
        var w: std.Io.Writer = .fixed(&fbuf);
        try w.print("{f}", .{addr});
        try testing.expect(addr.eql(try ip.Addr.parse(w.buffered())));
    } else |_| {}
    if (ip.Cidr.parse(text)) |c| {
        var w: std.Io.Writer = .fixed(&fbuf);
        try w.print("{f}", .{c});
        try testing.expect(c.eql(try ip.Cidr.parse(w.buffered())));
        try testing.expect(c.masked().contains(c.addr));
        try testing.expect(!c.masked().hasHostBits());
    } else |_| {}
    if (tun.Cidr.parse(text)) |c| {
        var w: std.Io.Writer = .fixed(&fbuf);
        try w.print("{f}", .{c});
        const back = try tun.Cidr.parse(w.buffered());
        try testing.expect(std.meta.eql(c, back));
        _ = c.network();
        if (c.family == .ip4) _ = c.netmask4();
    } else |_| {}
    if (dev.config.Endpoint.parse(text)) |e| {
        var w: std.Io.Writer = .fixed(&fbuf);
        try w.print("{f}", .{e});
        const back = try dev.config.Endpoint.parse(w.buffered());
        try testing.expectEqualStrings(e.host, back.host);
        try testing.expectEqual(e.port, back.port);
        _ = e.literal();
    } else |_| {}
    _ = tun.UdpTun.parseSpec(text) catch {};
}

test "fuzz: keys, addresses, CIDRs, endpoints" {
    try testing.fuzz({}, fuzzTextParsers, .{ .corpus = &.{
        sliceInput("eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w="),
        sliceInput("eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2x="),
        sliceInput("10.0.0.0/8"),
        sliceInput("fd00::1/64"),
        sliceInput("[2001:db8::1]:51820"),
        sliceInput("vpn.example.com:51820"),
        sliceInput("udp:51820"),
    } });
}

// ------------------------------------------------------------ allowed IPs

fn drawAddr(s: *Smith) ip.Addr {
    if (s.boolWeighted(1, 1)) {
        var b: [16]u8 = undefined;
        s.bytesWeighted(&b, interesting_bytes);
        return .{ .v6 = b };
    }
    var b: [4]u8 = undefined;
    s.bytesWeighted(&b, interesting_bytes);
    return .{ .v4 = b };
}

fn drawCidr(s: *Smith) ip.Cidr {
    const a = drawAddr(s);
    return .{ .addr = a, .prefix = s.valueRangeAtMost(u8, 0, a.bits()) };
}

const RefEntry = struct { cidr: ip.Cidr, value: u8 };

fn refLookup(ref: []const RefEntry, a: ip.Addr) ?u8 {
    var best: ?RefEntry = null;
    for (ref) |e| if (e.cidr.contains(a)) {
        if (best == null or e.cidr.prefix > best.?.cidr.prefix) best = e;
    };
    return if (best) |e| e.value else null;
}

fn refFind(ref: []const RefEntry, c: ip.Cidr) ?usize {
    for (ref, 0..) |e, i| if (e.cidr.eql(c)) return i;
    return null;
}

/// The trie against a brute-force list, over arbitrary sequences of
/// insert / remove / removeValue / lookup.
fn fuzzAllowedIps(_: void, s: *Smith) anyerror!void {
    var t = dev.AllowedIps(u8).init(testing.allocator);
    defer t.deinit();
    var ref_buf: [64]RefEntry = undefined;
    var n: usize = 0;
    var ops: usize = 0;
    while (ops < 128 and !s.eos()) : (ops += 1) {
        switch (s.valueRangeAtMost(u8, 0, 3)) {
            0 => {
                const raw = drawCidr(s); // host bits set: must be ignored
                const c = raw.masked();
                const v = s.valueRangeAtMost(u8, 0, 7);
                if (refFind(ref_buf[0..n], c)) |i| {
                    ref_buf[i].value = v;
                } else if (n < ref_buf.len) {
                    ref_buf[n] = .{ .cidr = c, .value = v };
                    n += 1;
                } else continue;
                try t.insert(raw, v);
            },
            1 => {
                const raw = drawCidr(s);
                const c = raw.masked();
                const want = refFind(ref_buf[0..n], c);
                if (want) |i| {
                    ref_buf[i] = ref_buf[n - 1];
                    n -= 1;
                }
                try testing.expectEqual(want != null, t.remove(raw));
            },
            2 => {
                const v = s.valueRangeAtMost(u8, 0, 7);
                var i: usize = 0;
                while (i < n) {
                    if (ref_buf[i].value == v) {
                        ref_buf[i] = ref_buf[n - 1];
                        n -= 1;
                    } else i += 1;
                }
                t.removeValue(v);
            },
            else => {
                const a = drawAddr(s);
                try testing.expectEqual(refLookup(ref_buf[0..n], a), t.lookup(a));
            },
        }
        // Every stored prefix's own network address resolves as the model says.
        for (ref_buf[0..n]) |e| try testing.expectEqual(refLookup(ref_buf[0..n], e.cidr.addr), t.lookup(e.cidr.addr));
    }
    if (n == 0) try testing.expectEqual(@as(usize, 0), t.nodeCount());
}

test "fuzz: allowed-IPs trie against a brute-force model" {
    try testing.fuzz({}, fuzzAllowedIps, .{});
}

// --------------------------------------------------- transport + replay

const fuzz_key: crypto.SymKey = @splat(0x42);

/// seal -> open round trip; every truncation and every authenticated
/// bit flip rejected; arbitrary bytes never authenticate.
fn fuzzTransport(_: void, s: *Smith) anyerror!void {
    const T = session.transport;
    var plain: [300]u8 = undefined;
    const pl = plain[0..s.slice(&plain)];
    const counter = s.value(u64);
    const index = s.value(u32);
    const mtu = s.valueRangeAtMost(u16, 0, 1500);
    var pkt: [512]u8 = undefined;
    const n = T.seal(&fuzz_key, index, counter, pl, mtu, &pkt) catch |err| switch (err) {
        error.BufferTooSmall => return,
    };
    try testing.expectEqual(T.messageLen(pl.len, mtu), n);
    var out: [512]u8 = undefined;
    const opened = try T.open(&fuzz_key, pkt[0..n], &out);
    try testing.expectEqualSlices(u8, pl, opened[0..pl.len]);
    for (opened[pl.len..]) |b| try testing.expectEqual(@as(u8, 0), b);
    const h = try T.Header.parse(pkt[0..n]);
    try testing.expectEqual(index, h.receiver_index);
    try testing.expectEqual(counter, h.counter);

    // Truncated: never opens.
    const cut = s.index(n);
    if (T.open(&fuzz_key, pkt[0..cut], &out)) |_| return error.TruncatedOpened else |_| {}

    // One flipped bit: the receiver index (bytes 4..8) is not authenticated
    // (WireGuard looks the keypair up by it); anything else must fail.
    const i = s.index(n);
    pkt[i] ^= @as(u8, 1) << s.value(u3);
    if (T.open(&fuzz_key, pkt[0..n], &out)) |_| {
        if (i < 4 or i >= 8) return error.TamperedOpened;
    } else |_| {}

    // Arbitrary bytes.
    var junk: [128]u8 = undefined;
    const jl = s.slice(&junk);
    if (T.open(&fuzz_key, junk[0..jl], &out)) |_| return error.JunkOpened else |_| {}
}

test "fuzz: transport seal/open" {
    try testing.fuzz({}, fuzzTransport, .{});
}

/// The RFC 6479 bitmap against an exact model: accept iff below
/// REJECT_AFTER_MESSAGES, not seen, and at most COUNTER_WINDOW_SIZE behind
/// the highest accepted counter.
fn fuzzReplay(_: void, s: *Smith) anyerror!void {
    const C = session.constants;
    var w: session.ReplayWindow = .{};
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(testing.allocator);
    var max: u64 = 0;
    var ops: usize = 0;
    while (ops < 512 and !s.eos()) : (ops += 1) {
        const d: u64 = s.valueWeighted(u16, &.{
            .rangeAtMost(u16, 0, 0xffff, 1),
            .rangeAtMost(u16, 0, 70, 1000),
            .rangeAtMost(u16, C.COUNTER_WINDOW_SIZE - 70, C.COUNTER_WINDOW_SIZE + 70, 1000),
        });
        const counter: u64 = switch (s.valueRangeAtMost(u8, 0, 4)) {
            0 => max -| d,
            1 => max +| d,
            2 => C.REJECT_AFTER_MESSAGES -% d,
            3 => max +| (d * 64),
            else => s.value(u64),
        };
        const expect = counter < C.REJECT_AFTER_MESSAGES and !seen.contains(counter) and
            (counter > max or max - counter <= C.COUNTER_WINDOW_SIZE);
        try testing.expectEqual(expect, w.check(counter));
        try testing.expectEqual(expect, w.update(counter));
        if (expect) {
            try seen.put(testing.allocator, counter, {});
            max = @max(max, counter);
        }
    }
}

test "fuzz: replay window against an exact model" {
    try testing.fuzz({}, fuzzReplay, .{});
}

// ------------------------------------------------------------ tun paths

const FlowSink = struct {
    var calls: usize = 0;
    var last_family: u8 = 0;
    var last_len: usize = 0;
    fn write(ctx: ?*anyopaque, p: [*]const u8, len: usize, family: u8) callconv(.c) void {
        _ = ctx;
        _ = p;
        calls += 1;
        last_family = family;
        last_len = len;
    }
};

fn fuzzTunPackets(_: void, s: *Smith) anyerror!void {
    var buf: [1600]u8 = undefined;
    const pkt = buf[0..s.slice(&buf)];

    if (ip.packetAddrs(pkt)) |a| {
        try testing.expect(pkt.len >= 20);
        try testing.expectEqual(std.meta.activeTag(a.src), std.meta.activeTag(a.dst));
    }

    // PacketFlowTun (the iOS seam): what is delivered is read back
    // unchanged (or dropped when above the MTU); writes tag the family from
    // the version nibble.
    const mtu = s.valueRangeAtMost(u16, 1, 1500);
    var pf = try tun.PacketFlowTun.init(testing.allocator, .{ .mtu = mtu, .capacity = 4, .write_fn = FlowSink.write });
    defer pf.deinit();
    const t = pf.tun();
    pf.deliver(pkt);
    var out: [1600]u8 = undefined;
    const got = try t.read(&out);
    if (pkt.len <= mtu) {
        try testing.expectEqualSlices(u8, pkt, got orelse return error.PacketLost);
    } else try testing.expect(got == null);
    try testing.expect((try t.read(&out)) == null);

    FlowSink.calls = 0;
    if (t.write(pkt)) |_| {
        try testing.expectEqual(@as(usize, 1), FlowSink.calls);
        try testing.expectEqual(pkt.len, FlowSink.last_len);
        const want: u8 = if (pkt[0] >> 4 == 4) tun.packetflow.af_inet else tun.packetflow.af_inet6;
        try testing.expectEqual(want, FlowSink.last_family);
    } else |_| try testing.expectEqual(@as(usize, 0), FlowSink.calls);

    // PacketRing against a FIFO model.
    var ring = try tun.queue.PacketRing.init(testing.allocator, 4, 64);
    defer ring.deinit(testing.allocator);
    const Slot = struct { len: usize, fill: u8 };
    var model: [4]Slot = undefined;
    var head: usize = 0;
    var count: usize = 0;
    var ops: usize = 0;
    while (ops < 64 and !s.eos()) : (ops += 1) {
        if (s.boolWeighted(1, 1)) {
            const len = s.valueRangeAtMost(u8, 0, 80);
            var p: [80]u8 = undefined;
            const fill: u8 = @truncate(ops);
            @memset(p[0..len], fill);
            if (ring.push(p[0..len])) |_| {
                try testing.expect(len <= 64 and count < 4);
                model[(head + count) % 4] = .{ .len = len, .fill = fill };
                count += 1;
            } else |err| switch (err) {
                error.PacketTooLarge => try testing.expect(len > 64),
                error.QueueFull => try testing.expect(count == 4),
            }
        } else {
            var o: [64]u8 = undefined;
            const outlen = s.valueRangeAtMost(u8, 0, 64);
            if (ring.pop(o[0..outlen])) |maybe| {
                if (maybe) |p| {
                    try testing.expect(count != 0);
                    const m = model[head];
                    try testing.expectEqual(m.len, p.len);
                    for (p) |byte| try testing.expectEqual(m.fill, byte);
                    head = (head + 1) % 4;
                    count -= 1;
                } else try testing.expect(count == 0);
            } else |_| {
                try testing.expect(count != 0 and model[head].len > outlen);
                head = (head + 1) % 4;
                count -= 1;
            }
        }
        try testing.expectEqual(count == 0, ring.isEmpty());
    }
}

const min_ipv4_header: [20]u8 = blk: {
    var b: [20]u8 = @splat(0);
    b[0] = 0x45;
    b[3] = 20;
    break :blk b;
};
const min_ipv6_header: [40]u8 = blk: {
    var b: [40]u8 = @splat(0);
    b[0] = 0x60;
    break :blk b;
};

test "fuzz: TUN packet paths (packetflow, packet ring, IP header parse)" {
    try testing.fuzz({}, fuzzTunPackets, .{ .corpus = &.{
        sliceInput(&min_ipv4_header),
        sliceInput(&min_ipv6_header),
    } });
}

// -------------------------------------------------------- device dispatch

const DispatchCtx = struct {
    device_priv: crypto.PrivateKey,
    remote_priv: crypto.PrivateKey,
};

const remote_v4 = [4]u8{ 10, 9, 0, 2 };
const remote_v6 = [16]u8{ 0xfd, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

fn drawV4(s: *Smith) [4]u8 {
    var b: [4]u8 = undefined;
    s.bytesWeighted(&b, interesting_bytes);
    return b;
}

/// An inner packet for the remote to send: raw bytes, or an IPv4/IPv6
/// header with fuzzed fields (source inside or outside the allowed IPs, any
/// claimed length) and a payload.
fn drawInner(s: *Smith, buf: []u8) []u8 {
    switch (s.valueRangeAtMost(u8, 0, 2)) {
        0 => return buf[0..s.slice(buf[0..200])],
        1 => {
            const payload = s.valueRangeAtMost(u16, 0, 200);
            const total = 20 + @as(usize, payload);
            @memset(buf[0..total], 0);
            buf[0] = 0x45;
            const claimed: u16 = if (s.boolWeighted(3, 1)) s.value(u16) else @intCast(total);
            std.mem.writeInt(u16, buf[2..4], claimed, .big);
            buf[9] = 17;
            buf[12..16].* = if (s.boolWeighted(3, 1)) drawV4(s) else remote_v4;
            buf[16..20].* = drawV4(s);
            return buf[0..total];
        },
        else => {
            const payload = s.valueRangeAtMost(u16, 0, 200);
            const total = 40 + @as(usize, payload);
            @memset(buf[0..total], 0);
            buf[0] = 0x60;
            const claimed: u16 = if (s.boolWeighted(3, 1)) s.value(u16) else payload;
            std.mem.writeInt(u16, buf[4..6], claimed, .big);
            buf[6] = 17;
            if (s.boolWeighted(3, 1)) s.bytes(buf[8..24]) else buf[8..24].* = remote_v6;
            s.bytes(buf[24..40]);
            return buf[0..total];
        },
    }
}

/// A real Device (FakeTun, real UDP sockets on loopback) and a remote peer
/// that speaks the protocol correctly (noise.Handshake + transport.seal), so
/// tests can drive the device with valid traffic and then break it.
const Harness = struct {
    fake: tun.FakeTun,
    d: *dev.Device,
    clock: dev.device.Clock,
    sock: dev.os.Udp,
    from: net.IpAddress,
    remote: noise.Local,
    hs: noise.Handshake,
    keys: ?noise.Seed = null,
    counter: u64 = 0,

    const allowed = [_]ip.Cidr{
        .{ .addr = .{ .v4 = remote_v4 }, .prefix = 32 },
        .{ .addr = .{ .v6 = remote_v6 }, .prefix = 128 },
    };
    const wall0: i96 = 1_700_000_000 * std.time.ns_per_s;

    /// `h` must stay at its address (the device points at h.clock).
    fn init(h: *Harness, ctx: DispatchCtx) !void {
        const gpa = testing.allocator;
        h.clock = .{ .io = testing.io };
        h.fake = try tun.FakeTun.init(gpa, .{ .capacity = 64 });
        errdefer h.fake.deinit();
        h.remote = noise.Local.init(ctx.remote_priv);
        h.d = try dev.Device.create(gpa, &h.clock, h.fake.tun(), .{
            .private_key = ctx.device_priv,
            .peers = &.{.{ .public_key = h.remote.public, .allowed_ips = &allowed }},
        });
        errdefer h.d.destroy();
        // The remote's socket: the device answers here.
        h.sock = try dev.os.Udp.open(.v4, 0);
        h.from = .{ .ip4 = .loopback(h.sock.localPort()) };
        h.hs = noise.Handshake.init(&h.remote, h.d.local.public, @splat(0));
        h.keys = null;
        h.counter = 0;
    }

    fn deinit(h: *Harness) void {
        if (h.keys) |*k| crypto.wipe(k);
        h.hs.wipe();
        h.sock.close();
        h.d.destroy();
        h.fake.deinit();
    }

    fn initiation(h: *Harness, now: i64, sender: u32, rng: std.Random) ?noise.Initiation {
        return h.hs.createInitiation(&h.remote, wall0 + now, now, sender, rng) catch null;
    }

    /// Read the device's answers; a valid response completes the remote's
    /// side of the handshake.
    fn collect(h: *Harness) void {
        var rx: [2048]u8 = undefined;
        while (h.sock.recv(&rx) catch null) |dg| {
            const r = noise.Response.parse(rx[0..dg.len]) catch continue;
            h.hs.consumeResponse(&h.remote, r) catch continue;
            if (h.keys) |*k| crypto.wipe(k);
            h.keys = h.hs.deriveKeys() catch null;
            h.counter = 0;
        }
    }

    /// Handshake initiated by the remote; true when keys were derived.
    fn handshake(h: *Harness, now: i64, rng: std.Random) bool {
        const m = h.initiation(now, 7, rng) orelse return false;
        var msg = m.asBytes().*;
        h.d.handleDatagram(&msg, h.from, now);
        h.collect();
        return h.keys != null;
    }

    fn seal(h: *Harness, inner: []const u8, counter: u64, mtu: u16, out: []u8) ?usize {
        const k = h.keys orelse return null;
        return session.transport.seal(&k.send, k.remote_index, counter, inner, mtu, out) catch null;
    }

    /// Cryptokey-routing invariants on everything handed to the TUN;
    /// returns how many packets were delivered.
    fn checkTun(h: *Harness) !usize {
        var out: [2048]u8 = undefined;
        var n: usize = 0;
        while (try h.fake.take(&out)) |p| : (n += 1) {
            const a = ip.packetAddrs(p) orelse return error.MalformedPacketToTun;
            try testing.expectEqual(a.total_len, p.len);
            const min: usize = if (a.src == .v4) 20 else 40;
            if (p.len < min) return error.TruncatedPacketToTun;
            const ok = for (allowed) |c| {
                if (c.contains(a.src)) break true;
            } else false;
            if (!ok) return error.SourceNotAllowed;
        }
        return n;
    }
};

/// The device fed a fuzzed sequence of datagrams from the remote: valid (or
/// mutated) initiations, transport packets sealed with the real session keys
/// (or mutated), cookie replies, stray responses and junk. Invariant:
/// whatever reaches the TUN is a well-formed IP packet of exactly its
/// header's length whose source the peer is allowed to use.
fn fuzzDispatch(ctx: DispatchCtx, s: *Smith) anyerror!void {
    var h: Harness = undefined;
    try h.init(ctx);
    defer h.deinit();
    var prng = std.Random.DefaultPrng.init(s.value(u64));
    const rng = prng.random();
    var now: i64 = 10 * std.time.ns_per_s;
    var msg: [2048]u8 = undefined;
    var inner: [300]u8 = undefined;
    var ops: usize = 0;
    while (ops < 24 and !s.eos()) : (ops += 1) {
        now += @as(i64, s.valueWeighted(u32, &.{
            .rangeAtMost(u32, 0, std.math.maxInt(u32), 1),
            .rangeAtMost(u32, 0, 100_000_000, 100),
        }));
        var len: usize = 0;
        switch (s.valueRangeAtMost(u8, 0, 4)) {
            0 => { // initiation from the remote
                const m = h.initiation(now, s.value(u32), rng) orelse continue;
                @memcpy(msg[0..noise.Initiation.size], m.asBytes());
                len = mutate(s, &msg, noise.Initiation.size);
            },
            1 => { // transport sealed with the real keys
                const p = drawInner(s, &inner);
                const ctr = if (s.boolWeighted(7, 1)) h.counter else s.value(u64);
                h.counter +%= 1;
                len = h.seal(p, ctr, s.valueRangeAtMost(u16, 0, 1500), &msg) orelse continue;
                len = mutate(s, &msg, len);
            },
            2 => { // cookie reply aimed at a live index
                var m: [noise.CookieReply.size]u8 = undefined;
                s.bytes(&m);
                m[0] = 3;
                @memset(m[1..4], 0);
                if (h.keys) |k| std.mem.writeInt(u32, m[4..8], k.remote_index, .little);
                @memcpy(msg[0..m.len], &m);
                len = mutate(s, &msg, m.len);
            },
            3 => { // junk with a chosen type byte
                len = s.slice(msg[0..200]);
                if (len != 0) msg[0] = s.valueRangeAtMost(u8, 0, 5);
                if (len >= 4 and s.boolWeighted(1, 3)) @memset(msg[1..4], 0);
            },
            else => { // a response to a handshake the device never started
                var m: [noise.Response.size]u8 = undefined;
                s.bytes(&m);
                m[0] = 2;
                @memset(m[1..4], 0);
                @memcpy(msg[0..m.len], &m);
                len = mutate(s, &msg, m.len);
            },
        }
        h.d.handleDatagram(msg[0..len], h.from, now);
        h.collect();
        _ = try h.checkTun();
    }
}

const dispatch_ctx: DispatchCtx = blk: {
    var dk: crypto.PrivateKey = @splat(0x11);
    var rk: crypto.PrivateKey = @splat(0x22);
    dk[0] &= 248;
    dk[31] = (dk[31] & 127) | 64;
    rk[0] &= 248;
    rk[31] = (rk[31] & 127) | 64;
    break :blk .{ .device_priv = dk, .remote_priv = rk };
};

test "fuzz: device datagram dispatch (handshake, transport, cookie, junk)" {
    try testing.fuzz(dispatch_ctx, fuzzDispatch, .{});
}

test "device drops inner packets whose IP length does not cover the header" {
    var h: Harness = undefined;
    try h.init(dispatch_ctx);
    defer h.deinit();
    var prng = std.Random.DefaultPrng.init(1);
    const now: i64 = 10 * std.time.ns_per_s;
    try testing.expect(h.handshake(now, prng.random()));
    var msg: [512]u8 = undefined;
    var inner: [64]u8 = @splat(0);
    inner[0] = 0x45;
    inner[9] = 17;
    inner[12..16].* = remote_v4;
    inner[16..20].* = .{ 10, 9, 0, 1 };
    // A sane packet first: delivered (and confirms the session).
    std.mem.writeInt(u16, inner[2..4], 28, .big);
    var n = h.seal(inner[0..28], 0, 1420, &msg).?;
    h.d.handleDatagram(msg[0..n], h.from, now);
    try testing.expectEqual(@as(usize, 1), try h.checkTun());
    // IPv4 total length 0..19: dropped, never a truncated packet on the TUN.
    for (0..20) |claimed| {
        std.mem.writeInt(u16, inner[2..4], @intCast(claimed), .big);
        n = h.seal(inner[0..28], 1 + claimed, 1420, &msg).?;
        h.d.handleDatagram(msg[0..n], h.from, now);
        try testing.expectEqual(@as(usize, 0), try h.checkTun());
    }
    try testing.expectEqual(@as(u64, 20), h.d.stats.dropped_invalid);
}
