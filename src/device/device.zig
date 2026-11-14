//! The WireGuard device: peers, cryptokey routing, UDP, TUN and the single
//! event loop that ties noise (handshakes) and session (transport data,
//! timers) together.
//!
//! One thread runs `run`. Each turn it waits once on
//!   {wake/stop events, UDP IPv4 socket, UDP IPv6 socket, TUN, deadline timer}
//! with the earliest peer timer deadline as the timeout (no deadline = wait
//! forever), then drains every source and fires due timers. Nothing ticks.
//! Time is the suspend-counting clock (`monotonic_clock`), and the deadline
//! timer (`os.DeadlineTimer`) fires on that clock too, so a resume from
//! sleep wakes the loop for every timer that fell due while asleep.
//!
//! Outbound: TUN -> route by destination (allowed IPs) -> peer -> encrypt
//!   (no key: stage the packet, bounded, and start a handshake) -> UDP.
//! Inbound: UDP -> type -> MAC1/cookie/load checks -> noise (1, 2),
//!   cookie reply (3) or decrypt (4) -> source address must be in the
//!   peer's allowed IPs -> TUN. Every authenticated packet updates the
//!   peer's endpoint (roaming).
//! Endpoint names: a peer configured with a DNS name is looked up again
//!   while its handshakes go unanswered, or until a failed lookup succeeds
//!   (resolver.zig: off the loop thread, woken by its Waker, deadlines in
//!   the same timer wait).
//!
//! Peer table: `setPeers` replaces it while the loop runs (from any thread;
//!   it is applied on the loop thread, woken like `kick`). Kept peers keep
//!   their sessions; removed ones are wiped.
//!
//! Memory is fixed after setup and after each peer-table change: per-peer
//! staging rings, one receive and one send buffer, a bounded index table
//! and a fixed-size rate limiter. Network input never allocates.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;

const crypto = @import("../crypto.zig");
const noise = @import("../noise/root.zig");
const session = @import("../session/root.zig");
const tun_mod = @import("../tun/root.zig");

const ip = @import("ip.zig");
const os = @import("os.zig");
const AllowedIps = @import("allowed_ips.zig").AllowedIps;
const IndexTable = @import("index_table.zig").IndexTable;
const ratelimit = @import("ratelimit.zig");
const show = @import("show.zig");
const config = @import("config.zig");
pub const resolver = @import("resolver.zig");

const log = std.log.scoped(.zwg);

pub const PeerId = u32;

/// Packets held per peer while a handshake is in progress (kernel and
/// wireguard-go: 128; when full, new packets are dropped).
pub const max_staged = 128;
/// Upper bound on packets handled per source per loop turn, so one flooded
/// source cannot starve the others (the loop comes straight back).
const batch_limit = 256;
/// Largest datagram we accept (IPv4/IPv6 payload limit).
const max_datagram = 65535;

/// The clock every protocol timer runs on: one that keeps counting while
/// the machine is suspended. WireGuard's timers are about time actually
/// elapsed: a session older than REJECT_AFTER_TIME must not stay usable,
/// nor a handshake retry or keepalive wait on, just because the laptop
/// slept through it. std's `.boot` is QueryPerformanceCounter on Windows
/// (counts suspend), CLOCK_BOOTTIME on Linux and CLOCK_MONOTONIC_RAW
/// (mach_continuous_time) on macOS / iOS; `.awake` would be
/// CLOCK_MONOTONIC / CLOCK_UPTIME_RAW there, which stop while asleep. The
/// waits themselves are made suspend-aware by `os.DeadlineTimer`.
pub const monotonic_clock: std.Io.Clock = .boot;

/// Monotonic and wall-clock time. Tests shift `offset_ns` to simulate time
/// passing (then `kick` the device so it re-reads its deadlines).
pub const Clock = struct {
    io: std.Io,
    offset_ns: std.atomic.Value(i64) = .init(0),

    pub fn now(c: *const Clock) i64 {
        const t = std.Io.Timestamp.now(c.io, monotonic_clock).nanoseconds;
        return @as(i64, @intCast(t)) + c.offset_ns.load(.monotonic);
    }

    pub fn wall(c: *const Clock) i96 {
        return std.Io.Timestamp.now(c.io, .real).nanoseconds + c.offset_ns.load(.monotonic);
    }

    pub fn advance(c: *Clock, ns: i64) void {
        _ = c.offset_ns.fetchAdd(ns, .monotonic);
    }
};

pub const PeerConfig = struct {
    public_key: crypto.PublicKey,
    preshared_key: ?crypto.PresharedKey = null,
    endpoint: ?net.IpAddress = null,
    /// The configured endpoint when it is a DNS name (`endpoint` is what it
    /// resolved to at start, or null if that failed): looked up again while
    /// the peer does not answer (resolver.zig). null for an IP literal.
    endpoint_name: ?config.Endpoint = null,
    allowed_ips: []const ip.Cidr = &.{},
    persistent_keepalive: u16 = 0,

    pub const FromConfig = struct {
        peer: PeerConfig,
        /// Why the endpoint name did not resolve now (`peer.endpoint` is
        /// then null; the device keeps looking it up).
        unresolved: ?anyerror = null,
    };

    /// The device's view of a parsed `[Peer]` (slices shared with `p`).
    /// An endpoint name is looked up now (blocking); `zwg up` and the
    /// tunnel service both start from here.
    pub fn fromConfig(io: std.Io, p: *const config.Peer) FromConfig {
        var r: FromConfig = .{ .peer = .{
            .public_key = p.public_key,
            .preshared_key = p.preshared_key,
            .allowed_ips = p.allowed_ips,
            .persistent_keepalive = p.persistent_keepalive,
        } };
        const e = p.endpoint orelse return r;
        if (e.literal()) |a| {
            r.peer.endpoint = a;
            return r;
        }
        r.peer.endpoint_name = e;
        r.peer.endpoint = resolver.systemLookup(null, io, e.host, e.port) catch |err| {
            r.unresolved = err;
            return r;
        };
        return r;
    }
};

pub const Options = struct {
    private_key: crypto.PrivateKey,
    /// null or 0 = any free port.
    listen_port: ?u16 = null,
    /// Listen on loopback only (the `--tun udp:<port>` test mode; unit
    /// tests do anyway): never reachable from, nor visible to, the network.
    loopback_only: bool = false,
    peers: []const PeerConfig = &.{},
    /// How endpoint names are looked up (tests substitute a fake).
    lookup: resolver.Lookup = .system,
};

pub const Peer = struct {
    id: PeerId,
    public_key: crypto.PublicKey,
    hs: noise.Handshake,
    sess: session.Peer,
    endpoint: ?net.IpAddress,
    persistent_keepalive: u16,
    /// Local index of the handshake we initiated and await a response for.
    handshake_index: ?u32 = null,
    staged: tun_mod.queue.PacketRing,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    last_handshake_wall_ns: ?i96 = null,
    /// When the last authenticated packet from this peer arrived (device clock).
    last_authenticated: ?i64 = null,
    /// Set when the endpoint is a DNS name: its slot in `Device.resolver`
    /// and when to look it up again.
    resolve: ?Resolve = null,

    pub const Resolve = struct {
        slot: u32,
        schedule: resolver.Schedule = .{},
    };
};

pub const Stats = struct {
    dropped_no_route: u64 = 0,
    dropped_no_endpoint: u64 = 0,
    dropped_staging_full: u64 = 0,
    dropped_invalid: u64 = 0,
    dropped_source_check: u64 = 0,
    dropped_ratelimited: u64 = 0,
    cookie_replies_sent: u64 = 0,
    tun_write_drops: u64 = 0,
    udp_send_errors: u64 = 0,
    endpoint_lookups: u64 = 0,
    endpoint_lookup_failures: u64 = 0,
    endpoint_updates: u64 = 0,
};

pub const Device = struct {
    gpa: std.mem.Allocator,
    clock: *Clock,
    csprng: std.Random.DefaultCsprng,
    rng: std.Random,

    local: noise.Local,
    checker: noise.CookieChecker,
    load: ratelimit.LoadMeter = .{},
    limiter: *ratelimit.Ratelimiter,

    peers: std.ArrayList(*Peer) = .empty,
    by_key: std.AutoHashMapUnmanaged(crypto.PublicKey, PeerId) = .empty,
    routes: AllowedIps(PeerId),
    indices: IndexTable(PeerId),

    tun: tun_mod.Tun,
    mtu: u16,
    udp4: ?os.Udp = null,
    udp6: ?os.Udp = null,
    listen_port: u16 = 0,
    scope: os.Scope = .default,

    waker: tun_mod.queue.Waker,
    /// Wakes the loop at the earliest timer deadline even across a
    /// suspend (the wait timeout alone would not count the time asleep).
    deadline_timer: os.DeadlineTimer,
    /// The deadline `deadline_timer` is armed for (null: disarmed).
    armed_deadline: ?i64 = null,
    stop_requested: std.atomic.Value(bool) = .init(false),
    /// Extra handle that stops the loop when ready (`zwg down`).
    external_stop: ?os.WaitHandle = null,
    /// Extra wait source serviced on the loop thread (the tunnel service's
    /// control pipe asks for status snapshots through it).
    control: ?Control = null,
    /// Lookups of endpoint names (null: no peer has one).
    resolver: ?*resolver.Shared = null,
    /// How endpoint names are looked up (`setPeers` makes new slots).
    lookup: resolver.Lookup = .system,
    /// `setPeers` hands its table to the loop thread through this.
    peer_update: PeerUpdate = .{},

    stats: Stats = .{},
    rx_buf: []u8,
    tx_buf: []u8,
    pkt_buf: []u8,
    /// Staged packets are popped into this (never aliases the others).
    flush_buf: []u8,

    /// `ready` runs on the loop thread whenever `handle` is signalled (it
    /// must reset the handle unless it is auto-reset), so it may read the
    /// device's state without locking. It must not block.
    pub const Control = struct {
        handle: os.WaitHandle,
        ctx: *anyopaque,
        ready: *const fn (ctx: *anyopaque, d: *Device) void,
    };

    /// The hand-over between `setPeers` (any thread) and the loop thread:
    /// one request at a time, served on the loop's next turn.
    const PeerUpdate = struct {
        mutex: std.Io.Mutex = .init,
        cond: std.Io.Condition = .init,
        /// `run` is running, on `loop_thread` (guarded by `mutex`).
        running: bool = false,
        loop_thread: std.Thread.Id = 0,
        /// The request the loop has yet to serve (guarded by `mutex`).
        pending: ?*Request = null,
        /// `pending != null`, readable without the lock (the loop checks
        /// it every turn).
        flag: std.atomic.Value(bool) = .init(false),

        const Request = struct {
            peers: []const PeerConfig,
            result: InitError!void = {},
            done: bool = false,
        };
    };

    pub const InitError = error{
        OutOfMemory,
        SystemResources,
        /// Two peers with the same public key.
        DuplicatePeer,
        /// A peer with our own public key, or an invalid allowed-IPs prefix.
        InvalidPeer,
        /// An endpoint name that is empty or longer than `resolver.max_host`.
        InvalidHost,
        /// More than `config.max_peers` peers.
        TooManyPeers,
        /// A peer with more than `config.max_list_entries` allowed IPs.
        TooManyAllowedIps,
        /// The same prefix in the allowed IPs of two peers.
        OverlappingAllowedIps,
    } || os.OpenError;

    /// Creates the device, binds its UDP sockets and adds the peers. The
    /// Device must stay at its address (it is heap-allocated).
    pub fn create(gpa: std.mem.Allocator, clock: *Clock, tun: tun_mod.Tun, options: Options) InitError!*Device {
        const d = try gpa.create(Device);
        errdefer gpa.destroy(d);
        try d.init(gpa, clock, tun, options);
        // From here on, teardown frees what init made (each thing once).
        errdefer d.teardown();

        try d.bind(options.listen_port orelse 0);
        try d.applyPeers(options.peers, null);
        return d;
    }

    /// All or nothing: on error, nothing is left to free.
    fn init(d: *Device, gpa: std.mem.Allocator, clock: *Clock, tun: tun_mod.Tun, options: Options) InitError!void {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        clock.io.random(&seed);
        const limiter = try gpa.create(ratelimit.Ratelimiter);
        errdefer gpa.destroy(limiter);
        const rx_buf = try gpa.alloc(u8, max_datagram);
        errdefer gpa.free(rx_buf);
        const tx_buf = try gpa.alloc(u8, max_datagram + 64);
        errdefer gpa.free(tx_buf);
        const pkt_buf = try gpa.alloc(u8, max_datagram);
        errdefer gpa.free(pkt_buf);
        const flush_buf = try gpa.alloc(u8, max_datagram);
        errdefer gpa.free(flush_buf);
        var waker = tun_mod.queue.Waker.init() catch return error.SystemResources;
        errdefer waker.deinit();
        var deadline_timer = os.DeadlineTimer.init() catch return error.SystemResources;
        errdefer deadline_timer.deinit();

        d.* = .{
            .gpa = gpa,
            .clock = clock,
            .csprng = .init(seed),
            .rng = undefined,
            .local = noise.Local.init(options.private_key),
            .checker = undefined,
            .limiter = limiter,
            .routes = .init(gpa),
            .indices = .init(16),
            .tun = tun,
            .mtu = tun.mtu(),
            .waker = waker,
            .scope = if (options.loopback_only) .loopback else .default,
            .deadline_timer = deadline_timer,
            .rx_buf = rx_buf,
            .tx_buf = tx_buf,
            .pkt_buf = pkt_buf,
            .flush_buf = flush_buf,
            .lookup = options.lookup,
        };
        std.crypto.secureZero(u8, &seed);
        d.rng = d.csprng.random();
        d.checker = noise.CookieChecker.init(&d.local.public);
        limiter.* = .init(d.rng);
    }

    pub fn destroy(d: *Device) void {
        const gpa = d.gpa;
        d.teardown();
        gpa.destroy(d);
    }

    fn teardown(d: *Device) void {
        // A lookup still in flight finishes on its own and frees the rest.
        if (d.resolver) |r| r.release();
        d.resolver = null;
        for (d.peers.items) |p| d.destroyPeer(p);
        d.peers.deinit(d.gpa);
        d.by_key.deinit(d.gpa);
        d.routes.deinit();
        d.indices.deinit(d.gpa);
        if (d.udp4) |*u| u.close();
        if (d.udp6) |*u| u.close();
        d.waker.deinit();
        d.deadline_timer.deinit();
        d.local.wipe();
        d.checker.wipe();
        std.crypto.secureZero(u8, std.mem.asBytes(&d.csprng));
        d.gpa.destroy(d.limiter);
        // Plaintext packets and ciphertext in flight: zeroed, not just freed.
        for ([_][]u8{ d.rx_buf, d.tx_buf, d.pkt_buf, d.flush_buf }) |b| {
            std.crypto.secureZero(u8, b);
            d.gpa.free(b);
        }
    }

    fn bind(d: *Device, port: u16) InitError!void {
        // An ephemeral IPv4 port may be taken on IPv6 by an unrelated
        // socket: then pick another pair rather than fail.
        var attempts: u8 = if (port == 0) 8 else 1;
        while (true) {
            d.udp4 = try os.Udp.openScoped(.v4, port, d.scope);
            d.listen_port = d.udp4.?.localPort();
            // Same port for IPv6. Only a host without IPv6 runs IPv4-only:
            // any other failure (above all a port someone else already
            // holds on IPv6, which would let a local process receive the
            // tunnel's IPv6 traffic) fails like IPv4 does.
            d.udp6 = os.Udp.openScoped(.v6, d.listen_port, d.scope) catch |err| switch (err) {
                error.AddressFamilyUnsupported => blk: {
                    log.info("IPv6 UDP socket unavailable ({s}); IPv4 only", .{@errorName(err)});
                    break :blk null;
                },
                else => {
                    d.udp4.?.close();
                    d.udp4 = null;
                    attempts -= 1;
                    if (err == error.AddressInUse and attempts > 0) continue;
                    return err;
                },
            };
            return;
        }
    }

    /// Closes the UDP sockets and binds new ones (network change; tests use
    /// it to simulate roaming). Call only while `run` is not running.
    pub fn rebind(d: *Device, port: u16) InitError!void {
        if (d.udp4) |*u| u.close();
        if (d.udp6) |*u| u.close();
        d.udp4 = null;
        d.udp6 = null;
        try d.bind(port);
    }

    // ---- the peer table -----------------------------------------------------

    /// Replaces the peer table with `cfgs`, in that order (a peer's id is
    /// its position). The startup path and `setPeers` both come here, on
    /// the loop thread or while `run` is not running. Everything that can
    /// fail (the checks and every allocation) comes before the first
    /// change, so an error leaves the device exactly as it was. `now` is
    /// null while the loop is not running (`run` starts the peers).
    fn applyPeers(d: *Device, cfgs: []const PeerConfig, now: ?i64) InitError!void {
        try d.checkPeers(cfgs);
        const gpa = d.gpa;
        const n: u32 = @intCast(cfgs.len);

        // The new key map and routing table, built aside; building them
        // finds duplicate keys and prefixes claimed by two peers. After
        // the swaps below, these deferred frees free the old ones.
        var by_key: std.AutoHashMapUnmanaged(crypto.PublicKey, PeerId) = .empty;
        defer by_key.deinit(gpa);
        try by_key.ensureTotalCapacity(gpa, n);
        var routes: AllowedIps(PeerId) = .init(gpa);
        defer routes.deinit();
        // Per new position: the current peer with that key, or a new one.
        const kept = try gpa.alloc(?*Peer, n);
        defer gpa.free(kept);
        const fresh = try gpa.alloc(?*Peer, n);
        defer gpa.free(fresh);
        @memset(fresh, null);
        errdefer for (fresh) |f| if (f) |p| d.destroyPeer(p);
        for (cfgs, kept, 0..) |*pc, *k, i| {
            const id: PeerId = @intCast(i);
            const gop = by_key.getOrPutAssumeCapacity(pc.public_key);
            if (gop.found_existing) return error.DuplicatePeer;
            gop.value_ptr.* = id;
            for (pc.allowed_ips) |c| {
                if (routes.exact(c)) |owner| if (owner != id) return error.OverlappingAllowedIps;
                try routes.insert(c, id);
            }
            k.* = d.peerByKey(pc.public_key);
        }
        for (cfgs, kept, fresh) |*pc, k, *f| if (k == null) {
            f.* = try d.newPeer(pc);
        };
        const names = try d.prepareResolver(cfgs, kept);
        errdefer if (names.shared) |s| if (s != d.resolver) s.release();
        // Old id -> new id (null: removed).
        const moved = try gpa.alloc(?PeerId, d.peers.items.len);
        defer gpa.free(moved);
        try d.peers.ensureTotalCapacity(gpa, n);

        // ---- nothing below fails ----
        @memset(moved, null);
        for (kept, 0..) |k, i| if (k) |p| {
            moved[p.id] = @intCast(i);
        };
        for (d.peers.items, moved) |p, m| if (m == null) d.destroyPeer(p);
        d.indices.remap(moved);
        d.peers.clearRetainingCapacity();
        for (cfgs, kept, fresh, 0..) |*pc, k, f, i| {
            const p = k orelse f.?;
            p.id = @intCast(i);
            d.peers.appendAssumeCapacity(p);
            if (k != null) d.updatePeer(p, pc, now);
        }
        std.mem.swap(@TypeOf(by_key), &d.by_key, &by_key);
        std.mem.swap(AllowedIps(PeerId), &d.routes, &routes);
        d.installResolver(names, cfgs, kept);
        // One in-flight handshake plus three keypairs per peer.
        d.indices.limit = 4 * @as(usize, n) + 16;
        if (now) |t| for (fresh) |f| if (f) |p| d.startPeer(p, t);
    }

    /// The checks that need no memory: limits and keys.
    fn checkPeers(d: *const Device, cfgs: []const PeerConfig) InitError!void {
        if (cfgs.len > config.max_peers) return error.TooManyPeers;
        for (cfgs) |*pc| {
            if (crypto.eql(32, &pc.public_key, &d.local.public)) return error.InvalidPeer;
            if (pc.allowed_ips.len > config.max_list_entries) return error.TooManyAllowedIps;
            for (pc.allowed_ips) |c| if (c.prefix > c.addr.bits()) return error.InvalidPeer;
            if (pc.endpoint_name) |nm| if (nm.host.len == 0 or nm.host.len > resolver.max_host) return error.InvalidHost;
        }
    }

    /// A peer as configured, with fresh handshake and session state. Its
    /// id is set, and it is registered, by `applyPeers`.
    fn newPeer(d: *Device, pc: *const PeerConfig) InitError!*Peer {
        const p = try d.gpa.create(Peer);
        errdefer d.gpa.destroy(p);
        const staged = try tun_mod.queue.PacketRing.init(d.gpa, max_staged, @max(d.mtu, 1280));
        p.* = .{
            .id = 0,
            .public_key = pc.public_key,
            .hs = noise.Handshake.init(&d.local, pc.public_key, pc.preshared_key orelse @splat(0)),
            .sess = session.Peer.init(session.Jitter.fromRandom(&d.rng)),
            .endpoint = pc.endpoint,
            .persistent_keepalive = pc.persistent_keepalive,
            .staged = staged,
        };
        return p;
    }

    /// Wipes a peer's session keys, handshake state (preshared key
    /// included) and staged packets, gives its indices back and frees it.
    fn destroyPeer(d: *Device, p: *Peer) void {
        d.retire(p.sess.deinit());
        if (p.handshake_index) |i| d.indices.remove(i);
        p.hs.wipe();
        // Staged plaintext packets waiting for a handshake.
        std.crypto.secureZero(u8, p.staged.storage);
        p.staged.deinit(d.gpa);
        std.crypto.secureZero(u8, std.mem.asBytes(p));
        d.gpa.destroy(p);
    }

    /// A kept peer takes its new settings. Its sessions, timers, counters
    /// and endpoint stay, unless the new config names an endpoint (then
    /// that one) or another preshared key (then its sessions go: none made
    /// with the old key may carry on).
    fn updatePeer(d: *Device, p: *Peer, pc: *const PeerConfig, now: ?i64) void {
        if (pc.endpoint) |e| p.endpoint = e;
        var psk: crypto.PresharedKey = pc.preshared_key orelse @splat(0);
        defer crypto.wipe(&psk);
        const new_psk = !crypto.eql(32, &psk, &p.hs.psk);
        if (new_psk) {
            p.hs.setPresharedKey(psk);
            p.hs.clear();
            if (p.handshake_index) |i| d.indices.remove(i);
            p.handshake_index = null;
            d.retire(p.sess.keypairs.clear());
        }
        const keepalive = pc.persistent_keepalive != p.persistent_keepalive;
        p.persistent_keepalive = pc.persistent_keepalive;
        const t = now orelse return; // `run` arms the timers when it starts
        if (keepalive) d.applyActions(p, p.sess.setPersistentKeepalive(p.persistent_keepalive), t);
        // Traffic waiting, or a keepalive wanted: a new session now.
        if (new_psk and (p.persistent_keepalive != 0 or !p.staged.isEmpty()))
            if (p.sess.wantHandshake(t)) d.sendInitiation(p, t);
    }

    /// The endpoint-name slots for a new peer table (`prepareResolver`).
    const Names = struct {
        /// null: no peer has a name. The current `Device.resolver` when
        /// every named peer keeps its slot and name; else new slots.
        shared: ?*resolver.Shared,
    };

    /// One lookup slot per peer whose endpoint is a DNS name, in table
    /// order. The current slots are kept if they still fit exactly.
    fn prepareResolver(d: *Device, cfgs: []const PeerConfig, kept: []const ?*Peer) InitError!Names {
        var count: u32 = 0;
        var fits = true;
        for (cfgs, kept) |*pc, k| if (pc.endpoint_name) |nm| {
            fits = fits and d.keepsSlot(k, count, nm);
            count += 1;
        };
        if (count == 0) return .{ .shared = null };
        if (fits and count == d.resolver.?.slots.len) return .{ .shared = d.resolver };
        const hosts = try d.gpa.alloc([]const u8, count);
        defer d.gpa.free(hosts);
        const ports = try d.gpa.alloc(u16, count);
        defer d.gpa.free(ports);
        var i: usize = 0;
        for (cfgs) |*pc| if (pc.endpoint_name) |nm| {
            hosts[i] = nm.host;
            ports[i] = nm.port;
            i += 1;
        };
        const s = resolver.Shared.create(d.clock.io, d.lookup, hosts, ports) catch |err| return switch (err) {
            error.InvalidHost => error.InvalidHost,
            error.SystemResources => error.SystemResources,
            error.OutOfMemory => error.OutOfMemory,
        };
        return .{ .shared = s };
    }

    /// Is `k` a current peer that looks `nm` up in slot `slot`?
    fn keepsSlot(d: *const Device, k: ?*Peer, slot: u32, nm: config.Endpoint) bool {
        const p = k orelse return false;
        const rv = p.resolve orelse return false;
        return rv.slot == slot and d.slotIs(rv.slot, nm);
    }

    /// Does current slot `slot` look up `nm`?
    fn slotIs(d: *const Device, slot: u32, nm: config.Endpoint) bool {
        const s = &(d.resolver orelse return false).slots[slot];
        return s.port == nm.port and std.mem.eql(u8, s.host, nm.host);
    }

    /// Commit half of `prepareResolver` (`d.peers` is the new table). A
    /// kept peer whose name did not change keeps its lookup schedule.
    fn installResolver(d: *Device, names: Names, cfgs: []const PeerConfig, kept: []const ?*Peer) void {
        const renewed = names.shared != d.resolver;
        var slot: u32 = 0;
        for (cfgs, kept, d.peers.items) |*pc, k, p| {
            const old = if (k != null) p.resolve else null;
            const nm = pc.endpoint_name orelse {
                p.resolve = null;
                continue;
            };
            var rv: Peer.Resolve = .{ .slot = slot };
            if (old) |o| if (d.slotIs(o.slot, nm)) {
                rv.schedule = o.schedule;
                if (renewed and rv.schedule.busy) {
                    // Its answer lands in the old slots: ask again now.
                    rv.schedule.busy = false;
                    rv.schedule.due_at = d.clock.now();
                }
            };
            p.resolve = rv;
            slot += 1;
        }
        // A lookup still in flight finishes on its own and frees the rest.
        if (renewed) if (d.resolver) |r| r.release();
        d.resolver = names.shared;
    }

    // ---- control from other threads -------------------------------------

    /// Replaces the peer table, while the tunnel runs or not (Portal pairs
    /// or forgets a device without restarting the tunnel). Thread-safe:
    /// while `run` is running, the change is handed to the loop thread
    /// (woken like `kick`) and applied between two turns; this returns once
    /// it is applied, or with the error that left everything unchanged.
    /// Calls from several threads are applied one at a time, in turn.
    /// Nothing in `peers` is used after this returns (the routing table
    /// and the endpoint-name slots keep their own copies).
    ///
    /// Peers are matched by public key:
    ///   * kept: sessions, timers, counters and the (roamed) endpoint stay;
    ///     allowed IPs, persistent keepalive and, if given, the endpoint
    ///     are updated. Another preshared key drops its sessions.
    ///   * removed: torn down; keys, session and handshake state wiped,
    ///     staged packets wiped and freed, its indices and routes gone.
    ///   * added: as at startup.
    /// The whole set is checked before anything changes: duplicate keys,
    /// our own key, the same prefix in two peers (nested prefixes are
    /// longest-prefix routing, as in the kernel), at most
    /// `config.max_peers` peers with `config.max_list_entries` allowed IPs
    /// each, and endpoint-name lengths.
    pub fn setPeers(d: *Device, peers: []const PeerConfig) InitError!void {
        const u = &d.peer_update;
        const io = d.clock.io;
        u.mutex.lockUncancelable(io);
        defer u.mutex.unlock(io);
        while (true) {
            // Not running: nothing else touches the device (`run` waits
            // for the lock before it starts).
            if (!u.running) return d.applyPeers(peers, null);
            // From the loop thread itself (a control hook): apply here.
            if (u.loop_thread == std.Thread.getCurrentId()) return d.applyPeers(peers, d.clock.now());
            if (u.pending == null) break;
            u.cond.waitUncancelable(io, &u.mutex);
        }
        var req: PeerUpdate.Request = .{ .peers = peers };
        u.pending = &req;
        u.flag.store(true, .release);
        d.waker.signal();
        while (!req.done) u.cond.waitUncancelable(io, &u.mutex);
        return req.result;
    }

    /// Loop thread: applies the `setPeers` request waiting, if any.
    fn servePeerUpdate(d: *Device, now: ?i64) void {
        const u = &d.peer_update;
        u.mutex.lockUncancelable(d.clock.io);
        defer u.mutex.unlock(d.clock.io);
        d.serveLocked(now);
    }

    fn serveLocked(d: *Device, now: ?i64) void {
        const u = &d.peer_update;
        const req = u.pending orelse return;
        req.result = d.applyPeers(req.peers, now);
        req.done = true;
        u.pending = null;
        u.flag.store(false, .release);
        u.cond.broadcast(d.clock.io);
    }

    fn enterLoop(d: *Device) void {
        const u = &d.peer_update;
        u.mutex.lockUncancelable(d.clock.io);
        defer u.mutex.unlock(d.clock.io);
        u.running = true;
        u.loop_thread = std.Thread.getCurrentId();
    }

    /// `run` returns: a request that came too late for the loop is
    /// applied here; later ones apply directly.
    fn leaveLoop(d: *Device) void {
        const u = &d.peer_update;
        u.mutex.lockUncancelable(d.clock.io);
        defer u.mutex.unlock(d.clock.io);
        d.serveLocked(null);
        u.running = false;
        u.cond.broadcast(d.clock.io);
    }

    /// Ask `run` to return (thread-safe).
    pub fn stop(d: *Device) void {
        d.stop_requested.store(true, .release);
        d.waker.signal();
    }

    /// Make `run` re-evaluate deadlines now (thread-safe; tests use it after
    /// advancing the clock).
    pub fn kick(d: *Device) void {
        d.waker.signal();
    }

    // ---- the loop ---------------------------------------------------------

    pub const RunError = error{ TunClosed, Unexpected };

    pub fn run(d: *Device) RunError!void {
        d.enterLoop();
        defer d.leaveLoop();
        var now = d.clock.now();
        for (d.peers.items) |p| d.startPeer(p, now);
        var more = false;
        while (true) {
            if (d.stop_requested.load(.acquire)) return;
            now = d.clock.now();
            const deadline = d.fireTimers(now);
            var handles: [8]os.WaitHandle = undefined;
            var n: usize = 0;
            handles[n] = d.waker.handle;
            n += 1;
            if (d.external_stop) |h| {
                handles[n] = h;
                n += 1;
            }
            const control_index = n;
            if (d.control) |c| {
                handles[n] = c.handle;
                n += 1;
            }
            const resolver_index = n;
            if (d.resolver) |rs| {
                handles[n] = rs.waker.handle;
                n += 1;
            }
            if (d.udp4) |*u| {
                handles[n] = u.waitHandle();
                n += 1;
            }
            if (d.udp6) |*u| {
                handles[n] = u.waitHandle();
                n += 1;
            }
            handles[n] = d.tun.waitHandle();
            n += 1;
            const timer_index = n;
            if (d.deadline_timer.waitHandle()) |h| {
                handles[n] = h;
                n += 1;
            }

            const timeout: ?u64 = if (more) 0 else if (deadline) |t| @intCast(@max(t - now, 0)) else null;
            if (!more) d.armDeadline(deadline, now);
            const ready = os.wait(handles[0..n], timeout) catch return error.Unexpected;
            if (ready) |r| {
                if (r == 0) d.waker.clear();
                if (r == timer_index and n > timer_index) {
                    d.deadline_timer.clear();
                    d.armed_deadline = null;
                }
                if (d.external_stop != null and r == 1) return;
                if (d.control) |c| if (r == control_index) c.ready(c.ctx, d);
                if (d.resolver) |rs| if (r == resolver_index) {
                    rs.waker.clear();
                    d.collectLookups(d.clock.now());
                };
            }
            if (d.peer_update.flag.load(.acquire)) d.servePeerUpdate(d.clock.now());
            more = false;
            now = d.clock.now();
            if (d.udp4 != null) more = d.drainUdp(&d.udp4.?, now) or more;
            if (d.udp6 != null) more = d.drainUdp(&d.udp6.?, now) or more;
            more = (try d.drainTun(now)) or more;
        }
    }

    /// Arms a peer's timers as the loop starts it (`run`, or `setPeers`
    /// adding it while the loop runs).
    fn startPeer(d: *Device, p: *Peer, now: i64) void {
        d.applyActions(p, p.sess.start(), now);
        d.applyActions(p, p.sess.setPersistentKeepalive(p.persistent_keepalive), now);
        // A name that could not be resolved yet: try again now (then on
        // the failure backoff).
        if (p.endpoint == null) if (p.resolve != null) d.requestLookup(p, now);
    }

    /// Arm the suspend-aware timer for `deadline` (device clock), or disarm
    /// it; nothing to do if it is already set for that deadline. The wait's
    /// relative timeout stays too: whichever is first wakes the loop, and
    /// the loop always recomputes from the clock.
    fn armDeadline(d: *Device, deadline: ?i64, now: i64) void {
        if (deadline == d.armed_deadline) return;
        if (deadline) |t| d.deadline_timer.arm(@intCast(@max(t - now, 0))) else d.deadline_timer.disarm();
        d.armed_deadline = deadline;
    }

    /// Fires due timers; returns the earliest remaining deadline.
    fn fireTimers(d: *Device, now: i64) ?i64 {
        var earliest: ?i64 = null;
        for (d.peers.items) |p| {
            if (p.resolve) |*rv| {
                if (rv.schedule.fire(now)) d.startLookup(p, now);
                if (rv.schedule.next()) |t| earliest = if (earliest) |e| @min(e, t) else t;
            }
            var guard: usize = 0;
            while (p.sess.next(now)) |t| {
                if (t > now or guard == 8) {
                    earliest = if (earliest) |e| @min(e, t) else t;
                    break;
                }
                guard += 1;
                const due = p.sess.due(now);
                d.retire(due.retired);
                d.applyActions(p, due.actions, now);
            }
        }
        return earliest;
    }

    fn applyActions(d: *Device, p: *Peer, a: session.Actions, now: i64) void {
        if (a.zero_keys) {
            p.hs.clear();
            if (p.handshake_index) |i| d.indices.remove(i);
            p.handshake_index = null;
        }
        if (a.handshake_gave_up) {
            while (p.staged.pop(d.flush_buf) catch null) |_| {}
        }
        if (a.initiate_handshake) d.sendInitiation(p, now);
        if (a.send_keepalive) d.sendData(p, &.{}, now);
        // The far end did not answer our last initiation: its name may now
        // point somewhere else (dynamic DNS).
        if (a.handshake_retry and p.resolve != null) d.requestLookup(p, now);
    }

    // ---- endpoint names ---------------------------------------------------

    fn requestLookup(d: *Device, p: *Peer, now: i64) void {
        const rv = &p.resolve.?;
        if (rv.schedule.request(now)) d.startLookup(p, now);
    }

    fn startLookup(d: *Device, p: *Peer, now: i64) void {
        const rv = &p.resolve.?;
        d.stats.endpoint_lookups += 1;
        if (!d.resolver.?.start(rv.slot)) {
            d.stats.endpoint_lookup_failures += 1;
            rv.schedule.finished(now, false);
        }
    }

    /// Answers of finished lookups (on the loop thread).
    fn collectLookups(d: *Device, now: i64) void {
        const rs = d.resolver orelse return;
        for (d.peers.items) |p| {
            const rv = if (p.resolve) |*r| r else continue;
            const r = rs.take(rv.slot);
            if (!r.done) continue;
            rv.schedule.finished(now, r.result != null);
            const addr = r.result orelse {
                d.stats.endpoint_lookup_failures += 1;
                log.info("peer {d}: endpoint name lookup failed; retrying", .{p.id});
                continue;
            };
            // Something authenticated arrived since the lookup started:
            // the endpoint it came from is the better one.
            if (p.last_authenticated) |t| if (rv.schedule.last_start) |s| if (t >= s) continue;
            const was = p.endpoint;
            if (was) |w| if (w.eql(&addr)) continue;
            p.endpoint = addr;
            d.stats.endpoint_updates += 1;
            log.info("peer {d}: endpoint name now resolves to {f}", .{ p.id, addr });
            // No endpoint until now: nothing was sent, so no timer is
            // armed; start the handshake if the peer wants traffic.
            if (was == null and (p.persistent_keepalive != 0 or !p.staged.isEmpty()))
                if (p.sess.wantHandshake(now)) d.sendInitiation(p, now);
        }
    }

    fn retire(d: *Device, r: session.Retired) void {
        for (r.slice()) |i| d.indices.remove(i);
    }

    // ---- outbound ---------------------------------------------------------

    fn drainTun(d: *Device, now: i64) RunError!bool {
        var count: usize = 0;
        while (count < batch_limit) : (count += 1) {
            const pkt = (d.tun.read(d.pkt_buf) catch |err| switch (err) {
                error.BufferTooSmall => continue,
                error.Closed => return error.TunClosed,
                error.Unexpected => return error.Unexpected,
            }) orelse return false;
            d.routePacket(pkt, now);
        }
        return true;
    }

    fn routePacket(d: *Device, pkt: []const u8, now: i64) void {
        const addrs = ip.packetAddrs(pkt) orelse {
            d.stats.dropped_invalid += 1;
            return;
        };
        const id = d.routes.lookup(addrs.dst) orelse {
            d.stats.dropped_no_route += 1;
            return;
        };
        const p = d.peers.items[id];
        if (p.endpoint == null) {
            d.stats.dropped_no_endpoint += 1;
            return;
        }
        if (!p.staged.isEmpty()) {
            // Keep order: queue behind what is already waiting.
            d.stage(p, pkt);
            d.flushStaged(p, now);
            return;
        }
        d.sendData(p, pkt, now);
    }

    fn stage(d: *Device, p: *Peer, pkt: []const u8) void {
        p.staged.push(pkt) catch {
            d.stats.dropped_staging_full += 1;
        };
    }

    /// Encrypts and sends one packet (empty = keepalive). Without a usable
    /// key: data is staged, and a handshake started if allowed.
    fn sendData(d: *Device, p: *Peer, pkt: []const u8, now: i64) void {
        const ep = p.endpoint orelse return;
        const r = p.sess.encrypt(now, pkt, d.mtu, d.tx_buf) catch |err| switch (err) {
            error.NoKey => {
                if (pkt.len != 0) d.stage(p, pkt);
                if (p.sess.wantHandshake(now)) d.sendInitiation(p, now);
                return;
            },
            error.BufferTooSmall => {
                d.stats.dropped_invalid += 1;
                return;
            },
        };
        d.sendUdp(ep, d.tx_buf[0..r.len]);
        p.tx_bytes += r.len;
        if (r.initiate_handshake) d.sendInitiation(p, now);
    }

    fn flushStaged(d: *Device, p: *Peer, now: i64) void {
        if (!p.sess.keypairs.canSend(now)) return;
        while (p.staged.pop(d.flush_buf) catch null) |pkt| {
            const r = p.sess.encrypt(now, pkt, d.mtu, d.tx_buf) catch {
                // Lost the key mid-flush: put it back and stop.
                d.stage(p, pkt);
                if (p.sess.wantHandshake(now)) d.sendInitiation(p, now);
                return;
            };
            if (p.endpoint) |ep| d.sendUdp(ep, d.tx_buf[0..r.len]);
            p.tx_bytes += r.len;
            if (r.initiate_handshake) d.sendInitiation(p, now);
        }
    }

    fn sendInitiation(d: *Device, p: *Peer, now: i64) void {
        const ep = p.endpoint orelse return;
        if (p.handshake_index) |old| d.indices.remove(old);
        p.handshake_index = null;
        const idx = d.indices.insert(d.gpa, d.rng, .{ .peer = p.id, .kind = .handshake }) catch return;
        const msg = p.hs.createInitiation(&d.local, d.clock.wall(), now, idx, d.rng) catch {
            d.indices.remove(idx);
            return;
        };
        p.handshake_index = idx;
        d.sendUdp(ep, msg.asBytes());
        p.tx_bytes += noise.Initiation.size;
        p.sess.initiationSent(now);
    }

    fn sendUdp(d: *Device, to: net.IpAddress, data: []const u8) void {
        const sock: ?*os.Udp = switch (to) {
            .ip4 => if (d.udp4) |*u| u else null,
            .ip6 => if (d.udp6) |*u| u else null,
        };
        const s = sock orelse {
            d.stats.udp_send_errors += 1;
            return;
        };
        s.send(to, data) catch {
            d.stats.udp_send_errors += 1;
        };
    }

    // ---- inbound ----------------------------------------------------------

    fn drainUdp(d: *Device, u: *os.Udp, now: i64) bool {
        u.beginDrain();
        var count: usize = 0;
        while (count < batch_limit) : (count += 1) {
            const dg = (u.recv(d.rx_buf) catch return false) orelse return false;
            d.handleDatagram(d.rx_buf[0..dg.len], dg.from, now);
        }
        return true;
    }

    /// Source of a handshake for MAC2 cookies: address bytes || BE16 port
    /// (the kernel's encoding).
    fn cookieSource(from: net.IpAddress, buf: *[18]u8) []const u8 {
        switch (from) {
            .ip4 => |a| {
                buf[0..4].* = a.bytes;
                std.mem.writeInt(u16, buf[4..6], a.port, .big);
                return buf[0..6];
            },
            .ip6 => |a| {
                buf[0..16].* = a.bytes;
                std.mem.writeInt(u16, buf[16..18], a.port, .big);
                return buf[0..18];
            },
        }
    }

    pub fn handleDatagram(d: *Device, msg: []u8, from: net.IpAddress, now: i64) void {
        const kind = noise.messageType(msg) orelse {
            d.stats.dropped_invalid += 1;
            return;
        };
        switch (kind) {
            .initiation, .response => {
                // mac1 first: only messages from senders that know our
                // public key count towards load, so random datagrams cannot
                // force cookie round trips on legitimate peers.
                if (!d.checker.checkMac1(msg)) {
                    d.stats.dropped_invalid += 1;
                    return;
                }
                const under_load = d.load.record(now);
                var sbuf: [18]u8 = undefined;
                const src = cookieSource(from, &sbuf);
                const verdict: noise.Verdict = if (under_load) d.checker.checkMac2(msg, src, now, d.rng) else .ok;
                switch (verdict) {
                    .invalid => unreachable,
                    .need_cookie => {
                        const reply = d.checker.createReply(msg, src, now, d.rng);
                        d.sendUdp(from, reply.asBytes());
                        d.stats.cookie_replies_sent += 1;
                        return;
                    },
                    .ok => {},
                }
                if (under_load and !d.limiter.allow(ip.Addr.fromIpAddress(from), now)) {
                    d.stats.dropped_ratelimited += 1;
                    return;
                }
                if (kind == .initiation) d.handleInitiation(msg, from, now) else d.handleResponse(msg, from, now);
            },
            .cookie_reply => {
                const reply = noise.CookieReply.parse(msg) catch return;
                const e = d.indices.get(reply.receiverIndex()) orelse return;
                d.peers.items[e.peer].hs.cookie.consumeReply(reply, now) catch {};
            },
            .transport => d.handleTransport(msg, from, now),
        }
    }

    fn handleInitiation(d: *Device, msg: []const u8, from: net.IpAddress, now: i64) void {
        const m = noise.Initiation.parse(msg) catch return;
        var start = noise.consumeInitiationStatic(&d.local, m) catch {
            d.stats.dropped_invalid += 1;
            return;
        };
        defer start.wipe();
        const id = d.by_key.get(start.remote_static) orelse {
            d.stats.dropped_invalid += 1;
            return;
        };
        const p = d.peers.items[id];
        // The replay check (strictly newer timestamp) only knows what this
        // process has accepted. Until then a recorded initiation replayed
        // by an on-path observer passes it, so the first one must not move
        // a known endpoint: the reply still goes to `from`, and the
        // endpoint follows once a transport packet authenticates.
        const timestamp_known = !crypto.isZero(crypto.tai64n_len, &p.hs.latest_timestamp);
        p.hs.consumeInitiation(&start, now) catch {
            d.stats.dropped_invalid += 1;
            return;
        };
        // Our response's sender index becomes the new keypair's local index.
        const idx = d.indices.insert(d.gpa, d.rng, .{ .peer = id, .kind = .keypair }) catch {
            p.hs.clear();
            return;
        };
        const resp = p.hs.createResponse(now, idx, d.rng) catch {
            d.indices.remove(idx);
            p.hs.clear();
            return;
        };
        var seed = p.hs.deriveKeys() catch {
            d.indices.remove(idx);
            return;
        };
        if (p.handshake_index) |old| d.indices.remove(old);
        p.handshake_index = null;
        d.retire(p.sess.responderSession(&seed, now));
        if (timestamp_known or p.endpoint == null) p.endpoint = from;
        p.last_authenticated = now;
        d.sendUdp(from, resp.asBytes());
        p.rx_bytes += msg.len;
        p.tx_bytes += noise.Response.size;
    }

    fn handleResponse(d: *Device, msg: []const u8, from: net.IpAddress, now: i64) void {
        const m = noise.Response.parse(msg) catch return;
        const e = d.indices.get(m.receiverIndex()) orelse return;
        if (e.kind != .handshake) return;
        const p = d.peers.items[e.peer];
        p.hs.consumeResponse(&d.local, m) catch {
            d.stats.dropped_invalid += 1;
            return;
        };
        var seed = p.hs.deriveKeys() catch return;
        d.indices.setKind(m.receiverIndex(), .keypair);
        p.handshake_index = null;
        d.retire(p.sess.initiatorSession(&seed, now));
        p.endpoint = from;
        p.last_authenticated = now;
        p.rx_bytes += msg.len;
        p.last_handshake_wall_ns = d.clock.wall();
        if (p.staged.isEmpty()) {
            d.sendData(p, &.{}, now); // confirm the session to the responder
        } else {
            d.flushStaged(p, now);
        }
    }

    fn handleTransport(d: *Device, msg: []const u8, from: net.IpAddress, now: i64) void {
        const hdr = session.transport.Header.parse(msg) catch return;
        const e = d.indices.get(hdr.receiver_index) orelse return;
        if (e.kind != .keypair) return;
        const p = d.peers.items[e.peer];
        const r = p.sess.decrypt(now, msg, d.pkt_buf) catch {
            d.stats.dropped_invalid += 1;
            return;
        };
        // Authenticated: roam to wherever it came from.
        p.endpoint = from;
        p.last_authenticated = now;
        p.rx_bytes += msg.len;
        d.retire(r.retired);
        if (r.confirmed) {
            p.last_handshake_wall_ns = d.clock.wall();
            d.flushStaged(p, now);
        }
        if (r.initiate_handshake) d.sendInitiation(p, now);
        if (r.plaintext.len == 0) return; // keepalive

        const addrs = ip.packetAddrs(r.plaintext) orelse {
            d.stats.dropped_invalid += 1;
            return;
        };
        // The claimed length must cover the IP header and fit in what was
        // decrypted (kernel receive.c: "dishonest_packet_size"; wireguard-go
        // does the same). An IPv6 length is payload + 40, so always >= 40.
        const min_len: usize = if (addrs.src == .v4) 20 else 40;
        if (addrs.total_len > r.plaintext.len or addrs.total_len < min_len) {
            d.stats.dropped_invalid += 1;
            return;
        }
        // Cryptokey routing, inbound half: the inner source must route back
        // to the peer that sent it.
        if (d.routes.lookup(addrs.src) != p.id) {
            d.stats.dropped_source_check += 1;
            return;
        }
        d.tun.write(r.plaintext[0..addrs.total_len]) catch {
            d.stats.tun_write_drops += 1;
        };
    }

    // ---- status -----------------------------------------------------------

    /// Live status for `show` (call from the loop thread or after `run`).
    pub fn peerStatus(d: *const Device, id: PeerId) show.PeerStatus {
        const p = d.peers.items[id];
        return .{
            .endpoint = p.endpoint,
            .last_handshake_unix = if (p.last_handshake_wall_ns) |t| @intCast(@divFloor(t, std.time.ns_per_s)) else null,
            .rx_bytes = p.rx_bytes,
            .tx_bytes = p.tx_bytes,
        };
    }

    pub fn peerByKey(d: *const Device, k: crypto.PublicKey) ?*Peer {
        const id = d.by_key.get(k) orelse return null;
        return d.peers.items[id];
    }
};

test "peer config from a parsed [Peer]: literal endpoints need no lookup and no name" {
    var allowed = [_]ip.Cidr{try ip.Cidr.parse("10.8.0.1/32")};
    var p: config.Peer = .{
        .public_key = @splat(7),
        .allowed_ips = &allowed,
        .persistent_keepalive = 25,
        .endpoint = try config.Endpoint.parse("[2001:db8::1]:51820"),
    };
    const r = PeerConfig.fromConfig(std.testing.io, &p);
    try std.testing.expectEqual(@as(?anyerror, null), r.unresolved);
    try std.testing.expect(r.peer.endpoint.? == .ip6);
    try std.testing.expectEqual(@as(u16, 51820), r.peer.endpoint.?.getPort());
    try std.testing.expectEqual(@as(?config.Endpoint, null), r.peer.endpoint_name);
    try std.testing.expectEqual(@as(u16, 25), r.peer.persistent_keepalive);
    try std.testing.expectEqual(@as(usize, 1), r.peer.allowed_ips.len);
    p.endpoint = null;
    const n = PeerConfig.fromConfig(std.testing.io, &p);
    try std.testing.expectEqual(@as(?net.IpAddress, null), n.peer.endpoint);
    try std.testing.expectEqual(@as(?config.Endpoint, null), n.peer.endpoint_name);
}

test "the device clock is the one that counts suspended time (.boot)" {
    try std.testing.expectEqual(std.Io.Clock.boot, monotonic_clock);
    var c: Clock = .{ .io = std.testing.io };
    const a = c.now();
    const b: i64 = @intCast(std.Io.Timestamp.now(std.testing.io, .boot).nanoseconds);
    const e = c.now();
    try std.testing.expect(a <= b and b <= e);
    c.advance(5 * std.time.ns_per_s);
    try std.testing.expect(c.now() >= e + 5 * std.time.ns_per_s);
}
