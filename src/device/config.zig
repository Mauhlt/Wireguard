//! The `[Interface]` / `[Peer]` configuration format, as wg-quick and
//! WireGuard for Windows write it.
//!
//! Syntax (matching both): one `Key = Value` per line, keys and section
//! names case-insensitive, `#` starts a comment anywhere on a line,
//! surrounding whitespace ignored, CRLF and a UTF-8 BOM accepted. Address,
//! DNS and AllowedIPs are comma-separated lists and may repeat (the entries
//! accumulate); every other key may appear once per section.
//!
//! Interface: PrivateKey (required), ListenPort, Address, DNS, MTU.
//! wg-quick's Table, PreUp, PostUp, PreDown, PostDown, SaveConfig and FwMark
//! are accepted and ignored with a warning (zwg runs no scripts).
//! Peer: PublicKey (required), PresharedKey, AllowedIPs, Endpoint
//! (host:port, [ipv6]:port; host may be a DNS name, resolved at `up`),
//! PersistentKeepalive (seconds, 0 or "off" = disabled).
//!
//! Errors carry the line number and never the value of a key line.

const std = @import("std");
const keys = @import("keys.zig");
const ip = @import("ip.zig");

pub const Key = keys.Key;
pub const Cidr = ip.Cidr;
pub const Addr = ip.Addr;

pub const Endpoint = struct {
    /// Host without brackets: an IPv4/IPv6 literal or a DNS name.
    host: []const u8,
    port: u16,

    /// Parses "host:port" / "[v6]:port" the way WireGuard for Windows does:
    /// the port follows the last colon; an IPv6 literal must be bracketed.
    pub fn parse(text: []const u8) error{InvalidEndpoint}!Endpoint {
        const colon = std.mem.findScalarLast(u8, text, ':') orelse return error.InvalidEndpoint;
        var host = text[0..colon];
        const port_text = text[colon + 1 ..];
        if (port_text.len == 0 or port_text.len > 5) return error.InvalidEndpoint;
        for (port_text) |c| if (c < '0' or c > '9') return error.InvalidEndpoint;
        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidEndpoint;
        if (port == 0) return error.InvalidEndpoint;
        if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
            host = host[1 .. host.len - 1];
            const a = Addr.parse(host) catch return error.InvalidEndpoint;
            if (a != .v6) return error.InvalidEndpoint;
            return .{ .host = host, .port = port };
        }
        if (host.len == 0) return error.InvalidEndpoint;
        if (std.mem.findAny(u8, host, "[]:") != null) return error.InvalidEndpoint;
        if (Addr.parse(host)) |_| {} else |_| {
            std.Io.net.HostName.validate(host) catch return error.InvalidEndpoint;
        }
        return .{ .host = host, .port = port };
    }

    /// The literal address, if the host is one (no DNS needed).
    pub fn literal(e: Endpoint) ?std.Io.net.IpAddress {
        const a = Addr.parse(e.host) catch return null;
        return switch (a) {
            .v4 => |b| .{ .ip4 = .{ .bytes = b, .port = e.port } },
            .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = e.port } },
        };
    }

    pub fn format(e: Endpoint, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (std.mem.findScalar(u8, e.host, ':') != null)
            try w.print("[{s}]:{d}", .{ e.host, e.port })
        else
            try w.print("{s}:{d}", .{ e.host, e.port });
    }
};

pub const Interface = struct {
    private_key: Key,
    listen_port: ?u16 = null,
    addresses: []Cidr = &.{},
    dns: []Addr = &.{},
    dns_search: [][]const u8 = &.{},
    mtu: ?u16 = null,
};

pub const Peer = struct {
    public_key: Key,
    preshared_key: ?Key = null,
    allowed_ips: []Cidr = &.{},
    endpoint: ?Endpoint = null,
    /// Seconds; 0 = off.
    persistent_keepalive: u16 = 0,
    /// Line of the `[Peer]` header (for messages).
    line: u32 = 0,
};

pub const Warning = struct {
    line: u32,
    /// Static text (never contains a value from the file).
    message: []const u8,
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    /// The arena's backing allocator: zeroes every block it gives back.
    wiper: *Wiping,
    interface: Interface,
    peers: []Peer,
    warnings: []Warning,

    pub fn deinit(c: *Config) void {
        std.crypto.secureZero(u8, &c.interface.private_key);
        for (c.peers) |*p| if (p.preshared_key) |*k| std.crypto.secureZero(u8, k);
        c.arena.deinit(); // every arena block (and stale copy in it) is zeroed on the way out
        const gpa = c.wiper.child;
        gpa.destroy(c.wiper);
        c.* = undefined;
    }
};

/// An allocator that zeroes memory before giving it back to `child`, so
/// nothing a parse put in its arena (keys, including copies left behind
/// when a list grew) survives `Config.deinit` or a failed parse. Never
/// moves a block (no remap), so no copy escapes unwiped.
pub const Wiping = struct {
    child: std.mem.Allocator,

    pub fn allocator(w: *Wiping) std.mem.Allocator {
        return .{ .ptr = w, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const w: *Wiping = @ptrCast(@alignCast(ctx));
        return w.child.rawAlloc(len, alignment, ret);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const w: *Wiping = @ptrCast(@alignCast(ctx));
        if (new_len < memory.len) std.crypto.secureZero(u8, memory[new_len..]);
        return w.child.rawResize(memory, alignment, new_len, ret);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret;
        return null; // the caller then allocates, copies and frees (wiped) itself
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const w: *Wiping = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        w.child.rawFree(memory, alignment, ret);
    }
};

/// Why parsing failed. `message` never contains key material.
pub const Diagnostic = struct {
    line: u32 = 0,
    buf: [200]u8 = undefined,
    len: usize = 0,

    pub fn message(d: *const Diagnostic) []const u8 {
        return d.buf[0..d.len];
    }

    fn set(d: *Diagnostic, line: u32, comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
        d.line = line;
        const s = std.fmt.bufPrint(&d.buf, fmt, args) catch blk: {
            const t = "(message too long)";
            @memcpy(d.buf[0..t.len], t);
            break :blk d.buf[0..t.len];
        };
        d.len = s.len;
        return error.InvalidConfig;
    }

    pub fn format(d: *const Diagnostic, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (d.line != 0) try w.print("line {d}: ", .{d.line});
        try w.writeAll(d.message());
    }
};

pub const ParseError = error{ InvalidConfig, OutOfMemory };

/// Largest config accepted; real ones are a few hundred bytes per peer.
pub const max_config_bytes = 1 << 20;

/// Read and parse a .conf file for the CLI (`zwg show / up`, and
/// `installtunnel`'s check before the UAC prompt). The text, which holds
/// the private key, is wiped. Problems and warnings go to `errw` as
/// "zwg: <path>: ..."; null when the file cannot be read or is invalid.
pub fn load(gpa: std.mem.Allocator, io: std.Io, path: []const u8, errw: *std.Io.Writer) !?Config {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes)) catch |err| {
        try errw.print("zwg: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    var diag: Diagnostic = .{};
    const c = parse(gpa, text, &diag) catch |err| switch (err) {
        error.InvalidConfig => {
            try errw.print("zwg: {s}: {f}\n", .{ path, diag });
            return null;
        },
        else => return err,
    };
    for (c.warnings) |w| try errw.print("zwg: {s}: line {d}: warning: {s}\n", .{ path, w.line, w.message });
    return c;
}
pub const max_peers = 4096;
pub const max_list_entries = 4096;

const Section = enum { none, interface, peer };

const ignored_interface_keys = [_][]const u8{ "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark" };

/// Parses a .conf. On error.InvalidConfig, `diag` says where and why.
/// The returned Config owns all its memory (free with `deinit`).
pub fn parse(gpa: std.mem.Allocator, text_in: []const u8, diag: *Diagnostic) ParseError!Config {
    const wiper = try gpa.create(Wiping);
    wiper.* = .{ .child = gpa };
    errdefer gpa.destroy(wiper);
    // On error the arena goes back through `wiper`: every block zeroed.
    var arena = std.heap.ArenaAllocator.init(wiper.allocator());
    errdefer arena.deinit();
    const a = arena.allocator();

    if (text_in.len > max_config_bytes) return diag.set(0, "file is larger than {d} bytes", .{max_config_bytes});
    var text = text_in;
    if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text = text[3..];

    var warnings: std.ArrayList(Warning) = .empty;
    var peers: std.ArrayList(Peer) = .empty;
    // Per-section accumulators.
    var addresses: std.ArrayList(Cidr) = .empty;
    var dns: std.ArrayList(Addr) = .empty;
    var dns_search: std.ArrayList([]const u8) = .empty;
    var allowed: std.ArrayList(Cidr) = .empty;

    var iface: Interface = .{ .private_key = undefined };
    var have_interface = false;
    var have_private = false;
    var seen: std.StringHashMapUnmanaged(void) = .empty; // keys seen in this section
    var section: Section = .none;
    var peer: Peer = .{ .public_key = undefined };
    var have_public = false;
    // The keys on this stack frame, on any error.
    errdefer {
        std.crypto.secureZero(u8, &iface.private_key);
        if (peer.preshared_key) |*k| std.crypto.secureZero(u8, k);
    }
    var private_line: u32 = 0;
    var interface_line: u32 = 0;

    var line_no: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        var line = raw;
        if (std.mem.findScalar(u8, line, '#')) |h| line = line[0..h];
        line = std.mem.trim(u8, line, " \t\r");
        if (line.len == 0) continue;

        if (line[0] == '[') {
            const name = line;
            // Close the previous peer.
            if (section == .peer) {
                try finishPeer(a, diag, &peers, &peer, have_public, &allowed);
            }
            seen.clearRetainingCapacity();
            if (std.ascii.eqlIgnoreCase(name, "[Interface]")) {
                if (have_interface) return diag.set(line_no, "a second [Interface] section", .{});
                have_interface = true;
                interface_line = line_no;
                section = .interface;
            } else if (std.ascii.eqlIgnoreCase(name, "[Peer]")) {
                if (peers.items.len >= max_peers) return diag.set(line_no, "more than {d} peers", .{max_peers});
                section = .peer;
                peer = .{ .public_key = undefined, .line = line_no };
                have_public = false;
            } else {
                return diag.set(line_no, "unknown section (expected [Interface] or [Peer])", .{});
            }
            continue;
        }

        const eq = std.mem.findScalar(u8, line, '=') orelse
            return diag.set(line_no, "expected 'Key = Value'", .{});
        const key_text = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (key_text.len == 0) return diag.set(line_no, "expected 'Key = Value'", .{});
        var lower_buf: [32]u8 = undefined;
        if (key_text.len > lower_buf.len) return diag.set(line_no, "unknown key", .{});
        const key = std.ascii.lowerString(&lower_buf, key_text);

        if (section == .none) return diag.set(line_no, "'{s}' outside of a section", .{key_text});

        const is_list = std.mem.eql(u8, key, "address") or std.mem.eql(u8, key, "dns") or std.mem.eql(u8, key, "allowedips");
        if (!is_list) {
            const gop = try seen.getOrPut(a, try a.dupe(u8, key));
            if (gop.found_existing) return diag.set(line_no, "duplicate key '{s}' in this section", .{key_text});
        }

        switch (section) {
            .none => unreachable,
            .interface => {
                if (std.mem.eql(u8, key, "privatekey")) {
                    iface.private_key = keys.decode(value) catch
                        return diag.set(line_no, "PrivateKey is not a valid key (44 characters of base64)", .{});
                    have_private = true;
                    private_line = line_no;
                } else if (std.mem.eql(u8, key, "listenport")) {
                    iface.listen_port = parsePort(value) orelse
                        return diag.set(line_no, "ListenPort must be a number from 0 to 65535", .{});
                } else if (std.mem.eql(u8, key, "address")) {
                    var it = try ListIter.init(value, diag, line_no);
                    while (try it.next(diag)) |item| {
                        const c = Cidr.parse(item) catch
                            return diag.set(line_no, "Address '{s}' is not an IP address with an optional /prefix", .{item});
                        if (addresses.items.len >= max_list_entries) return diag.set(line_no, "too many addresses", .{});
                        try addresses.append(a, c);
                    }
                } else if (std.mem.eql(u8, key, "dns")) {
                    var it = try ListIter.init(value, diag, line_no);
                    while (try it.next(diag)) |item| {
                        if (dns.items.len + dns_search.items.len >= max_list_entries) return diag.set(line_no, "too many DNS entries", .{});
                        if (Addr.parse(item)) |addr| {
                            try dns.append(a, addr);
                        } else |_| {
                            // Not an address: a search domain (WireGuard for Windows does the same).
                            std.Io.net.HostName.validate(item) catch
                                return diag.set(line_no, "DNS '{s}' is neither an IP address nor a domain name", .{item});
                            try dns_search.append(a, try a.dupe(u8, item));
                        }
                    }
                } else if (std.mem.eql(u8, key, "mtu")) {
                    const m = std.fmt.parseInt(u16, value, 10) catch 0;
                    if (m < 576 or !allDigits(value))
                        return diag.set(line_no, "MTU must be a number from 576 to 65535", .{});
                    iface.mtu = m;
                } else if (isIgnored(key)) {
                    try warnings.append(a, .{ .line = line_no, .message = ignoredMessage(key) });
                } else {
                    return diag.set(line_no, "unknown [Interface] key '{s}'", .{key_text});
                }
            },
            .peer => {
                if (std.mem.eql(u8, key, "publickey")) {
                    peer.public_key = keys.decode(value) catch
                        return diag.set(line_no, "PublicKey is not a valid key (44 characters of base64)", .{});
                    have_public = true;
                } else if (std.mem.eql(u8, key, "presharedkey")) {
                    var k = keys.decode(value) catch
                        return diag.set(line_no, "PresharedKey is not a valid key (44 characters of base64)", .{});
                    defer std.crypto.secureZero(u8, &k);
                    // All zeros means "no preshared key" (wg prints it as "(none)").
                    peer.preshared_key = if (keys.isZero(&k)) null else k;
                } else if (std.mem.eql(u8, key, "allowedips")) {
                    var it = try ListIter.init(value, diag, line_no);
                    while (try it.next(diag)) |item| {
                        const c = Cidr.parse(item) catch
                            return diag.set(line_no, "AllowedIPs '{s}' is not an IP address with an optional /prefix", .{item});
                        if (c.hasHostBits())
                            try warnings.append(a, .{ .line = line_no, .message = "AllowedIPs entry has host bits set; they are ignored (as the kernel does)" });
                        if (allowed.items.len >= max_list_entries) return diag.set(line_no, "too many AllowedIPs", .{});
                        try allowed.append(a, c.masked());
                    }
                } else if (std.mem.eql(u8, key, "endpoint")) {
                    const e = Endpoint.parse(value) catch
                        return diag.set(line_no, "Endpoint '{s}' must be host:port or [IPv6]:port", .{value});
                    peer.endpoint = .{ .host = try a.dupe(u8, e.host), .port = e.port };
                } else if (std.mem.eql(u8, key, "persistentkeepalive")) {
                    if (std.ascii.eqlIgnoreCase(value, "off")) {
                        peer.persistent_keepalive = 0;
                    } else {
                        peer.persistent_keepalive = parsePort(value) orelse
                            return diag.set(line_no, "PersistentKeepalive must be 'off' or a number of seconds from 0 to 65535", .{});
                    }
                } else {
                    return diag.set(line_no, "unknown [Peer] key '{s}'", .{key_text});
                }
            },
        }
    }
    if (section == .peer) try finishPeer(a, diag, &peers, &peer, have_public, &allowed);

    if (!have_interface) return diag.set(0, "no [Interface] section", .{});
    if (!have_private) return diag.set(interface_line, "[Interface] has no PrivateKey", .{});
    iface.addresses = try addresses.toOwnedSlice(a);
    iface.dns = try dns.toOwnedSlice(a);
    iface.dns_search = try dns_search.toOwnedSlice(a);

    // Cross-section checks.
    const own_public = keys.publicFromPrivate(&iface.private_key);
    for (peers.items, 0..) |*p, i| {
        if (std.mem.eql(u8, &p.public_key, &own_public))
            return diag.set(p.line, "this peer has the interface's own public key", .{});
        for (peers.items[0..i]) |*q| {
            if (std.mem.eql(u8, &p.public_key, &q.public_key))
                return diag.set(p.line, "duplicate peer (same PublicKey as the peer at line {d})", .{q.line});
        }
    }

    return .{
        .arena = arena,
        .wiper = wiper,
        .interface = iface,
        .peers = try peers.toOwnedSlice(a),
        .warnings = try warnings.toOwnedSlice(a),
    };
}

fn finishPeer(a: std.mem.Allocator, diag: *Diagnostic, peers: *std.ArrayList(Peer), peer: *Peer, have_public: bool, allowed: *std.ArrayList(Cidr)) ParseError!void {
    if (!have_public) return diag.set(peer.line, "[Peer] has no PublicKey", .{});
    peer.allowed_ips = try allowed.toOwnedSlice(a);
    try peers.append(a, peer.*);
}

fn isIgnored(key: []const u8) bool {
    for (ignored_interface_keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

fn ignoredMessage(key: []const u8) []const u8 {
    if (std.mem.eql(u8, key, "table")) return "Table is ignored (zwg does not manage routing tables)";
    if (std.mem.eql(u8, key, "saveconfig")) return "SaveConfig is ignored";
    if (std.mem.eql(u8, key, "fwmark")) return "FwMark is ignored";
    return "PreUp/PostUp/PreDown/PostDown are ignored (zwg runs no scripts)";
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

fn parsePort(s: []const u8) ?u16 {
    if (!allDigits(s) or s.len > 5) return null;
    return std.fmt.parseInt(u16, s, 10) catch null;
}

/// Comma-separated list; an empty value is an empty list, an empty item
/// ("a,,b" or a trailing comma) is an error, as in WireGuard for Windows.
const ListIter = struct {
    it: std.mem.SplitIterator(u8, .scalar),
    empty: bool,
    line: u32,

    fn init(value: []const u8, diag: *Diagnostic, line: u32) ParseError!ListIter {
        _ = diag;
        return .{ .it = std.mem.splitScalar(u8, value, ','), .empty = value.len == 0, .line = line };
    }

    fn next(l: *ListIter, diag: *Diagnostic) ParseError!?[]const u8 {
        if (l.empty) return null;
        const item = l.it.next() orelse return null;
        const t = std.mem.trim(u8, item, " \t");
        if (t.len == 0) return diag.set(l.line, "empty entry in a comma-separated list", .{});
        return t;
    }
};

// ---- Writing (for `zwg show`) -------------------------------------------

/// Writes the config back in .conf form. Secrets are replaced by
/// "(hidden)" unless `show_secrets` is set (only `zwg` itself never sets it).
pub fn write(c: *const Config, w: *std.Io.Writer, show_secrets: bool) std.Io.Writer.Error!void {
    try w.writeAll("[Interface]\n");
    if (show_secrets) {
        try w.print("PrivateKey = {s}\n", .{&keys.encode(&c.interface.private_key)});
    } else {
        try w.writeAll("PrivateKey = (hidden)\n");
    }
    if (c.interface.listen_port) |p| try w.print("ListenPort = {d}\n", .{p});
    if (c.interface.addresses.len != 0) {
        try w.writeAll("Address = ");
        try writeCidrs(w, c.interface.addresses);
        try w.writeAll("\n");
    }
    if (c.interface.dns.len + c.interface.dns_search.len != 0) {
        try w.writeAll("DNS = ");
        var first = true;
        for (c.interface.dns) |d| {
            if (!first) try w.writeAll(", ");
            first = false;
            try w.print("{f}", .{d});
        }
        for (c.interface.dns_search) |d| {
            if (!first) try w.writeAll(", ");
            first = false;
            try w.writeAll(d);
        }
        try w.writeAll("\n");
    }
    if (c.interface.mtu) |m| try w.print("MTU = {d}\n", .{m});
    for (c.peers) |*p| {
        try w.print("\n[Peer]\nPublicKey = {s}\n", .{&keys.encode(&p.public_key)});
        if (p.preshared_key) |*k| {
            if (show_secrets) try w.print("PresharedKey = {s}\n", .{&keys.encode(k)}) else try w.writeAll("PresharedKey = (hidden)\n");
        }
        if (p.allowed_ips.len != 0) {
            try w.writeAll("AllowedIPs = ");
            try writeCidrs(w, p.allowed_ips);
            try w.writeAll("\n");
        }
        if (p.endpoint) |e| try w.print("Endpoint = {f}\n", .{e});
        if (p.persistent_keepalive != 0) try w.print("PersistentKeepalive = {d}\n", .{p.persistent_keepalive});
    }
}

pub fn writeCidrs(w: *std.Io.Writer, list: []const Cidr) std.Io.Writer.Error!void {
    for (list, 0..) |c, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("{f}", .{c});
    }
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;

// Keys made with `wg genkey` / `wg pubkey` for these tests only.
const desktop_priv = "eE9wmXJ5Q1xwrdhbdsbsC0Y0zPjS4BOFhVDhfF4zZ2w=";
const laptop_priv = "WAdXKvvGG8bEGuj6IXZLtVvvXQ0HM8SNJ+mOhTq4HlQ=";
const phone_priv = "OCRz6Lf/a9wkeOKKCGHuK/0oUGCUQpd/qz6+v/PQ6Fs=";

fn pubOf(comptime priv: []const u8) [44]u8 {
    const k = keys.decode(priv) catch unreachable;
    return keys.encode(&keys.publicFromPrivate(&k));
}

fn expectInvalid(text: []const u8, line: u32, needle: []const u8) !void {
    var d: Diagnostic = .{};
    if (parse(testing.allocator, text, &d)) |c| {
        var cc = c;
        cc.deinit();
        return error.TestExpectedError;
    } else |err| {
        try testing.expectEqual(error.InvalidConfig, err);
        try testing.expectEqual(line, d.line);
        if (std.mem.find(u8, d.message(), needle) == null) {
            std.debug.print("message: {s}\n", .{d.message()});
            return error.TestUnexpectedMessage;
        }
    }
}

/// Test helper: wraps testing.allocator and remembers whether any block given back
/// still contained one of `needles` (key bytes).
pub const FreeSpy = struct {
    needles: []const []const u8,
    leaked: bool = false,

    pub fn allocator(s: *FreeSpy) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(_: *anyopaque, len: usize, al: std.mem.Alignment, ret: usize) ?[*]u8 {
        return testing.allocator.rawAlloc(len, al, ret);
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ret: usize) bool {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        if (n < m.len) s.check(m[n..]);
        return testing.allocator.rawResize(m, al, n, ret);
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ret: usize) void {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        s.check(m);
        testing.allocator.rawFree(m, al, ret);
    }
    fn check(s: *FreeSpy, m: []const u8) void {
        for (s.needles) |n| if (std.mem.indexOf(u8, m, n) != null) {
            s.leaked = true;
        };
    }
};

test "key material is wiped from freed memory: after deinit and after a failed parse" {
    const psk_b64 = "E2c8gYB5tYTUAg8ekhHYT5RhEnVyIu0ppD2D9+ZyMH0=";
    const psk = try keys.decode(psk_b64);
    const priv = try keys.decode(desktop_priv);
    const head = "[Interface]\nPrivateKey = " ++ desktop_priv ++ "\n" ++
        "[Peer]\nPublicKey = " ++ pubOf(laptop_priv) ++ "\nPresharedKey = " ++ psk_b64 ++ "\nAllowedIPs = 10.8.0.2/32\n" ++
        "[Peer]\nPublicKey = " ++ pubOf(phone_priv) ++ "\nPresharedKey = " ++ psk_b64 ++ "\nAllowedIPs = 10.8.0.3/32\n";
    const needles = [_][]const u8{ &psk, &priv };
    {
        var spy: FreeSpy = .{ .needles = &needles };
        var d: Diagnostic = .{};
        var c = try parse(spy.allocator(), head, &d);
        try testing.expectEqualSlices(u8, &psk, &c.peers[1].preshared_key.?);
        c.deinit();
        try testing.expect(!spy.leaked);
    }
    {
        // Fails after both peers (with their keys) were stored in the arena.
        var spy: FreeSpy = .{ .needles = &needles };
        var d: Diagnostic = .{};
        try testing.expectError(error.InvalidConfig, parse(spy.allocator(), head ++ "[Peer]\nPublicKey = not-a-key\n", &d));
        try testing.expect(!spy.leaked);
    }
    {
        // Sanity: the spy does see keys in memory given back unwiped
        // (rawFree, as ArenaAllocator.deinit frees its blocks; free()
        // would scribble over it in safe builds first).
        var spy: FreeSpy = .{ .needles = &needles };
        const a = spy.allocator();
        const buf = try a.dupe(u8, &psk);
        a.rawFree(buf, .of(u8), @returnAddress());
        try testing.expect(spy.leaked);
        // And an arena straight on it (no Wiping) would leak the keys.
        var spy2: FreeSpy = .{ .needles = &needles };
        var arena = std.heap.ArenaAllocator.init(spy2.allocator());
        _ = try arena.allocator().dupe(u8, &psk);
        arena.deinit();
        try testing.expect(spy2.leaked);
    }
}

test "desktop hub config (Portal docs/wireguard.md) with two peers" {
    const text = "[Interface]\r\n" ++
        "PrivateKey = " ++ desktop_priv ++ "\r\n" ++
        "Address = 10.8.0.1/24\r\n" ++
        "ListenPort = 51820\r\n" ++
        "\r\n" ++
        "[Peer]\r\n" ++
        "# laptop\r\n" ++
        "PublicKey = " ++ pubOf(laptop_priv) ++ "\r\n" ++
        "AllowedIPs = 10.8.0.2/32\r\n" ++
        "\r\n" ++
        "[Peer]\r\n" ++
        "# iphone\r\n" ++
        "PublicKey = " ++ pubOf(phone_priv) ++ "\r\n" ++
        "AllowedIPs = 10.8.0.3/32\r\n";
    var d: Diagnostic = .{};
    var c = try parse(testing.allocator, text, &d);
    defer c.deinit();
    try testing.expectEqual(@as(?u16, 51820), c.interface.listen_port);
    try testing.expectEqual(@as(usize, 1), c.interface.addresses.len);
    try testing.expect(c.interface.addresses[0].eql(try Cidr.parse("10.8.0.1/24")));
    try testing.expectEqual(@as(usize, 2), c.peers.len);
    try testing.expectEqualStrings(&pubOf(laptop_priv), &keys.encode(&c.peers[0].public_key));
    try testing.expect(c.peers[1].allowed_ips[0].eql(try Cidr.parse("10.8.0.3/32")));
    try testing.expectEqual(@as(?Endpoint, null), c.peers[0].endpoint);
    try testing.expectEqual(@as(usize, 0), c.warnings.len);

    // Written form hides the private key.
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try write(&c, &out.writer, false);
    try testing.expect(std.mem.find(u8, out.written(), desktop_priv) == null);
    try testing.expect(std.mem.find(u8, out.written(), "PrivateKey = (hidden)") != null);
    try testing.expect(std.mem.find(u8, out.written(), "AllowedIPs = 10.8.0.3/32") != null);
}

test "laptop and iPhone client configs with DDNS endpoint and keepalive" {
    const laptop = "[Interface]\n" ++
        "PrivateKey = " ++ laptop_priv ++ "\n" ++
        "Address = 10.8.0.2/24\n\n" ++
        "[Peer]\n# desktop\n" ++
        "PublicKey = " ++ pubOf(desktop_priv) ++ "\n" ++
        "Endpoint = home.example.duckdns.org:51820\n" ++
        "AllowedIPs = 10.8.0.1/32\n" ++
        "PersistentKeepalive = 25\n";
    var d: Diagnostic = .{};
    var c = try parse(testing.allocator, laptop, &d);
    defer c.deinit();
    const e = c.peers[0].endpoint.?;
    try testing.expectEqualStrings("home.example.duckdns.org", e.host);
    try testing.expectEqual(@as(u16, 51820), e.port);
    try testing.expectEqual(@as(?std.Io.net.IpAddress, null), e.literal());
    try testing.expectEqual(@as(u16, 25), c.peers[0].persistent_keepalive);

    // The iPhone app's export style: lowercase-insensitive keys, DNS, MTU,
    // IP literal endpoint, several AllowedIPs over two lines.
    const phone = "\xEF\xBB\xBF[Interface]\n" ++
        "privatekey=" ++ phone_priv ++ "\n" ++
        "Address = 10.8.0.3/32\n" ++
        "DNS = 1.1.1.1, 2606:4700:4700::1111, home.lan\n" ++
        "MTU = 1420\n" ++
        "[peer]\n" ++
        "PublicKey = " ++ pubOf(desktop_priv) ++ "\n" ++
        "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" ++
        "AllowedIPs = 10.8.0.1/32, fd00::1/128\n" ++
        "AllowedIPs = 0.0.0.0/0,::/0\n" ++
        "Endpoint = [2001:db8::1]:51820 # v6\n";
    var c2 = try parse(testing.allocator, phone, &d);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 2), c2.interface.dns.len);
    try testing.expectEqualStrings("home.lan", c2.interface.dns_search[0]);
    try testing.expectEqual(@as(?u16, 1420), c2.interface.mtu);
    try testing.expectEqual(@as(?Key, null), c2.peers[0].preshared_key);
    try testing.expectEqual(@as(usize, 4), c2.peers[0].allowed_ips.len);
    try testing.expectEqualStrings("2001:db8::1", c2.peers[0].endpoint.?.host);
    try testing.expect(c2.peers[0].endpoint.?.literal() != null);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("[2001:db8::1]:51820", try std.fmt.bufPrint(&buf, "{f}", .{c2.peers[0].endpoint.?}));
}

test "wg-quick extras are ignored with warnings" {
    const text = "[Interface]\nPrivateKey = " ++ desktop_priv ++ "\n" ++
        "Table = off\nPostUp = iptables -A FORWARD\nPreDown = x\nSaveConfig = true\n" ++
        "[Peer]\nPublicKey = " ++ pubOf(laptop_priv) ++ "\nAllowedIPs = 10.8.0.5/24\nPersistentKeepalive = off\n";
    var d: Diagnostic = .{};
    var c = try parse(testing.allocator, text, &d);
    defer c.deinit();
    try testing.expectEqual(@as(usize, 5), c.warnings.len);
    try testing.expectEqual(@as(u32, 3), c.warnings[0].line);
    try testing.expectEqual(@as(u32, 9), c.warnings[4].line); // host bits
    try testing.expect(c.peers[0].allowed_ips[0].eql(try Cidr.parse("10.8.0.0/24")));
    try testing.expectEqual(@as(u16, 0), c.peers[0].persistent_keepalive);
}

test "validation errors carry line numbers and no secrets" {
    const iface = "[Interface]\nPrivateKey = " ++ desktop_priv ++ "\n";
    const peer_hdr = "[Peer]\nPublicKey = " ++ pubOf(laptop_priv) ++ "\n";
    try expectInvalid("PrivateKey = x\n", 1, "outside of a section");
    try expectInvalid("[Interface]\nPrivateKey = abc\n", 2, "PrivateKey is not a valid key");
    try expectInvalid("[Interface]\nPrivateKey = " ++ desktop_priv[0..43] ++ "x\n", 2, "PrivateKey");
    try expectInvalid("[Interface]\nAddress = 10.0.0.1/24\n", 1, "no PrivateKey");
    try expectInvalid("[Peer]\nPublicKey = " ++ pubOf(laptop_priv) ++ "\n", 0, "no [Interface]");
    try expectInvalid(iface ++ "ListenPort = 70000\n", 3, "ListenPort");
    try expectInvalid(iface ++ "ListenPort = -1\n", 3, "ListenPort");
    try expectInvalid(iface ++ "MTU = 500\n", 3, "MTU");
    try expectInvalid(iface ++ "Address = 10.0.0.1/24,,10.0.0.2\n", 3, "empty entry");
    try expectInvalid(iface ++ "Address = 10.0.0.1/33\n", 3, "Address '10.0.0.1/33'");
    try expectInvalid(iface ++ "Bogus = 1\n", 3, "unknown [Interface] key");
    try expectInvalid(iface ++ "[Interface]\n", 3, "second [Interface]");
    try expectInvalid(iface ++ "[Wat]\n", 3, "unknown section");
    try expectInvalid(iface ++ "ListenPort = 1\nlistenport = 2\n", 4, "duplicate key");
    try expectInvalid(iface ++ "just text\n", 3, "Key = Value");
    try expectInvalid(iface ++ "[Peer]\nAllowedIPs = 10.0.0.2/32\n", 3, "no PublicKey");
    try expectInvalid(iface ++ peer_hdr ++ "Endpoint = 2001:db8::1:51820\n", 5, "Endpoint");
    try expectInvalid(iface ++ peer_hdr ++ "Endpoint = host\n", 5, "Endpoint");
    try expectInvalid(iface ++ peer_hdr ++ "Endpoint = host:0\n", 5, "Endpoint");
    try expectInvalid(iface ++ peer_hdr ++ "Endpoint = [10.0.0.1]:5\n", 5, "Endpoint");
    try expectInvalid(iface ++ peer_hdr ++ "PersistentKeepalive = 1m\n", 5, "PersistentKeepalive");
    try expectInvalid(iface ++ peer_hdr ++ "PresharedKey = nope\n", 5, "PresharedKey is not");
    try expectInvalid(iface ++ peer_hdr ++ "DNS = 1.1.1.1\n", 5, "unknown [Peer] key");
    try expectInvalid(iface ++ peer_hdr ++ peer_hdr, 5, "duplicate peer");
    try expectInvalid(iface ++ "[Peer]\nPublicKey = " ++ pubOf(desktop_priv) ++ "\n", 3, "own public key");

    // A bad key's text never appears in the message.
    var d: Diagnostic = .{};
    const secret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2Vj";
    try testing.expectError(error.InvalidConfig, parse(testing.allocator, "[Interface]\nPrivateKey = " ++ secret ++ "\n", &d));
    try testing.expect(std.mem.find(u8, d.message(), "c2Vj") == null);
}

test "endpoint parsing" {
    const e = try Endpoint.parse("1.2.3.4:51820");
    try testing.expectEqualStrings("1.2.3.4", e.host);
    try testing.expect(e.literal().?.ip4.port == 51820);
    _ = try Endpoint.parse("[::1]:1");
    try testing.expectError(error.InvalidEndpoint, Endpoint.parse(":51820"));
    try testing.expectError(error.InvalidEndpoint, Endpoint.parse("[::1]"));
    try testing.expectError(error.InvalidEndpoint, Endpoint.parse("a b:1"));
    try testing.expectError(error.InvalidEndpoint, Endpoint.parse("x:65536"));
}
