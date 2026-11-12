//! Windows TUN backend: Wintun.
//!
//! THE ONE NON-ZIG RUNTIME COMPONENT. A layer-3 virtual adapter on Windows
//! needs a kernel driver, and Windows only loads signed kernel drivers, so a
//! pure-userspace TUN is impossible. We use Wintun (by the WireGuard project,
//! https://www.wintun.net/), whose wintun.dll carries the signed driver and
//! installs it on first use. wintun.dll is loaded at runtime with
//! LoadLibraryExW restricted to the application directory and System32, so a
//! planted DLL in the current directory or PATH is never picked up.
//!
//! We never ship or commit wintun.dll. To run zwg on Windows:
//!   1. Download the official signed release zip from https://www.wintun.net/
//!      (currently wintun-0.14.1.zip) and check its SHA-256 against the one
//!      published on that page.
//!   2. Copy wintun/bin/<arch>/wintun.dll (amd64, arm64, x86 or arm) next to
//!      zwg.exe.
//! The DLL is signed by "WireGuard LLC"; the driver it installs is
//! Microsoft-attested. Nothing else is required.
//!
//! Privilege: creating an adapter, starting a session (the adapter's device
//! object is SYSTEM/Administrators only) and adding addresses/routes all need
//! an elevated token. `open` checks elevation first and fails with
//! `error.AccessDenied` instead of a confusing driver error. See
//! tests/interop/README.md, "Elevation design", for how zwg is meant to run.
//!
//! Event-driven: `waitHandle` is Wintun's read-wait event (auto-reset, owned by
//! the session: do not close it). Wintun signals it when the ring goes from
//! empty to non-empty, so the device drains with `read` until null and then
//! waits again; no polling.
const std = @import("std");
const root = @import("root.zig");
const Cidr = root.Cidr;
const Tun = root.Tun;
const WaitHandle = root.WaitHandle;

const log = std.log.scoped(.wintun);

const HANDLE = std.os.windows.HANDLE;
const HMODULE = *opaque {};
const NET_LUID = u64;

pub const default_ring_capacity: u32 = 0x40_0000; // 4 MiB, as wireguard-go uses
pub const min_ring_capacity: u32 = 0x2_0000; // WINTUN_MIN_RING_CAPACITY
pub const max_ring_capacity: u32 = 0x400_0000; // WINTUN_MAX_RING_CAPACITY
pub const max_ip_packet_size = 0xFFFF; // WINTUN_MAX_IP_PACKET_SIZE
pub const max_adapter_name = 127; // MAX_ADAPTER_NAME (128 incl. NUL)
pub const tunnel_type = "zwg";

/// What to tell the user on `error.AccessDenied`.
pub const elevation_hint =
    "creating a Wintun adapter needs an elevated (Administrator) process: run `zwg up` " ++
    "from an elevated prompt, or install the tunnel as a service (tests/interop/README.md, " ++
    "\"Elevation design\")";

/// What to tell the user on `error.WintunNotFound`.
pub const wintun_hint =
    "wintun.dll was not found next to zwg.exe or in System32. Download the signed official " ++
    "release from https://www.wintun.net/, verify its SHA-256, and copy " ++
    "wintun\\bin\\<arch>\\wintun.dll next to zwg.exe";

pub const OpenError = error{
    /// The process is not elevated (see the module doc).
    AccessDenied,
    /// wintun.dll is not next to the executable nor in System32.
    WintunNotFound,
    /// wintun.dll lacks an expected export (too old / not Wintun).
    WintunIncompatible,
    InvalidName,
    NameTooLong,
    AdapterCreateFailed,
    SessionStartFailed,
    Unexpected,
};

pub const OpenOptions = struct {
    mtu: u16 = root.default_mtu,
    ring_capacity: u32 = default_ring_capacity,
};

// ---- Wintun API (wintun.h, v0.14) ------------------------------------------

const Adapter = *opaque {};
const Session = *opaque {};
const Guid = extern struct { bytes: [16]u8 };
const LoggerCallback = *const fn (level: c_int, timestamp: u64, message: [*:0]const u16) callconv(.winapi) void;

const Api = struct {
    dll: HMODULE,
    CreateAdapter: *const fn (name: [*:0]const u16, tunnel_type: [*:0]const u16, guid: ?*const Guid) callconv(.winapi) ?Adapter,
    CloseAdapter: *const fn (adapter: Adapter) callconv(.winapi) void,
    GetAdapterLUID: *const fn (adapter: Adapter, luid: *NET_LUID) callconv(.winapi) void,
    GetRunningDriverVersion: *const fn () callconv(.winapi) u32,
    SetLogger: *const fn (cb: ?LoggerCallback) callconv(.winapi) void,
    StartSession: *const fn (adapter: Adapter, capacity: u32) callconv(.winapi) ?Session,
    EndSession: *const fn (session: Session) callconv(.winapi) void,
    GetReadWaitEvent: *const fn (session: Session) callconv(.winapi) HANDLE,
    ReceivePacket: *const fn (session: Session, size: *u32) callconv(.winapi) ?[*]u8,
    ReleaseReceivePacket: *const fn (session: Session, packet: [*]const u8) callconv(.winapi) void,
    AllocateSendPacket: *const fn (session: Session, size: u32) callconv(.winapi) ?[*]u8,
    SendPacket: *const fn (session: Session, packet: [*]const u8) callconv(.winapi) void,

    /// Load wintun.dll from the application directory or System32 only.
    pub fn load() error{ WintunNotFound, WintunIncompatible }!Api {
        const dll = k32.LoadLibraryExW(
            std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll"),
            null,
            k32.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | k32.LOAD_LIBRARY_SEARCH_SYSTEM32,
        ) orelse return error.WintunNotFound;
        errdefer _ = k32.FreeLibrary(dll);
        var api: Api = undefined;
        api.dll = dll;
        inline for (comptime std.meta.fieldNames(Api)) |name| {
            if (comptime std.mem.eql(u8, name, "dll")) continue;
            const sym = k32.GetProcAddress(dll, "Wintun" ++ name) orelse return error.WintunIncompatible;
            @field(api, name) = @ptrCast(@alignCast(sym));
        }
        return api;
    }

    pub fn unload(api: *Api) void {
        _ = k32.FreeLibrary(api.dll);
        api.* = undefined;
    }
};

fn wintunLogger(level: c_int, timestamp: u64, message: [*:0]const u16) callconv(.winapi) void {
    _ = timestamp;
    const msg = std.unicode.fmtUtf16Le(std.mem.span(message));
    switch (level) {
        0 => log.info("{f}", .{msg}),
        1 => log.warn("{f}", .{msg}),
        else => log.err("{f}", .{msg}),
    }
}

/// Is wintun.dll loadable, and which driver version is running (0 = driver
/// not loaded yet; it loads when the first adapter is created)? Needs no
/// privileges; used by diagnostics and tests.
pub fn probe() error{ WintunNotFound, WintunIncompatible }!u32 {
    var api = try Api.load();
    defer api.unload();
    return api.GetRunningDriverVersion();
}

// ---- the adapter -----------------------------------------------------------

pub const Wintun = struct {
    api: Api,
    adapter: Adapter,
    session: Session,
    read_event: HANDLE,
    luid: NET_LUID,
    mtu_value: u16,
    /// Diagnostic counters (the device may report them).
    dropped_reads: u64 = 0,

    /// Create the adapter `name` (UTF-8, at most 127 UTF-16 units), start a
    /// session and set the interface MTU. Requires an elevated process.
    pub fn open(name: []const u8, options: OpenOptions) OpenError!Wintun {
        if (!isElevated()) return error.AccessDenied; // caller prints `elevation_hint`
        if (name.len == 0) return error.InvalidName;
        // UTF-16 never needs more units than UTF-8 has bytes, so this bounds the copy.
        if (name.len > max_adapter_name) return error.NameTooLong;
        var wname: [max_adapter_name + 1]u16 = undefined;
        const wlen = std.unicode.utf8ToUtf16Le(wname[0..max_adapter_name], name) catch |e| switch (e) {
            error.InvalidUtf8 => return error.InvalidName,
        };
        wname[wlen] = 0;

        var api = try Api.load(); // on WintunNotFound the caller prints `wintun_hint`
        errdefer api.unload();
        api.SetLogger(wintunLogger);

        // A stable GUID per name keeps Windows from creating a new "Network N"
        // profile every time the tunnel comes up (wireguard-windows does the same).
        const guid = adapterGuid(name);
        const adapter = api.CreateAdapter(
            @ptrCast(&wname),
            std.unicode.utf8ToUtf16LeStringLiteral(tunnel_type),
            &guid,
        ) orelse {
            const err = lastError();
            log.err("WintunCreateAdapter failed: Win32 error {d}", .{err});
            return if (err == ERROR_ACCESS_DENIED) error.AccessDenied else error.AdapterCreateFailed;
        };
        errdefer api.CloseAdapter(adapter);
        log.info("Wintun driver version {d}.{d}", .{ api.GetRunningDriverVersion() >> 16, api.GetRunningDriverVersion() & 0xffff });

        var luid: NET_LUID = 0;
        api.GetAdapterLUID(adapter, &luid);

        const cap = std.math.clamp(std.math.ceilPowerOfTwoAssert(u32, @max(options.ring_capacity, 1)), min_ring_capacity, max_ring_capacity);
        const session = api.StartSession(adapter, cap) orelse {
            log.err("WintunStartSession failed: Win32 error {d}", .{lastError()});
            return error.SessionStartFailed;
        };
        errdefer api.EndSession(session);

        // MTU: both families; IPv6 may be disabled on the host, which is fine.
        setInterfaceMtu(luid, AF_INET, options.mtu) catch |e| {
            log.err("setting IPv4 MTU failed: {t}", .{e});
            return error.Unexpected;
        };
        setInterfaceMtu(luid, AF_INET6, options.mtu) catch {};

        return .{
            .api = api,
            .adapter = adapter,
            .session = session,
            .read_event = api.GetReadWaitEvent(session),
            .luid = luid,
            .mtu_value = options.mtu,
        };
    }

    /// End the session and remove the adapter (and with it its addresses
    /// and routes).
    pub fn close(w: *Wintun) void {
        w.api.EndSession(w.session);
        w.api.CloseAdapter(w.adapter);
        w.api.SetLogger(null);
        w.api.unload();
        w.* = undefined;
    }

    pub fn tun(w: *Wintun) Tun {
        return .{ .ptr = w, .vtable = &vtable };
    }

    const vtable: Tun.VTable = .{
        .waitHandle = waitHandle,
        .read = read,
        .write = write,
        .mtu = mtu,
        .setAddress = setAddress,
        .addRoute = addRoute,
    };

    fn self(ptr: *anyopaque) *Wintun {
        return @ptrCast(@alignCast(ptr));
    }

    fn waitHandle(ptr: *anyopaque) WaitHandle {
        return self(ptr).read_event;
    }

    fn read(ptr: *anyopaque, buf: []u8) root.ReadError!?[]u8 {
        const w = self(ptr);
        var size: u32 = 0;
        const pkt = w.api.ReceivePacket(w.session, &size) orelse return switch (lastError()) {
            ERROR_NO_MORE_ITEMS => null,
            ERROR_HANDLE_EOF => error.Closed, // adapter is terminating
            ERROR_INVALID_DATA => error.Closed, // ring corrupt: session unusable
            else => error.Unexpected,
        };
        defer w.api.ReleaseReceivePacket(w.session, pkt);
        if (size > buf.len) {
            w.dropped_reads += 1;
            return error.BufferTooSmall;
        }
        @memcpy(buf[0..size], pkt[0..size]);
        return buf[0..size];
    }

    fn write(ptr: *anyopaque, packet: []const u8) root.WriteError!void {
        const w = self(ptr);
        if (packet.len == 0) return error.InvalidPacket;
        if (packet.len > max_ip_packet_size) return error.PacketTooLarge;
        const out = w.api.AllocateSendPacket(w.session, @intCast(packet.len)) orelse return switch (lastError()) {
            ERROR_BUFFER_OVERFLOW => error.QueueFull,
            ERROR_HANDLE_EOF => error.Closed,
            else => error.Unexpected,
        };
        @memcpy(out[0..packet.len], packet);
        w.api.SendPacket(w.session, out);
    }

    fn mtu(ptr: *anyopaque) u16 {
        return self(ptr).mtu_value;
    }

    fn setAddress(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        return addUnicastAddress(self(ptr).luid, cidr);
    }

    fn addRoute(ptr: *anyopaque, cidr: Cidr) root.ConfigError!void {
        return addOnLinkRoute(self(ptr).luid, cidr);
    }
};

/// Deterministic adapter GUID from the name (a v4-style GUID, hash-derived).
pub fn adapterGuid(name: []const u8) Guid {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("zwg wintun adapter guid v1\x00");
    h.update(name);
    var d: [32]u8 = undefined;
    h.final(&d);
    var g: Guid = .{ .bytes = d[0..16].* };
    g.bytes[7] = (g.bytes[7] & 0x0f) | 0x40; // version 4 (Data3 high nibble, little-endian)
    g.bytes[8] = (g.bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    return g;
}

// ---- elevation ---------------------------------------------------------------

/// True when the process token is elevated (TokenElevation). Unelevated
/// admin users under UAC report false, which is what we want: Wintun needs
/// the full token.
pub fn isElevated() bool {
    const current_process: HANDLE = @ptrFromInt(std.math.maxInt(usize));
    var token: HANDLE = undefined;
    if (advapi32.OpenProcessToken(current_process, advapi32.TOKEN_QUERY, &token) == 0) return false;
    defer std.os.windows.CloseHandle(token);
    var elevation: u32 = 0;
    var ret_len: u32 = 0;
    if (advapi32.GetTokenInformation(token, advapi32.TokenElevation, &elevation, @sizeOf(u32), &ret_len) == 0) return false;
    return elevation != 0;
}

// ---- IP Helper: addresses, routes, MTU -------------------------------------

fn netioToConfigError(status: u32) root.ConfigError!void {
    return switch (status) {
        0, ERROR_OBJECT_ALREADY_EXISTS => {},
        ERROR_ACCESS_DENIED => error.AccessDenied,
        ERROR_NOT_FOUND, ERROR_FILE_NOT_FOUND => error.Closed,
        else => {
            log.err("IP Helper call failed: NETIO_STATUS {d}", .{status});
            return error.Unexpected;
        },
    };
}

fn sockaddrInet(cidr: Cidr) iphlp.SOCKADDR_INET {
    var sa: iphlp.SOCKADDR_INET = std.mem.zeroes(iphlp.SOCKADDR_INET);
    switch (cidr.family) {
        .ip4 => {
            sa.v4.family = AF_INET;
            sa.v4.addr = cidr.addr[0..4].*;
        },
        .ip6 => {
            sa.v6.family = AF_INET6;
            sa.v6.addr = cidr.addr;
        },
    }
    return sa;
}

pub fn addUnicastAddress(luid: NET_LUID, cidr: Cidr) root.ConfigError!void {
    var row: iphlp.MIB_UNICASTIPADDRESS_ROW = undefined;
    iphlp.InitializeUnicastIpAddressEntry(&row);
    row.Address = sockaddrInet(cidr);
    row.InterfaceLuid = luid;
    row.OnLinkPrefixLength = cidr.prefix_len;
    row.DadState = iphlp.IpDadStatePreferred;
    return netioToConfigError(iphlp.CreateUnicastIpAddressEntry(&row));
}

pub fn addOnLinkRoute(luid: NET_LUID, cidr: Cidr) root.ConfigError!void {
    var row: iphlp.MIB_IPFORWARD_ROW2 = undefined;
    iphlp.InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddrInet(cidr.network());
    row.DestinationPrefix.PrefixLength = cidr.prefix_len;
    // On-link: next hop is the unspecified address of the same family.
    row.NextHop = sockaddrInet(switch (cidr.family) {
        .ip4 => Cidr.ip4(.{ 0, 0, 0, 0 }, 0),
        .ip6 => Cidr.ip6(@splat(0), 0),
    });
    row.Metric = 0;
    return netioToConfigError(iphlp.CreateIpForwardEntry2(&row));
}

fn setInterfaceMtu(luid: NET_LUID, family: u16, mtu: u16) root.ConfigError!void {
    var row: iphlp.MIB_IPINTERFACE_ROW = undefined;
    iphlp.InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = luid;
    try netioToConfigError(iphlp.GetIpInterfaceEntry(&row));
    row.NlMtu = mtu;
    if (family == AF_INET) row.SitePrefixLength = 0; // required by SetIpInterfaceEntry for IPv4
    return netioToConfigError(iphlp.SetIpInterfaceEntry(&row));
}

// ---- Win32 declarations (hand-declared: std and the owner's Windows bindings
// lack LoadLibraryExW, advapi32 token calls and all of iphlpapi) -------------

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

fn lastError() u32 {
    return @intFromEnum(std.os.windows.GetLastError());
}

const k32 = struct {
    const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: ?HANDLE, flags: u32) callconv(.winapi) ?HMODULE;
    extern "kernel32" fn GetProcAddress(module: HMODULE, name: [*:0]const u8) callconv(.winapi) ?*const anyopaque;
    extern "kernel32" fn FreeLibrary(module: HMODULE) callconv(.winapi) c_int;
};

const advapi32 = struct {
    const TOKEN_QUERY: u32 = 0x0008;
    const TokenElevation: c_int = 20;
    extern "advapi32" fn OpenProcessToken(process: HANDLE, access: u32, token: *HANDLE) callconv(.winapi) c_int;
    extern "advapi32" fn GetTokenInformation(token: HANDLE, class: c_int, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) c_int;
};

pub const iphlp = struct {
    pub const SockaddrIn = extern struct { family: u16, port: u16, addr: [4]u8, zero: [8]u8 };
    pub const SockaddrIn6 = extern struct { family: u16, port: u16, flowinfo: u32, addr: [16]u8, scope_id: u32 };
    pub const SOCKADDR_INET = extern union { v4: SockaddrIn, v6: SockaddrIn6, family: u16 };

    pub const IpDadStatePreferred: c_int = 4;

    pub const MIB_UNICASTIPADDRESS_ROW = extern struct {
        Address: SOCKADDR_INET,
        InterfaceLuid: NET_LUID,
        InterfaceIndex: u32,
        PrefixOrigin: c_int,
        SuffixOrigin: c_int,
        ValidLifetime: u32,
        PreferredLifetime: u32,
        OnLinkPrefixLength: u8,
        SkipAsSource: u8,
        DadState: c_int,
        ScopeId: u32,
        CreationTimeStamp: i64,
    };

    pub const IP_ADDRESS_PREFIX = extern struct {
        Prefix: SOCKADDR_INET,
        PrefixLength: u8,
    };

    pub const MIB_IPFORWARD_ROW2 = extern struct {
        InterfaceLuid: NET_LUID,
        InterfaceIndex: u32,
        DestinationPrefix: IP_ADDRESS_PREFIX,
        NextHop: SOCKADDR_INET,
        SitePrefixLength: u8,
        ValidLifetime: u32,
        PreferredLifetime: u32,
        Metric: u32,
        Protocol: c_int,
        Loopback: u8,
        AutoconfigureAddress: u8,
        Publish: u8,
        Immortal: u8,
        Age: u32,
        Origin: c_int,
    };

    pub const MIB_IPINTERFACE_ROW = extern struct {
        Family: u16,
        InterfaceLuid: NET_LUID,
        InterfaceIndex: u32,
        MaxReassemblySize: u32,
        InterfaceIdentifier: u64,
        MinRouterAdvertisementInterval: u32,
        MaxRouterAdvertisementInterval: u32,
        AdvertisingEnabled: u8,
        ForwardingEnabled: u8,
        WeakHostSend: u8,
        WeakHostReceive: u8,
        UseAutomaticMetric: u8,
        UseNeighborUnreachabilityDetection: u8,
        ManagedAddressConfigurationSupported: u8,
        OtherStatefulConfigurationSupported: u8,
        AdvertiseDefaultRoute: u8,
        RouterDiscoveryBehavior: c_int,
        DadTransmits: u32,
        BaseReachableTime: u32,
        RetransmitTime: u32,
        PathMtuDiscoveryTimeout: u32,
        LinkLocalAddressBehavior: c_int,
        LinkLocalAddressTimeout: u32,
        ZoneIndices: [16]u32,
        SitePrefixLength: u32,
        Metric: u32,
        NlMtu: u32,
        Connected: u8,
        SupportsWakeUpPatterns: u8,
        SupportsNeighborDiscovery: u8,
        SupportsRouterDiscovery: u8,
        ReachableTime: u32,
        TransmitOffload: u8,
        ReceiveOffload: u8,
        DisableDefaultRoutes: u8,
    };

    comptime {
        // Sizes from the Windows SDK (x64 and arm64 share them).
        std.debug.assert(@sizeOf(SOCKADDR_INET) == 28);
        std.debug.assert(@sizeOf(MIB_UNICASTIPADDRESS_ROW) == 80);
        std.debug.assert(@offsetOf(MIB_UNICASTIPADDRESS_ROW, "InterfaceLuid") == 32);
        std.debug.assert(@sizeOf(MIB_IPFORWARD_ROW2) == 104);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "NextHop") == 44);
        std.debug.assert(@offsetOf(MIB_IPFORWARD_ROW2, "Metric") == 84);
        std.debug.assert(@sizeOf(MIB_IPINTERFACE_ROW) == 168);
        std.debug.assert(@offsetOf(MIB_IPINTERFACE_ROW, "NlMtu") == 152);
    }

    pub extern "iphlpapi" fn InitializeUnicastIpAddressEntry(row: *MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) void;
    pub extern "iphlpapi" fn CreateUnicastIpAddressEntry(row: *const MIB_UNICASTIPADDRESS_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn InitializeIpForwardEntry(row: *MIB_IPFORWARD_ROW2) callconv(.winapi) void;
    pub extern "iphlpapi" fn CreateIpForwardEntry2(row: *const MIB_IPFORWARD_ROW2) callconv(.winapi) u32;
    pub extern "iphlpapi" fn InitializeIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(.winapi) void;
    pub extern "iphlpapi" fn GetIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(.winapi) u32;
    pub extern "iphlpapi" fn SetIpInterfaceEntry(row: *MIB_IPINTERFACE_ROW) callconv(.winapi) u32;
};

test "adapter guid is stable, versioned and name-dependent" {
    const a = adapterGuid("wg0");
    try std.testing.expectEqual(a, adapterGuid("wg0"));
    try std.testing.expect(!std.meta.eql(a, adapterGuid("wg1")));
    try std.testing.expectEqual(@as(u8, 0x40), a.bytes[7] & 0xf0);
    try std.testing.expectEqual(@as(u8, 0x80), a.bytes[8] & 0xc0);
}

test "elevation check runs without privileges" {
    _ = isElevated(); // either answer is fine; it must not crash
}

test "wintun.dll probe (skipped when the DLL is not installed)" {
    const version = probe() catch |e| switch (e) {
        error.WintunNotFound => return error.SkipZigTest,
        error.WintunIncompatible => return e,
    };
    _ = version;
}

test "open refuses cleanly when not elevated" {
    if (isElevated()) return error.SkipZigTest; // would really create an adapter
    try std.testing.expectError(error.AccessDenied, Wintun.open("zwg-test", .{}));
}
