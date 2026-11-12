//! tun module: the device's packet interface to the OS. Contract: DESIGN.md.
//!
//! Every backend moves raw IP packets (IPv4 or IPv6, no link header, no
//! protocol-info prefix) and exposes a `WaitHandle` so the device's single
//! event loop can sleep on {UDP sockets, TUN, next timer deadline} at once.
//!
//! Reading protocol (identical for every backend, including FakeTun):
//!   1. wait until `waitHandle()` is ready (or something else woke the loop);
//!   2. call `read(buf)` until it returns null;
//!   3. go back to waiting.
//! Spurious wakeups are allowed. The handle is owned by the Tun: never read
//! from it, reset it or close it.
//!
//! Writing never blocks: when the OS ring/queue is full the packet is dropped
//! and `error.QueueFull` is returned (same as a NIC dropping on overrun; the
//! device should count it and carry on).
//!
//! Backends:
//!   * windows: Wintun (`windows.zig`), wintun.dll loaded at runtime.
//!   * linux:   /dev/net/tun, IFF_TUN | IFF_NO_PI (`linux.zig`).
//!   * macos:   utun via PF_SYSTEM / SYSPROTO_CONTROL (`darwin.zig`).
//!   * ios:     NEPacketTunnelProvider.packetFlow adapter (`ios.zig`).
//!   * tests:   `FakeTun` (in-memory, any OS).
const std = @import("std");
const builtin = @import("builtin");

pub const Cidr = @import("cidr.zig").Cidr;
pub const queue = @import("queue.zig");
pub const FakeTun = @import("fake.zig").FakeTun;

/// What the event loop waits on. Windows: a waitable HANDLE (use
/// WaitForMultipleObjects). Elsewhere: a file descriptor that polls readable
/// (POLLIN / EVFILT_READ).
pub const WaitHandle = if (builtin.os.tag == .windows) std.os.windows.HANDLE else std.posix.fd_t;

/// Largest IP packet any backend hands out (IPv4/IPv6 total-length limit).
pub const max_packet_size = 65535;

/// MTU used when the configuration does not say (same as wg-quick / WireGuard
/// for Windows: 1500 - 80 bytes of IPv6 + UDP + WireGuard overhead).
pub const default_mtu = 1420;

pub const ReadError = error{
    /// The packet did not fit in the caller's buffer and was dropped. Use a
    /// buffer of at least `mtu()` bytes (or `max_packet_size`).
    BufferTooSmall,
    /// The adapter went away (driver unloaded, interface deleted, closed).
    Closed,
    Unexpected,
};

pub const WriteError = error{
    /// The OS queue is full; the packet was dropped.
    QueueFull,
    /// Larger than the MTU / backend limit; dropped.
    PacketTooLarge,
    /// Not an IPv4/IPv6 packet (backends that must tag the family).
    InvalidPacket,
    Closed,
    Unexpected,
};

pub const ConfigError = error{
    /// The calling process lacks the privilege (Windows: not elevated;
    /// Unix: no CAP_NET_ADMIN / not root).
    AccessDenied,
    /// The platform configures addresses elsewhere (iOS: NEPacketTunnelNetworkSettings).
    Unsupported,
    Closed,
    Unexpected,
};

/// Type-erased handle the device holds; every backend provides `tun()`.
pub const Tun = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        waitHandle: *const fn (ptr: *anyopaque) WaitHandle,
        read: *const fn (ptr: *anyopaque, buf: []u8) ReadError!?[]u8,
        write: *const fn (ptr: *anyopaque, packet: []const u8) WriteError!void,
        mtu: *const fn (ptr: *anyopaque) u16,
        setAddress: *const fn (ptr: *anyopaque, cidr: Cidr) ConfigError!void,
        addRoute: *const fn (ptr: *anyopaque, cidr: Cidr) ConfigError!void,
    };

    /// Ready when packets may be available to `read`.
    pub fn waitHandle(t: Tun) WaitHandle {
        return t.vtable.waitHandle(t.ptr);
    }

    /// Next packet from the OS (outbound traffic to encrypt), copied into
    /// `buf`; null when there is none right now. Never blocks.
    pub fn read(t: Tun, buf: []u8) ReadError!?[]u8 {
        return t.vtable.read(t.ptr, buf);
    }

    /// Hand a decrypted packet to the OS. Never blocks.
    pub fn write(t: Tun, packet: []const u8) WriteError!void {
        return t.vtable.write(t.ptr, packet);
    }

    pub fn mtu(t: Tun) u16 {
        return t.vtable.mtu(t.ptr);
    }

    /// Assign an interface address ("10.0.0.2/24"), like `Address =` in a .conf.
    pub fn setAddress(t: Tun, cidr: Cidr) ConfigError!void {
        return t.vtable.setAddress(t.ptr, cidr);
    }

    /// Route a prefix into the tunnel (one call per AllowedIPs entry).
    pub fn addRoute(t: Tun, cidr: Cidr) ConfigError!void {
        return t.vtable.addRoute(t.ptr, cidr);
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("cidr.zig");
    _ = @import("queue.zig");
    _ = @import("fake.zig");
}
