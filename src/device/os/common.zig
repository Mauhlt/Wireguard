//! Types shared by the OS backends (windows.zig, posix.zig).
const std = @import("std");

pub const Family = enum { v4, v6 };

/// Where a UDP socket listens: every interface (a real endpoint), or
/// loopback only (unit tests, and the `--tun udp:<port>` test mode, so
/// neither ever opens the machine to the network nor raises a Windows
/// Firewall prompt for a freshly built executable).
pub const Scope = enum {
    any,
    loopback,

    /// What `Udp.open` uses: loopback in unit tests, every interface otherwise.
    pub const default: Scope = if (@import("builtin").is_test) .loopback else .any;
};

pub const Datagram = struct {
    len: usize,
    from: std.Io.net.IpAddress,
};

pub const OpenError = error{
    AddressInUse,
    AccessDenied,
    AddressFamilyUnsupported,
    SystemResources,
    Unexpected,
};

pub const RecvError = error{Unexpected};

pub const SendError = error{
    /// Socket buffer full: the datagram was dropped (UDP semantics).
    WouldBlock,
    /// No route to the destination right now.
    Unreachable,
    MessageTooBig,
    AddressFamilyMismatch,
    Unexpected,
};

pub const WaitError = error{Unexpected};

pub const StopError = error{ AlreadyRunning, NotRunning, NameTooLong, Unexpected, Unsupported };
