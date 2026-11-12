//! Types shared by the OS backends (windows.zig, posix.zig).
const std = @import("std");

pub const Family = enum { v4, v6 };

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
