//! Wire layouts of the three handshake messages (wireguard.com/protocol).
//!
//! Every struct is `extern` with byte-array fields only, so it has alignment 1
//! and can be viewed directly over any received buffer; multi-byte integers
//! are little-endian on the wire and go through the accessors. The first four
//! bytes are a little-endian u32 message type, i.e. type byte + 3 zero bytes;
//! like the kernel and wireguard-go we compare all four, so non-zero reserved
//! bytes make a message unrecognised. Lengths must match exactly.
const std = @import("std");
const crypto = @import("../crypto.zig");

pub const MessageType = enum(u32) {
    initiation = 1,
    response = 2,
    cookie_reply = 3,
    /// Transport data (owned by session); listed so the device can dispatch.
    transport = 4,
};

pub const ParseError = error{ WrongLength, WrongType };

/// Smallest transport message: 16-byte header + 16-byte tag (keepalive).
pub const transport_min_len = 32;

/// Classify a received datagram by its 4-byte header and length, as the
/// kernel's receive path does. Returns null for anything that is not a
/// well-formed WireGuard message shape (drop it).
pub fn messageType(bytes: []const u8) ?MessageType {
    if (bytes.len < 4) return null;
    const t = std.mem.readInt(u32, bytes[0..4], .little);
    return switch (t) {
        1 => if (bytes.len == Initiation.size) .initiation else null,
        2 => if (bytes.len == Response.size) .response else null,
        3 => if (bytes.len == CookieReply.size) .cookie_reply else null,
        4 => if (bytes.len >= transport_min_len) .transport else null,
        else => null,
    };
}

fn makeHeader(t: MessageType) [4]u8 {
    var h: [4]u8 = undefined;
    std.mem.writeInt(u32, &h, @backingInt(t), .little);
    return h;
}

fn parseAs(comptime T: type, bytes: []const u8) ParseError!*const T {
    if (bytes.len != T.size) return error.WrongLength;
    if (std.mem.readInt(u32, bytes[0..4], .little) != @backingInt(T.message_type)) return error.WrongType;
    return @ptrCast(bytes.ptr);
}

/// Message 1: initiator -> responder, 148 bytes.
pub const Initiation = extern struct {
    header: [4]u8 = makeHeader(.initiation),
    sender: [4]u8,
    ephemeral: [32]u8,
    encrypted_static: [32 + crypto.tag_len]u8,
    encrypted_timestamp: [crypto.tai64n_len + crypto.tag_len]u8,
    mac1: [16]u8,
    mac2: [16]u8,

    pub const size = 148;
    pub const message_type: MessageType = .initiation;
    comptime {
        std.debug.assert(@sizeOf(Initiation) == size);
        std.debug.assert(@alignOf(Initiation) == 1);
        std.debug.assert(@offsetOf(Initiation, "mac1") == size - 32);
    }

    pub fn senderIndex(m: *const Initiation) u32 {
        return std.mem.readInt(u32, &m.sender, .little);
    }
    pub fn asBytes(m: *const Initiation) *const [size]u8 {
        return @ptrCast(m);
    }
    /// View `bytes` (exactly 148, header 1,0,0,0) as an Initiation, no copy.
    pub fn parse(bytes: []const u8) ParseError!*const Initiation {
        return parseAs(Initiation, bytes);
    }
};

/// Message 2: responder -> initiator, 92 bytes.
pub const Response = extern struct {
    header: [4]u8 = makeHeader(.response),
    sender: [4]u8,
    receiver: [4]u8,
    ephemeral: [32]u8,
    encrypted_nothing: [crypto.tag_len]u8,
    mac1: [16]u8,
    mac2: [16]u8,

    pub const size = 92;
    pub const message_type: MessageType = .response;
    comptime {
        std.debug.assert(@sizeOf(Response) == size);
        std.debug.assert(@alignOf(Response) == 1);
        std.debug.assert(@offsetOf(Response, "mac1") == size - 32);
    }

    pub fn senderIndex(m: *const Response) u32 {
        return std.mem.readInt(u32, &m.sender, .little);
    }
    pub fn receiverIndex(m: *const Response) u32 {
        return std.mem.readInt(u32, &m.receiver, .little);
    }
    pub fn asBytes(m: *const Response) *const [size]u8 {
        return @ptrCast(m);
    }
    pub fn parse(bytes: []const u8) ParseError!*const Response {
        return parseAs(Response, bytes);
    }
};

/// Message 3: cookie reply to an initiation or response sent under load, 64 bytes.
pub const CookieReply = extern struct {
    header: [4]u8 = makeHeader(.cookie_reply),
    receiver: [4]u8,
    nonce: [crypto.xnonce_len]u8,
    encrypted_cookie: [16 + crypto.tag_len]u8,

    pub const size = 64;
    pub const message_type: MessageType = .cookie_reply;
    comptime {
        std.debug.assert(@sizeOf(CookieReply) == size);
        std.debug.assert(@alignOf(CookieReply) == 1);
    }

    pub fn receiverIndex(m: *const CookieReply) u32 {
        return std.mem.readInt(u32, &m.receiver, .little);
    }
    pub fn asBytes(m: *const CookieReply) *const [size]u8 {
        return @ptrCast(m);
    }
    pub fn parse(bytes: []const u8) ParseError!*const CookieReply {
        return parseAs(CookieReply, bytes);
    }
};

pub fn writeIndex(dst: *[4]u8, index: u32) void {
    std.mem.writeInt(u32, dst, index, .little);
}

/// The sender index of a handshake message (initiation or response): where a
/// cookie reply to it must be addressed. Assumes `bytes` passed `messageType`.
pub fn handshakeSenderIndex(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[4..8], .little);
}

/// Offsets of mac1/mac2 for a handshake message of length `len` (148 or 92).
pub fn mac1Offset(len: usize) usize {
    return len - 32;
}
pub fn mac2Offset(len: usize) usize {
    return len - 16;
}

test "message type classification" {
    var buf: [200]u8 = @splat(0);
    buf[0] = 1;
    try std.testing.expectEqual(MessageType.initiation, messageType(buf[0..148]).?);
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..147]));
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..149]));
    buf[0] = 2;
    try std.testing.expectEqual(MessageType.response, messageType(buf[0..92]).?);
    buf[0] = 3;
    try std.testing.expectEqual(MessageType.cookie_reply, messageType(buf[0..64]).?);
    buf[0] = 4;
    try std.testing.expectEqual(MessageType.transport, messageType(buf[0..32]).?);
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..31]));
    buf[0] = 1;
    buf[3] = 1; // reserved byte set
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..148]));
    try std.testing.expectError(error.WrongType, Initiation.parse(buf[0..148]));
    buf[3] = 0;
    buf[0] = 5;
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..148]));
    try std.testing.expectEqual(@as(?MessageType, null), messageType(buf[0..3]));
    buf[0] = 1;
    try std.testing.expectError(error.WrongLength, Initiation.parse(buf[0..92]));
    // Unaligned view.
    var odd: [149]u8 = @splat(0);
    odd[1] = 1;
    odd[5] = 0x78;
    const m = try Initiation.parse(odd[1..149]);
    try std.testing.expectEqual(@as(u32, 0x78), m.senderIndex());
}
