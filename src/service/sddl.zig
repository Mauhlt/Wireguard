//! The security descriptors the tunnel service uses, as SDDL strings built
//! here (pure, testable anywhere) and parsed by Windows at the point of use.
//!
//!   store directory  SYSTEM + Administrators full control, protected (no
//!                    inherited ACEs from %ProgramData%, whose default ACL
//!                    lets Users create and read files), inherited by
//!                    everything below: tunnels\<name>\tunnel.conf.dpapi,
//!                    the service's copy of zwg.exe / wintun.dll, logs.
//!   control pipe     SYSTEM + Administrators full control; the installing
//!                    user read + write data only (not FILE_CREATE_PIPE_INSTANCE,
//!                    WRITE_DAC, ...). Nobody else, no network clients
//!                    (PIPE_REJECT_REMOTE_CLIENTS) and, with no mandatory
//!                    label, no writes from below medium integrity.
//!   service object   Windows' default service DACL plus the installing user:
//!                    query status/config, start, stop, interrogate. That is
//!                    what makes `zwg down <name>` (and `sc start`) work
//!                    unelevated for that user, and only that user.

const std = @import("std");
const names = @import("names.zig");

/// O:BA owner Administrators; P = protected; OICI = inherited by files and
/// subdirectories; FA = FILE_ALL_ACCESS.
pub const store_dir = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE.
/// Deliberately not FILE_APPEND_DATA: on a pipe that bit is
/// FILE_CREATE_PIPE_INSTANCE, which would let the user add server instances.
pub const pipe_user_access: u32 = 0x0001 | 0x0002 | 0x0080 | 0x0002_0000 | 0x0010_0000;

/// SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP |
/// SERVICE_INTERROGATE | READ_CONTROL. Not CHANGE_CONFIG, DELETE, WRITE_DAC:
/// the user can stop and start the tunnel, not change what runs as SYSTEM.
pub const service_user_access: u32 = 0x0001 | 0x0004 | 0x0010 | 0x0020 | 0x0080 | 0x0002_0000;

/// Windows' default DACL for a new service (as `sc sdshow` prints it for
/// one created by CreateServiceW): SYSTEM, Administrators, interactive and
/// service logons may query; only SYSTEM and Administrators control.
pub const service_default_aces =
    "(A;;CCLCSWRPWPDTLOCRRC;;;SY)" ++
    "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" ++
    "(A;;CCLCSWLOCRRC;;;IU)" ++
    "(A;;CCLCSWLOCRRC;;;SU)";

pub const Error = error{ InvalidSid, NoSpaceLeft };

/// Control pipe DACL for `user_sid` (validated: it is spliced into SDDL).
pub fn pipe(buf: []u8, user_sid: []const u8) Error![]const u8 {
    if (!names.isValidSidString(user_sid)) return error.InvalidSid;
    return std.fmt.bufPrint(buf, "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{x};;;{s})", .{ pipe_user_access, user_sid });
}

/// Service object DACL for `user_sid`.
pub fn service(buf: []u8, user_sid: []const u8) Error![]const u8 {
    if (!names.isValidSidString(user_sid)) return error.InvalidSid;
    return std.fmt.bufPrint(buf, "D:" ++ service_default_aces ++ "(A;;0x{x};;;{s})", .{ service_user_access, user_sid });
}

const user = "S-1-5-21-1004336348-1177238915-682003330-1001";

test "pipe and service SDDL strings" {
    const t = std.testing;
    var buf: [512]u8 = undefined;
    try t.expectEqualStrings(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;" ++ user ++ ")",
        try pipe(&buf, user),
    );
    const s = try service(&buf, user);
    try t.expect(std.mem.endsWith(u8, s, "(A;;0x200b5;;;" ++ user ++ ")"));
    try t.expect(std.mem.startsWith(u8, s, "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"));
    // Anything that is not a plain SID is refused, never spliced.
    try t.expectError(error.InvalidSid, pipe(&buf, "S-1-5-21-1)(A;;GA;;;WD"));
    try t.expectError(error.InvalidSid, pipe(&buf, "WD"));
    try t.expectError(error.InvalidSid, service(&buf, "S-1-1-0)(A;;GA;;;WD"));
    try t.expectError(error.NoSpaceLeft, pipe(buf[0..20], user));
}

// What Windows makes of them: parse each with the real SDDL parser and check
// owner, protection and every ACE (type, flags, mask, SID).
const builtin = @import("builtin");

const Ace = struct { flags: u8, mask: u32, sid: []const u8 };

fn expectAces(sddl: []const u8, protected: bool, want: []const Ace) !void {
    const win = @import("win32.zig");
    var sd = try win.SecurityDescriptor.fromSddl(sddl);
    defer sd.deinit();
    var control: u16 = 0;
    var rev: u32 = 0;
    try std.testing.expect(win.GetSecurityDescriptorControl(sd.sd, &control, &rev) != 0);
    try std.testing.expectEqual(protected, control & win.SE_DACL_PROTECTED != 0);
    const acl = sd.dacl() orelse return error.NoDacl;
    try std.testing.expectEqual(want.len, acl.ace_count);
    for (want, 0..) |w, i| {
        var p: ?*anyopaque = null;
        try std.testing.expect(win.GetAce(acl, @intCast(i), &p) != 0);
        const ace: *const win.ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(p.?));
        try std.testing.expectEqual(win.ACCESS_ALLOWED_ACE_TYPE, ace.header.kind);
        try std.testing.expectEqual(w.flags, ace.header.flags);
        try std.testing.expectEqual(w.mask, ace.mask);
        var wsid: [128]u16 = undefined;
        var expect_sid: ?win.PSID = null;
        try std.testing.expect(win.ConvertStringSidToSidW((try win.W(&wsid, w.sid)).ptr, &expect_sid) != 0);
        defer _ = win.LocalFree(expect_sid);
        try std.testing.expect(win.EqualSid(@ptrCast(@constCast(&ace.sid_start)), expect_sid.?) != 0);
    }
}

test "Windows parses the store directory DACL as intended" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const oici = 0x1 | 0x2;
    try expectAces(store_dir, true, &.{
        .{ .flags = oici, .mask = 0x1F01FF, .sid = "S-1-5-18" }, // FILE_ALL_ACCESS
        .{ .flags = oici, .mask = 0x1F01FF, .sid = "S-1-5-32-544" },
    });
}

test "Windows parses the pipe DACL as intended" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    var buf: [512]u8 = undefined;
    // GA stays GENERIC_ALL in the descriptor (mapped when the pipe applies it).
    try expectAces(try pipe(&buf, user), true, &.{
        .{ .flags = 0, .mask = 0x1000_0000, .sid = "S-1-5-18" },
        .{ .flags = 0, .mask = 0x1000_0000, .sid = "S-1-5-32-544" },
        .{ .flags = 0, .mask = 0x0012_0083, .sid = user },
    });
    // The user's ACE grants neither FILE_CREATE_PIPE_INSTANCE nor any WRITE_DAC/OWNER/DELETE.
    try std.testing.expectEqual(@as(u32, 0), pipe_user_access & (0x0004 | 0x0004_0000 | 0x0008_0000 | 0x0001_0000));
}

test "Windows parses the service DACL as intended" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    var buf: [512]u8 = undefined;
    try expectAces(try service(&buf, user), false, &.{
        .{ .flags = 0, .mask = 0x0002_01FD, .sid = "S-1-5-18" },
        .{ .flags = 0, .mask = 0x000F_01FF, .sid = "S-1-5-32-544" },
        .{ .flags = 0, .mask = 0x0002_018D, .sid = "S-1-5-4" },
        .{ .flags = 0, .mask = 0x0002_018D, .sid = "S-1-5-6" },
        .{ .flags = 0, .mask = 0x0002_00B5, .sid = user },
    });
}
