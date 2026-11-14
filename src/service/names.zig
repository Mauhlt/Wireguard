//! Tunnel names and everything derived from them: the service name, the
//! control pipe name and the stored-configuration paths. Pure (no I/O), so
//! the rules are testable on any OS.

const std = @import("std");

/// As WireGuard for Windows: 1-32 characters from [A-Za-z0-9_=+.-]. The name
/// becomes a service name, a pipe name, a directory name and the adapter
/// name, so nothing that could mean something to any of those (path
/// separators, spaces, quotes, `$`, `%`) is allowed.
pub const max_name_len = 32;

pub const service_prefix = "zwgTunnel$";
pub const pipe_prefix = "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\zwg\\";
pub const max_service_name = service_prefix.len + max_name_len;
pub const max_pipe_name = pipe_prefix.len + max_name_len;

/// Device names DOS still reserves in every directory (a file "CON.conf"
/// would not be a file).
const reserved = [_][]const u8{
    "CON",  "PRN",  "AUX",  "NUL",  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
};

pub fn isValid(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    for (name) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '=', '+', '.', '-' => {},
        else => return false,
    };
    // Windows strips trailing dots from file names; a leading dot would
    // allow "." and "..".
    if (name[0] == '.' or name[name.len - 1] == '.') return false;
    const stem = if (std.mem.findScalar(u8, name, '.')) |i| name[0..i] else name;
    for (reserved) |r| if (std.ascii.eqlIgnoreCase(stem, r)) return false;
    return true;
}

/// "C:\tunnels\laptop.conf" -> "laptop" (as wg-quick and WireGuard for
/// Windows name tunnels); a bare name stays as it is.
pub fn fromPath(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    return if (std.ascii.endsWithIgnoreCase(base, ".conf")) base[0 .. base.len - 5] else base;
}

/// Does `zwg show <arg>` mean a .conf file (old behaviour) or an installed
/// tunnel? A file path ends in ".conf" or has a directory part.
pub fn looksLikeFile(arg: []const u8) bool {
    if (std.ascii.endsWithIgnoreCase(arg, ".conf")) return true;
    return std.mem.findAny(u8, arg, "/\\:") != null;
}

pub fn serviceName(buf: *[max_service_name]u8, name: []const u8) []const u8 {
    std.debug.assert(isValid(name));
    @memcpy(buf[0..service_prefix.len], service_prefix);
    @memcpy(buf[service_prefix.len..][0..name.len], name);
    return buf[0 .. service_prefix.len + name.len];
}

/// The tunnel name of a service name, or null if it is not one of ours.
pub fn fromServiceName(service: []const u8) ?[]const u8 {
    if (service.len <= service_prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(service[0..service_prefix.len], service_prefix)) return null;
    const name = service[service_prefix.len..];
    return if (isValid(name)) name else null;
}

/// `\\.\pipe\ProtectedPrefix\Administrators\zwg\<name>`: only a process in
/// the Administrators group (or SYSTEM) can create a pipe under
/// ProtectedPrefix\Administrators, so an unprivileged process cannot squat
/// the name before the service starts and impersonate it to `zwg show`.
pub fn pipeName(buf: *[max_pipe_name]u8, name: []const u8) []const u8 {
    std.debug.assert(isValid(name));
    @memcpy(buf[0..pipe_prefix.len], pipe_prefix);
    @memcpy(buf[pipe_prefix.len..][0..name.len], name);
    return buf[0 .. pipe_prefix.len + name.len];
}

/// A Windows SID string as the installer passes it on: "S-1-" then dash
/// separated decimal numbers. Strict, because it is spliced into SDDL.
pub fn isValidSidString(s: []const u8) bool {
    if (s.len < 5 or s.len > 184) return false;
    if (!std.mem.startsWith(u8, s, "S-1-")) return false;
    var parts: usize = 0;
    var it = std.mem.splitScalar(u8, s[4..], '-');
    while (it.next()) |p| {
        if (p.len == 0 or p.len > 10) return false;
        for (p) |c| if (c < '0' or c > '9') return false;
        parts += 1;
    }
    // Identifier authority + 1..15 sub-authorities.
    return parts >= 2 and parts <= 16;
}

/// A SID string naming a user *account* (the installing user the pipe and
/// service DACLs grant access to), not a group, alias or well-known
/// principal: syntactically valid (`isValidSidString`) and either a
/// local / domain account, S-1-5-21-<3 domain sub-authorities>-<RID>, or
/// an Entra ID (Azure AD) account, S-1-12-1-<4 sub-authorities>. So
/// "S-1-1-0" (Everyone), "S-1-5-11" (Authenticated Users), "S-1-5-32-545"
/// (Users) or "S-1-5-18" (SYSTEM) are refused even though they parse. The
/// elevated installer additionally asks Windows that the SID is a user
/// (LookupAccountSidW: SidTypeUser).
pub fn isAccountSidString(s: []const u8) bool {
    if (!isValidSidString(s)) return false;
    const prefixes = [_]struct { prefix: []const u8, rest: usize }{
        .{ .prefix = "S-1-5-21-", .rest = 4 },
        .{ .prefix = "S-1-12-1-", .rest = 4 },
    };
    for (prefixes) |p| if (std.mem.startsWith(u8, s, p.prefix)) {
        return std.mem.countScalar(u8, s[p.prefix.len..], '-') + 1 == p.rest;
    };
    return false;
}

test "tunnel names" {
    const t = std.testing;
    for ([_][]const u8{ "wg0", "laptop", "Home-VPN_2", "a", "x=y+z", "a.b", "con1", "CONx" }) |n| try t.expect(isValid(n));
    for ([_][]const u8{
        "",                                  "a b",      "a/b", "a\\b", "a:b", "a$b", "a%b", "\"a\"", "a\x00",
        "123456789012345678901234567890123", ".",        "..",  ".a",   "a.",  "CON", "con", "nul.x", "COM1",
        "lpt9",                              "\xc3\xa9",
    }) |n| try t.expect(!isValid(n));
    try t.expectEqualStrings("laptop", fromPath("C:\\tunnels\\laptop.conf"));
    try t.expectEqualStrings("laptop", fromPath("laptop.CONF"));
    try t.expectEqualStrings("wg0", fromPath("wg0"));
    try t.expect(looksLikeFile("x.conf"));
    try t.expect(looksLikeFile(".\\x"));
    try t.expect(looksLikeFile("C:x"));
    try t.expect(!looksLikeFile("laptop"));
}

test "service and pipe names" {
    const t = std.testing;
    var sb: [max_service_name]u8 = undefined;
    try t.expectEqualStrings("zwgTunnel$laptop", serviceName(&sb, "laptop"));
    try t.expectEqualStrings("laptop", fromServiceName("zwgTunnel$laptop").?);
    try t.expectEqualStrings("laptop", fromServiceName("ZWGTUNNEL$laptop").?);
    try t.expectEqual(@as(?[]const u8, null), fromServiceName("zwgTunnel$"));
    try t.expectEqual(@as(?[]const u8, null), fromServiceName("WireGuardTunnel$laptop"));
    try t.expectEqual(@as(?[]const u8, null), fromServiceName("zwgTunnel$a b"));
    var pb: [max_pipe_name]u8 = undefined;
    try t.expectEqualStrings("\\\\.\\pipe\\ProtectedPrefix\\Administrators\\zwg\\laptop", pipeName(&pb, "laptop"));
}

test "SID strings" {
    const t = std.testing;
    try t.expect(isValidSidString("S-1-5-18"));
    try t.expect(isValidSidString("S-1-5-21-1004336348-1177238915-682003330-1001"));
    for ([_][]const u8{
        "",                        "S-1-",      "S-1-5",   "S-1-5-",    "S-1-5--1",          "S-2-5-18",                                     "s-1-5-18",
        "S-1-5-21-1)(A;;GA;;;WD)", "S-1-5-18;", "S-1-5-x", "S-1-5-18 ", "S-1-5-12345678901", "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    }) |s| try t.expect(!isValidSidString(s));
}

test "account SIDs only: users, not groups or well-known principals" {
    const t = std.testing;
    for ([_][]const u8{
        "S-1-5-21-1004336348-1177238915-682003330-1001",
        "S-1-5-21-1-2-3-500",
        "S-1-12-1-1234567890-1234567890-1234567890-1234567890",
    }) |s| try t.expect(isAccountSidString(s));
    for ([_][]const u8{
        "S-1-1-0", // Everyone
        "S-1-5-11", // Authenticated Users
        "S-1-5-4", // Interactive
        "S-1-5-18", // SYSTEM
        "S-1-5-32-544", // Administrators
        "S-1-5-32-545", // Users
        "S-1-5-21-1-2-3", // a domain, no RID
        "S-1-5-21-1-2-3-4-5",
        "S-1-12-1-1-2-3",
        "S-1-5-21-1-2-3-1001)(A;;GA;;;WD)",
        "S-1-5-21-",
        "",
    }) |s| try t.expect(!isAccountSidString(s));
}
