//! Where an installed tunnel lives on disk, and how its configuration is
//! protected (Windows only).
//!
//!   %ProgramData%\zwg\                         protected DACL: SYSTEM + Administrators only
//!     tunnels\<name>\tunnel.conf.dpapi         the .conf, DPAPI (machine scope) encrypted
//!     tunnels\<name>\zwg.exe, wintun.dll       what the service runs (copied at install)
//!     logs\<name>.log                          bounded service log, never keys
//!
//! Two layers for the private key: the directory ACL is the access control
//! (no user process can open the file), DPAPI with CRYPTPROTECT_LOCAL_MACHINE
//! is defence in depth: a copy of the file (backup, disk image without the
//! machine's LSA secrets, another OS) is ciphertext. Machine scope rather
//! than user scope because the installer runs as the (elevated) user and the
//! service as SYSTEM; both must decrypt, and the ACL already decides who may
//! read the file at all.
//!
//! The service's binary is copied into the same protected tree, so the
//! LocalSystem service never runs an executable a non-admin user could
//! replace (zig-out\bin is user-writable).
//!
//! %ProgramData% comes from SHGetKnownFolderPath, never the environment
//! (a user can set %ProgramData% for their own elevated processes).
//! %ProgramData% lets Users create subdirectories, so a pre-existing
//! %ProgramData%\zwg is used only if it is a real directory (not a junction
//! or symlink) owned by SYSTEM or Administrators; its DACL is then reset.

const std = @import("std");
const win = @import("win32.zig");
const names = @import("names.zig");
const sddl = @import("sddl.zig");

pub const conf_file = "tunnel.conf.dpapi";
pub const exe_file = "zwg.exe";
pub const wintun_file = "wintun.dll";
pub const max_log_bytes = 1 << 20;
const max_binary_bytes = 64 << 20;

/// DPAPI's optional entropy: binds the blob to this purpose (another
/// program's machine-scope blob cannot be swapped in and decrypt as ours).
const entropy = "zwg tunnel configuration v1";

pub const Error = error{
    /// %ProgramData%\zwg exists but is a link or not owned by SYSTEM/Administrators.
    UntrustedDirectory,
    AccessDenied,
    NotFound,
    TooLarge,
    NameTooLong,
    ProtectFailed,
    Unexpected,
    OutOfMemory,
};

/// Absolute paths (UTF-8) for one tunnel. All derive from the
/// known-folder ProgramData path and a validated tunnel name.
pub const Paths = struct {
    /// Each path lives in its own buffer and is reached through a method,
    /// so a Paths can be copied (returned by value, wrapped in an optional)
    /// without its paths pointing into the copy it was built in.
    buf: [6][260]u8 = undefined,
    len: [6]usize = @splat(0),

    pub fn init(name: []const u8) Error!Paths {
        std.debug.assert(names.isValid(name));
        var pd_buf: [260]u8 = undefined;
        const pd = try programData(&pd_buf);
        var p: Paths = .{};
        try p.put(0, "{s}\\zwg", .{pd});
        try p.put(1, "{s}\\zwg\\tunnels", .{pd});
        try p.put(2, "{s}\\zwg\\tunnels\\{s}", .{ pd, name });
        try p.put(3, "{s}\\zwg\\tunnels\\{s}\\" ++ conf_file, .{ pd, name });
        try p.put(4, "{s}\\zwg\\logs", .{pd});
        try p.put(5, "{s}\\zwg\\logs\\{s}.log", .{ pd, name });
        return p;
    }

    /// %ProgramData%\zwg
    pub fn root(p: *const Paths) []const u8 {
        return p.get(0);
    }
    /// %ProgramData%\zwg\tunnels
    pub fn tunnels(p: *const Paths) []const u8 {
        return p.get(1);
    }
    /// %ProgramData%\zwg\tunnels\<name>
    pub fn dir(p: *const Paths) []const u8 {
        return p.get(2);
    }
    /// The encrypted configuration in dir().
    pub fn conf(p: *const Paths) []const u8 {
        return p.get(3);
    }
    /// %ProgramData%\zwg\logs
    pub fn logs(p: *const Paths) []const u8 {
        return p.get(4);
    }
    /// %ProgramData%\zwg\logs\<name>.log
    pub fn log(p: *const Paths) []const u8 {
        return p.get(5);
    }

    /// `<dir>\<file>` into `out`.
    pub fn inDir(p: *const Paths, out: []u8, file: []const u8) Error![]const u8 {
        return std.fmt.bufPrint(out, "{s}\\{s}", .{ p.dir(), file }) catch error.NameTooLong;
    }

    fn get(p: *const Paths, i: usize) []const u8 {
        return p.buf[i][0..p.len[i]];
    }

    fn put(p: *Paths, i: usize, comptime fmt: []const u8, args: anytype) Error!void {
        const s = std.fmt.bufPrint(&p.buf[i], fmt, args) catch return error.NameTooLong;
        p.len[i] = s.len;
    }
};

fn programData(buf: []u8) Error![]const u8 {
    var w: ?win.LPWSTR = null;
    if (win.SHGetKnownFolderPath(&win.FOLDERID_ProgramData, 0, null, &w) != 0) {
        win.CoTaskMemFree(w);
        return error.Unexpected;
    }
    defer win.CoTaskMemFree(w);
    const span = std.mem.span(w.?);
    const n = std.unicode.utf16LeToUtf8(buf, span) catch return error.NameTooLong;
    if (n > buf.len) return error.NameTooLong;
    return buf[0..n];
}

// ---- directories ---------------------------------------------------------------

/// Create every directory of `p` (root, tunnels, the tunnel's, logs) with
/// the protected DACL, or verify and re-secure them if they exist.
/// Needs an elevated process (owner = Administrators).
pub fn prepare(p: *const Paths) Error!void {
    try secureDir(p.root(), true);
    try secureDir(p.tunnels(), false);
    try secureDir(p.logs(), false);
    try secureDir(p.dir(), false);
}

fn secureDir(path: []const u8, is_root: bool) Error!void {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    var sd = win.SecurityDescriptor.fromSddl(sddl.store_dir) catch return error.Unexpected;
    defer sd.deinit();
    var sa = sd.attributes();
    if (win.CreateDirectoryW(w.ptr, &sa) != 0) return;
    switch (win.GetLastError()) {
        win.ERROR_ALREADY_EXISTS => {},
        win.ERROR_ACCESS_DENIED => return error.AccessDenied,
        else => return error.Unexpected,
    }
    const attrs = win.GetFileAttributesW(w.ptr);
    if (attrs == win.INVALID_FILE_ATTRIBUTES) return error.Unexpected;
    if (attrs & win.FILE_ATTRIBUTE_DIRECTORY == 0 or attrs & win.FILE_ATTRIBUTE_REPARSE_POINT != 0)
        return error.UntrustedDirectory;
    // Only the root can have been pre-created by a user (ProgramData lets
    // Users create folders); below it only administrators can create.
    if (is_root) try checkOwner(w);
    // Reset the DACL (protected: nothing inherited from ProgramData) and
    // the owner; inheritance carries it to everything inside.
    const acl = sd.dacl() orelse return error.Unexpected;
    var owner: ?win.PSID = null;
    var defaulted: win.BOOL = 0;
    if (win.GetSecurityDescriptorOwner(sd.sd, &owner, &defaulted) == 0) return error.Unexpected;
    const rc = win.SetNamedSecurityInfoW(
        w.ptr,
        win.SE_FILE_OBJECT,
        win.OWNER_SECURITY_INFORMATION | win.DACL_SECURITY_INFORMATION | win.PROTECTED_DACL_SECURITY_INFORMATION,
        owner,
        null,
        acl,
        null,
    );
    if (rc == win.ERROR_ACCESS_DENIED) return error.AccessDenied;
    if (rc != 0) return error.Unexpected;
}

fn checkOwner(w: [:0]const u16) Error!void {
    var owner: ?win.PSID = null;
    var sd: ?win.PSECURITY_DESCRIPTOR = null;
    const rc = win.GetNamedSecurityInfoW(w.ptr, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION, &owner, null, null, null, &sd);
    if (rc != 0) return error.Unexpected;
    defer _ = win.LocalFree(sd);
    const o = owner orelse return error.UntrustedDirectory;
    if (win.IsWellKnownSid(o, win.WinBuiltinAdministratorsSid) == 0 and win.IsWellKnownSid(o, win.WinLocalSystemSid) == 0)
        return error.UntrustedDirectory;
}

/// Remove the tunnel's directory (its files must be gone) and, if empty,
/// tunnels\, logs\ and the root. Best effort.
pub fn removeDirs(p: *const Paths) void {
    for ([_][]const u8{ p.dir(), p.tunnels(), p.logs(), p.root() }) |d| {
        var wbuf: [300]u16 = undefined;
        const w = win.W(&wbuf, d) catch continue;
        _ = win.RemoveDirectoryW(w.ptr);
    }
}

// ---- DPAPI ---------------------------------------------------------------------

/// Encrypt with machine-scope DPAPI. Caller frees the result.
pub fn protect(gpa: std.mem.Allocator, plain: []const u8) Error![]u8 {
    return dpapi(gpa, plain, true);
}

/// Decrypt a `protect` blob. Caller wipes and frees the result.
pub fn unprotect(gpa: std.mem.Allocator, blob: []const u8) Error![]u8 {
    return dpapi(gpa, blob, false);
}

fn dpapi(gpa: std.mem.Allocator, in: []const u8, encrypt: bool) Error![]u8 {
    if (in.len > std.math.maxInt(u32)) return error.TooLarge;
    const in_blob: win.DATA_BLOB = .{ .len = @intCast(in.len), .data = @constCast(in.ptr) };
    const ent: win.DATA_BLOB = .{ .len = entropy.len, .data = @constCast(entropy.ptr) };
    var out: win.DATA_BLOB = .{ .len = 0, .data = null };
    const flags = win.CRYPTPROTECT_UI_FORBIDDEN | win.CRYPTPROTECT_LOCAL_MACHINE;
    const ok = if (encrypt)
        win.CryptProtectData(&in_blob, std.unicode.utf8ToUtf16LeStringLiteral("zwg tunnel"), &ent, null, null, flags, &out)
    else
        win.CryptUnprotectData(&in_blob, null, &ent, null, null, win.CRYPTPROTECT_UI_FORBIDDEN, &out);
    if (ok == 0) return error.ProtectFailed;
    const data = out.data.?[0..out.len];
    defer {
        std.crypto.secureZero(u8, data);
        _ = win.LocalFree(out.data);
    }
    return gpa.dupe(u8, data);
}

// ---- files ---------------------------------------------------------------------

/// Write `data` to a new file `path` (an existing file is deleted first, so
/// the new one gets `security` or, if null, the protected directory's
/// inherited DACL — never a DACL left over from before).
pub fn writeNew(path: []const u8, data: []const u8, security: ?[]const u8) Error!void {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    _ = win.DeleteFileW(w.ptr);
    var sd: ?win.SecurityDescriptor = if (security) |s| win.SecurityDescriptor.fromSddl(s) catch return error.Unexpected else null;
    defer if (sd) |*s| s.deinit();
    var sa: ?win.SECURITY_ATTRIBUTES = if (sd) |*s| s.attributes() else null;
    const h = win.CreateFileW(w.ptr, win.GENERIC_WRITE, 0, if (sa) |*a| a else null, win.CREATE_NEW, win.FILE_ATTRIBUTE_NORMAL, null);
    if (h == win.INVALID_HANDLE_VALUE) return mapOpen(win.GetLastError());
    defer _ = win.CloseHandle(h);
    try writeAll(h, data);
    if (win.FlushFileBuffers(h) == 0) return error.Unexpected;
}

/// Read a whole file (at most `limit` bytes). Caller frees.
pub fn readAll(gpa: std.mem.Allocator, path: []const u8, limit: usize) Error![]u8 {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    const h = win.CreateFileW(w.ptr, win.GENERIC_READ, win.FILE_SHARE_READ, null, win.OPEN_EXISTING, win.FILE_ATTRIBUTE_NORMAL, null);
    if (h == win.INVALID_HANDLE_VALUE) return mapOpen(win.GetLastError());
    defer _ = win.CloseHandle(h);
    var size: i64 = 0;
    if (win.GetFileSizeEx(h, &size) == 0) return error.Unexpected;
    if (size < 0 or size > limit) return error.TooLarge;
    const buf = try gpa.alloc(u8, @intCast(size));
    errdefer gpa.free(buf);
    var got: usize = 0;
    while (got < buf.len) {
        var n: u32 = 0;
        const chunk: u32 = @intCast(@min(buf.len - got, 1 << 20));
        if (win.ReadFile(h, buf.ptr + got, chunk, &n, null) == 0) return error.Unexpected;
        if (n == 0) return error.Unexpected; // shrank under us
        got += n;
    }
    return buf;
}

/// Overwrite a file with zeros, then delete it. Missing = done.
pub fn wipe(path: []const u8) Error!void {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    const h = win.CreateFileW(w.ptr, win.GENERIC_WRITE | win.GENERIC_READ, 0, null, win.OPEN_EXISTING, win.FILE_ATTRIBUTE_NORMAL, null);
    if (h == win.INVALID_HANDLE_VALUE) {
        const e = win.GetLastError();
        if (e == win.ERROR_FILE_NOT_FOUND or e == win.ERROR_PATH_NOT_FOUND) return;
        return mapOpen(e);
    }
    {
        defer _ = win.CloseHandle(h);
        var size: i64 = 0;
        if (win.GetFileSizeEx(h, &size) == 0) return error.Unexpected;
        const zeros: [4096]u8 = @splat(0);
        var left: u64 = @intCast(@max(size, 0));
        while (left > 0) {
            const n: usize = @intCast(@min(left, zeros.len));
            try writeAll(h, zeros[0..n]);
            left -= n;
        }
        _ = win.FlushFileBuffers(h);
    }
    try delete(path);
}

pub fn delete(path: []const u8) Error!void {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    if (win.DeleteFileW(w.ptr) != 0) return;
    const e = win.GetLastError();
    if (e == win.ERROR_FILE_NOT_FOUND or e == win.ERROR_PATH_NOT_FOUND) return;
    return mapOpen(e);
}

pub fn exists(path: []const u8) bool {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return false;
    return win.GetFileAttributesW(w.ptr) != win.INVALID_FILE_ATTRIBUTES;
}

/// Copy a file (bounded) into the protected tree, as a new file.
pub fn copyInto(gpa: std.mem.Allocator, from: []const u8, to: []const u8) Error!void {
    const data = try readAll(gpa, from, max_binary_bytes);
    defer gpa.free(data);
    try writeNew(to, data, null);
}

fn writeAll(h: win.HANDLE, data: []const u8) Error!void {
    var off: usize = 0;
    while (off < data.len) {
        var n: u32 = 0;
        const chunk: u32 = @intCast(@min(data.len - off, 1 << 20));
        if (win.WriteFile(h, data.ptr + off, chunk, &n, null) == 0) return error.Unexpected;
        off += n;
    }
}

fn mapOpen(e: u32) Error {
    return switch (e) {
        win.ERROR_FILE_NOT_FOUND, win.ERROR_PATH_NOT_FOUND => error.NotFound,
        win.ERROR_ACCESS_DENIED => error.AccessDenied,
        else => error.Unexpected,
    };
}

// ---- the stored configuration ----------------------------------------------------

/// Encrypt and store the configuration text (the caller wipes `text`).
pub fn storeConfig(gpa: std.mem.Allocator, p: *const Paths, text: []const u8) Error!void {
    const blob = try protect(gpa, text);
    defer gpa.free(blob);
    try writeNew(p.conf(), blob, null);
}

/// Read and decrypt the stored configuration. Caller wipes and frees.
pub fn loadConfig(gpa: std.mem.Allocator, p: *const Paths) Error![]u8 {
    const blob = try readAll(gpa, p.conf(), 4 << 20);
    defer gpa.free(blob);
    return unprotect(gpa, blob);
}

// ---- tests (no elevation needed) ---------------------------------------------------

const testing = std.testing;

test "DPAPI machine scope round trip; ciphertext does not contain the key" {
    const conf = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n";
    const blob = try protect(testing.allocator, conf);
    defer testing.allocator.free(blob);
    try testing.expect(std.mem.indexOf(u8, blob, "yAnz5TF") == null);
    try testing.expect(std.mem.indexOf(u8, blob, "PrivateKey") == null);
    const back = try unprotect(testing.allocator, blob);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings(conf, back);
    // Tampering is detected.
    blob[blob.len - 1] ^= 1;
    try testing.expectError(error.ProtectFailed, unprotect(testing.allocator, blob));
}

test "a blob made for another purpose (other entropy) does not decrypt as ours" {
    const plain = "x";
    const in_blob: win.DATA_BLOB = .{ .len = 1, .data = @constCast(plain.ptr) };
    var out: win.DATA_BLOB = .{ .len = 0, .data = null };
    try testing.expect(win.CryptProtectData(&in_blob, null, null, null, null, win.CRYPTPROTECT_UI_FORBIDDEN | win.CRYPTPROTECT_LOCAL_MACHINE, &out) != 0);
    defer _ = win.LocalFree(out.data);
    try testing.expectError(error.ProtectFailed, unprotect(testing.allocator, out.data.?[0..out.len]));
}

test "paths come from the known folder, not the environment" {
    const p = try Paths.init("laptop");
    try testing.expect(std.ascii.endsWithIgnoreCase(p.root(), "\\zwg"));
    try testing.expect(std.mem.endsWith(u8, p.conf(), "\\zwg\\tunnels\\laptop\\tunnel.conf.dpapi"));
    try testing.expect(std.mem.endsWith(u8, p.log(), "\\zwg\\logs\\laptop.log"));
    try testing.expect(std.fs.path.isAbsoluteWindows(p.root()));
}

test "write a file with an explicit DACL, read it back, wipe it" {
    // A DACL for the current user only (the production one names
    // Administrators as owner, which an unelevated test cannot set).
    var sid_buf: [184]u8 = undefined;
    const sid = try win.currentUserSid(&sid_buf);
    var sddl_buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&sddl_buf, "D:P(A;;FA;;;{s})", .{sid});

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [300]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buf);
    var path_buf: [400]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}\\secret.bin", .{dir_buf[0..dir_len]});

    try writeNew(path, "secret", s);
    try writeNew(path, "secret2", s); // replaces, never appends
    const back = try readAll(testing.allocator, path, 100);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("secret2", back);
    try testing.expectError(error.TooLarge, readAll(testing.allocator, path, 3));

    // The DACL on disk is exactly the one asked for: protected, one ACE.
    var wbuf: [400]u16 = undefined;
    const w = try win.W(&wbuf, path);
    var dacl: ?*win.ACL = null;
    var sd: ?win.PSECURITY_DESCRIPTOR = null;
    try testing.expectEqual(@as(u32, 0), win.GetNamedSecurityInfoW(w.ptr, win.SE_FILE_OBJECT, win.DACL_SECURITY_INFORMATION, null, null, &dacl, null, &sd));
    defer _ = win.LocalFree(sd);
    try testing.expectEqual(@as(u16, 1), dacl.?.ace_count);
    var control: u16 = 0;
    var rev: u32 = 0;
    _ = win.GetSecurityDescriptorControl(sd.?, &control, &rev);
    try testing.expect(control & win.SE_DACL_PROTECTED != 0);

    try wipe(path);
    try testing.expect(!exists(path));
    try wipe(path); // already gone: fine
}

test "the running executable can be copied (the installer copies itself)" {
    var w: [600]u16 = undefined;
    const self = try win.selfExePath(&w);
    var buf: [1800]u8 = undefined;
    const n = try std.unicode.utf16LeToUtf8(&buf, self);
    const data = try readAll(testing.allocator, buf[0..n], max_binary_bytes);
    defer testing.allocator.free(data);
    try testing.expect(std.mem.startsWith(u8, data, "MZ"));
}

test "paths stay valid after the Paths value is copied (returned, wrapped in an optional)" {
    const S = struct {
        fn make() ?Paths {
            return Paths.init("laptop") catch null;
        }
        // Reuses the stack the init call ran on.
        fn scribble() u8 {
            var junk: [8192]u8 = undefined;
            @memset(&junk, 0xAA);
            std.mem.doNotOptimizeAway(&junk);
            return junk[100];
        }
    };
    const opt = S.make();
    _ = S.scribble();
    const p = opt orelse return error.TestUnexpectedResult;
    try testing.expect(std.ascii.endsWithIgnoreCase(p.root(), "\\zwg"));
    try testing.expect(std.mem.endsWith(u8, p.dir(), "\\zwg\\tunnels\\laptop"));
    try testing.expect(std.mem.endsWith(u8, p.log(), "\\zwg\\logs\\laptop.log"));
}
