//! Where an installed tunnel lives on disk, and how its configuration is
//! protected (Windows only).
//!
//!   %ProgramFiles%\zwg\                        protected DACL: SYSTEM + Administrators only
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
//! Location: %ProgramFiles% comes from SHGetKnownFolderPath, never the
//! environment (a user can set %ProgramFiles% for their own elevated
//! processes). Its default DACL lets only administrators (and
//! TrustedInstaller) create entries, which WireGuard for Windows relies on
//! for %ProgramFiles%\WireGuard\Data: an unprivileged user can neither
//! pre-create %ProgramFiles%\zwg nor swap it, or anything below it, for a
//! junction or symbolic link. (The store used to be under %ProgramData%,
//! where Users may create folders: a user-made `zwg` folder swapped for a
//! junction between the elevated installer's checks and its writes would
//! have redirected SYSTEM's files and the key.)
//!
//! Belt and braces, the elevated installer and uninstaller resolve every
//! store directory exactly once (`Dirs`): the root by path, each
//! subdirectory relative to its already verified parent handle, never
//! following a reparse point (FILE_FLAG_OPEN_REPARSE_POINT /
//! FILE_OPEN_REPARSE_POINT). Each handle is checked (a plain directory, not
//! a reparse point, owned by SYSTEM or Administrators), its DACL is set on
//! that same handle, and the handles stay open, without FILE_SHARE_DELETE,
//! for the whole install or uninstall: nothing on the path can be renamed,
//! deleted or replaced meanwhile. Files are created, wiped and deleted
//! relative to those handles.

const std = @import("std");
const nt = std.os.windows;
const win = @import("win32.zig");
const names = @import("names.zig");
const sddl = @import("sddl.zig");

pub const conf_file = "tunnel.conf.dpapi";
pub const exe_file = "zwg.exe";
pub const wintun_file = "wintun.dll";
pub const max_log_bytes = 1 << 20;
pub const max_binary_bytes = 64 << 20;

/// DPAPI's optional entropy: binds the blob to this purpose (another
/// program's machine-scope blob cannot be swapped in and decrypt as ours).
const entropy = "zwg tunnel configuration v1";

pub const Error = error{
    /// A store directory is a link, not a directory, or not owned by SYSTEM/Administrators.
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
/// known-folder Program Files path and a validated tunnel name.
pub const Paths = struct {
    /// Each path lives in its own buffer and is reached through a method,
    /// so a Paths can be copied (returned by value, wrapped in an optional)
    /// without its paths pointing into the copy it was built in.
    buf: [6][260]u8 = undefined,
    len: [6]usize = @splat(0),

    pub fn init(tunnel: []const u8) Error!Paths {
        std.debug.assert(names.isValid(tunnel));
        var pf_buf: [260]u8 = undefined;
        const pf = try programFiles(&pf_buf);
        var p: Paths = .{};
        try p.put(0, "{s}\\zwg", .{pf});
        try p.put(1, "{s}\\zwg\\tunnels", .{pf});
        try p.put(2, "{s}\\zwg\\tunnels\\{s}", .{ pf, tunnel });
        try p.put(3, "{s}\\zwg\\tunnels\\{s}\\" ++ conf_file, .{ pf, tunnel });
        try p.put(4, "{s}\\zwg\\logs", .{pf});
        try p.put(5, "{s}\\zwg\\logs\\{s}.log", .{ pf, tunnel });
        return p;
    }

    /// %ProgramFiles%\zwg
    pub fn root(p: *const Paths) []const u8 {
        return p.get(0);
    }
    /// %ProgramFiles%\zwg\tunnels
    pub fn tunnels(p: *const Paths) []const u8 {
        return p.get(1);
    }
    /// %ProgramFiles%\zwg\tunnels\<name>
    pub fn dir(p: *const Paths) []const u8 {
        return p.get(2);
    }
    /// The encrypted configuration in dir().
    pub fn conf(p: *const Paths) []const u8 {
        return p.get(3);
    }
    /// %ProgramFiles%\zwg\logs
    pub fn logs(p: *const Paths) []const u8 {
        return p.get(4);
    }
    /// %ProgramFiles%\zwg\logs\<name>.log
    pub fn log(p: *const Paths) []const u8 {
        return p.get(5);
    }
    /// The tunnel name (the last component of dir()).
    pub fn name(p: *const Paths) []const u8 {
        return std.fs.path.basenameWindows(p.dir());
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

/// The known folder Program Files (the native one: zwg is built for the
/// machine's architecture), never %ProgramFiles% from the environment.
pub fn programFiles(buf: []u8) Error![]const u8 {
    var w: ?win.LPWSTR = null;
    if (win.SHGetKnownFolderPath(&win.FOLDERID_ProgramFiles, 0, null, &w) != 0) {
        win.CoTaskMemFree(w);
        return error.Unexpected;
    }
    defer win.CoTaskMemFree(w);
    const span = std.mem.span(w.?);
    if (span.len * 3 > buf.len) return error.NameTooLong;
    const n = std.unicode.utf16LeToUtf8(buf, span) catch return error.NameTooLong;
    return buf[0..n];
}

// ---- directories ---------------------------------------------------------------

/// What every store directory handle is opened with. No DELETE, so another
/// installer or uninstaller can hold the same directories at the same time
/// (all share READ | WRITE); nobody can open them for DELETE (rename,
/// delete) while we hold them, because we do not share delete.
const dir_access = win.READ_CONTROL | win.WRITE_DAC | win.WRITE_OWNER | win.SYNCHRONIZE |
    win.FILE_LIST_DIRECTORY | win.FILE_ADD_FILE | win.FILE_ADD_SUBDIRECTORY | win.FILE_TRAVERSE | win.FILE_READ_ATTRIBUTES;
const dir_share = win.FILE_SHARE_READ | win.FILE_SHARE_WRITE;

// NtCreateFile CreateOptions.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const dir_options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;
const file_options = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;

/// The open, verified store directories of one tunnel (elevated installer
/// and uninstaller). Null: does not exist (only after `openExisting`).
pub const Dirs = struct {
    root: ?win.HANDLE = null,
    tunnels: ?win.HANDLE = null,
    logs: ?win.HANDLE = null,
    dir: ?win.HANDLE = null,

    /// Create every directory of `p` (root, tunnels, logs, the tunnel's)
    /// with the protected DACL, or open and verify the existing one and
    /// reset its owner and DACL, each on its own single handle. Needs an
    /// elevated process (owner = Administrators). The handles stay open
    /// until `close` / `remove`.
    pub fn prepare(p: *const Paths) Error!Dirs {
        var sd = win.SecurityDescriptor.fromSddl(sddl.store_dir) catch return error.Unexpected;
        defer sd.deinit();
        var d: Dirs = .{};
        errdefer d.close();
        d.root = try openRoot(p.root(), &sd);
        try secure(d.root.?, &sd);
        d.tunnels = try openChild(d.root.?, "tunnels", &sd);
        try secure(d.tunnels.?, &sd);
        d.logs = try openChild(d.root.?, "logs", &sd);
        try secure(d.logs.?, &sd);
        d.dir = try openChild(d.tunnels.?, p.name(), &sd);
        try secure(d.dir.?, &sd);
        return d;
    }

    /// Open (verified as in `prepare`, changing nothing) whatever of the
    /// store exists; a missing directory stays null, and so does
    /// everything below it.
    pub fn openExisting(p: *const Paths) Error!Dirs {
        var d: Dirs = .{};
        errdefer d.close();
        d.root = openRoot(p.root(), null) catch |e| return if (e == error.NotFound) d else e;
        d.tunnels = try optional(openChild(d.root.?, "tunnels", null));
        d.logs = try optional(openChild(d.root.?, "logs", null));
        if (d.tunnels) |t| d.dir = try optional(openChild(t, p.name(), null));
        return d;
    }

    pub fn close(d: *Dirs) void {
        inline for (.{ "dir", "tunnels", "logs", "root" }) |f| if (@field(d, f)) |h| {
            _ = win.CloseHandle(h);
            @field(d, f) = null;
        };
    }

    /// Remove the tunnel's directory and, if they are empty, tunnels\,
    /// logs\ and the root, then close everything. Best effort. Each handle
    /// is closed (it does not share delete) and the directory deleted
    /// relative to its still open parent; the root by path (its parent,
    /// Program Files, is administrators-only).
    pub fn remove(d: *Dirs, p: *const Paths) void {
        if (d.dir) |h| {
            _ = win.CloseHandle(h);
            d.dir = null;
            if (d.tunnels) |t| deleteChild(t, p.name(), dir_options);
        }
        if (d.tunnels) |h| {
            _ = win.CloseHandle(h);
            d.tunnels = null;
            if (d.root) |r| deleteChild(r, "tunnels", dir_options);
        }
        if (d.logs) |h| {
            _ = win.CloseHandle(h);
            d.logs = null;
            if (d.root) |r| deleteChild(r, "logs", dir_options);
        }
        if (d.root) |h| {
            _ = win.CloseHandle(h);
            d.root = null;
            var wbuf: [300]u16 = undefined;
            const w = win.W(&wbuf, p.root()) catch return;
            _ = win.RemoveDirectoryW(w.ptr);
        }
    }
};

fn optional(r: Error!win.HANDLE) Error!?win.HANDLE {
    return r catch |e| if (e == error.NotFound) null else e;
}

/// The store root by path: created with `sd` if it does not exist (when
/// `sd` is given), then opened once without following a reparse point and
/// verified on that handle.
fn openRoot(path: []const u8, sd: ?*const win.SecurityDescriptor) Error!win.HANDLE {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return error.NameTooLong;
    if (sd) |s| {
        var sa = s.attributes();
        if (win.CreateDirectoryW(w.ptr, &sa) == 0) switch (win.GetLastError()) {
            win.ERROR_ALREADY_EXISTS => {},
            win.ERROR_ACCESS_DENIED => return error.AccessDenied,
            else => return error.Unexpected,
        };
    }
    const h = win.CreateFileW(w.ptr, dir_access, dir_share, null, win.OPEN_EXISTING, win.FILE_FLAG_BACKUP_SEMANTICS | win.FILE_FLAG_OPEN_REPARSE_POINT, null);
    if (h == win.INVALID_HANDLE_VALUE) return mapOpen(win.GetLastError());
    errdefer _ = win.CloseHandle(h);
    try checkPlainDir(h);
    try checkOwner(h);
    return h;
}

/// `name` (one component) inside the open directory `parent`: created with
/// `sd` if missing (when `sd` is given), never through a reparse point,
/// verified on the returned handle.
fn openChild(parent: win.HANDLE, name: []const u8, sd: ?*const win.SecurityDescriptor) Error!win.HANDLE {
    const h = try ntCreate(parent, name, dir_access, dir_share, if (sd != null) .OPEN_IF else .OPEN, dir_options, if (sd) |s| s.sd else null);
    errdefer _ = win.CloseHandle(h);
    try checkPlainDir(h);
    try checkOwner(h);
    return h;
}

/// The handle is a directory and not a reparse point (junction, symbolic
/// link, mount point).
fn checkPlainDir(h: win.HANDLE) Error!void {
    var info: win.FILE_ATTRIBUTE_TAG_INFO = undefined;
    if (win.GetFileInformationByHandleEx(h, win.FileAttributeTagInfo, &info, @sizeOf(win.FILE_ATTRIBUTE_TAG_INFO)) == 0) return error.Unexpected;
    if (info.attributes & win.FILE_ATTRIBUTE_DIRECTORY == 0 or info.attributes & win.FILE_ATTRIBUTE_REPARSE_POINT != 0)
        return error.UntrustedDirectory;
}

/// Owned by Administrators or SYSTEM (nobody else could have created it,
/// or could have changed what is inside).
fn checkOwner(h: win.HANDLE) Error!void {
    var owner: ?win.PSID = null;
    var sd: ?win.PSECURITY_DESCRIPTOR = null;
    if (win.GetSecurityInfo(h, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION, &owner, null, null, null, &sd) != 0) return error.Unexpected;
    defer _ = win.LocalFree(sd);
    const o = owner orelse return error.UntrustedDirectory;
    if (win.IsWellKnownSid(o, win.WinBuiltinAdministratorsSid) == 0 and win.IsWellKnownSid(o, win.WinLocalSystemSid) == 0)
        return error.UntrustedDirectory;
}

/// Reset owner and DACL (protected: nothing inherited from Program Files)
/// on the verified handle; inheritance carries it to everything inside.
fn secure(h: win.HANDLE, sd: *const win.SecurityDescriptor) Error!void {
    const acl = sd.dacl() orelse return error.Unexpected;
    var owner: ?win.PSID = null;
    var defaulted: win.BOOL = 0;
    if (win.GetSecurityDescriptorOwner(sd.sd, &owner, &defaulted) == 0) return error.Unexpected;
    const rc = win.SetSecurityInfo(h, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION | win.DACL_SECURITY_INFORMATION | win.PROTECTED_DACL_SECURITY_INFORMATION, owner, null, acl, null);
    if (rc == win.ERROR_ACCESS_DENIED) return error.AccessDenied;
    if (rc != 0) return error.Unexpected;
}

/// NtCreateFile for `name` (UTF-8, exactly one path component) relative to
/// the open directory `parent`. `sd` applies only when the object is created.
fn ntCreate(parent: win.HANDLE, name: []const u8, access: u32, share: u32, disposition: nt.FILE.CREATE_DISPOSITION, options: u32, sd: ?win.PSECURITY_DESCRIPTOR) Error!win.HANDLE {
    if (name.len == 0 or std.mem.findAny(u8, name, "\\/:") != null or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
        return error.NotFound;
    var wbuf: [64]u16 = undefined;
    const w = win.W(&wbuf, name) catch return error.NameTooLong;
    var us = nt.UNICODE_STRING.init(w);
    const attr: nt.OBJECT.ATTRIBUTES = .{ .RootDirectory = parent, .ObjectName = &us, .SecurityDescriptor = sd };
    var h: nt.HANDLE = undefined;
    var iosb: nt.IO_STATUS_BLOCK = undefined;
    const st = nt.ntdll.NtCreateFile(&h, @bitCast(access), &attr, &iosb, null, @bitCast(win.FILE_ATTRIBUTE_NORMAL), @bitCast(share), disposition, @bitCast(options), null, 0);
    return switch (st) {
        .SUCCESS => h,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => error.NotFound,
        .ACCESS_DENIED => error.AccessDenied,
        .NOT_A_DIRECTORY => error.UntrustedDirectory,
        else => error.Unexpected,
    };
}

fn deleteChild(parent: win.HANDLE, name: []const u8, options: u32) void {
    const h = ntCreate(parent, name, win.DELETE | win.SYNCHRONIZE, win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE, .OPEN, options | FILE_DELETE_ON_CLOSE, null) catch return;
    _ = win.CloseHandle(h);
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

/// Write `data` to a new file `file` in the open directory `dir` (an
/// existing file is deleted first, so the new one gets `security` or, if
/// null, the protected directory's inherited DACL — never a DACL left over
/// from before).
pub fn writeNewAt(dir: win.HANDLE, file: []const u8, data: []const u8, security: ?[]const u8) Error!void {
    try deleteAt(dir, file);
    var sd: ?win.SecurityDescriptor = if (security) |s| win.SecurityDescriptor.fromSddl(s) catch return error.Unexpected else null;
    defer if (sd) |*s| s.deinit();
    const h = try ntCreate(dir, file, win.GENERIC_WRITE | win.SYNCHRONIZE, 0, .CREATE, file_options, if (sd) |s| s.sd else null);
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
    return readHandle(gpa, h, limit);
}

/// Read a whole open file from its start (at most `limit` bytes). Caller frees.
pub fn readHandle(gpa: std.mem.Allocator, h: win.HANDLE, limit: usize) Error![]u8 {
    var size: i64 = 0;
    if (win.GetFileSizeEx(h, &size) == 0) return error.Unexpected;
    if (size < 0 or size > limit) return error.TooLarge;
    const buf = try gpa.alloc(u8, @intCast(size));
    errdefer gpa.free(buf);
    var got: usize = 0;
    while (got < buf.len) {
        var n: u32 = 0;
        const chunk: u32 = @intCast(@min(buf.len - got, 1 << 20));
        // Explicit offsets: the handle may have been read before.
        var ov: win.OVERLAPPED = .{ .offset = @truncate(got), .offset_high = @truncate(@as(u64, got) >> 32) };
        if (win.ReadFile(h, buf.ptr + got, chunk, &n, &ov) == 0) return error.Unexpected;
        if (n == 0) return error.Unexpected; // shrank under us
        got += n;
    }
    return buf;
}

/// Overwrite `file` in the open directory `dir` with zeros, then delete it.
/// Missing = done.
pub fn wipeAt(dir: win.HANDLE, file: []const u8) Error!void {
    const h = ntCreate(dir, file, win.GENERIC_READ | win.GENERIC_WRITE | win.DELETE | win.SYNCHRONIZE, 0, .OPEN, file_options, null) catch |e|
        return if (e == error.NotFound) {} else e;
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
    const del: win.FILE_DISPOSITION_INFO = .{ .delete_file = 1 };
    if (win.SetFileInformationByHandle(h, win.FileDispositionInfo, &del, @sizeOf(win.FILE_DISPOSITION_INFO)) == 0) return error.Unexpected;
}

/// Delete `file` in the open directory `dir`. Missing = done.
pub fn deleteAt(dir: win.HANDLE, file: []const u8) Error!void {
    const h = ntCreate(dir, file, win.DELETE | win.SYNCHRONIZE, win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE, .OPEN, file_options | FILE_DELETE_ON_CLOSE, null) catch |e|
        return if (e == error.NotFound) {} else e;
    _ = win.CloseHandle(h);
}

pub fn exists(path: []const u8) bool {
    var wbuf: [300]u16 = undefined;
    const w = win.W(&wbuf, path) catch return false;
    return win.GetFileAttributesW(w.ptr) != win.INVALID_FILE_ATTRIBUTES;
}

/// Copy the open file `from` (bounded) into the open directory `dir` as a
/// new file `file`.
pub fn copyInto(gpa: std.mem.Allocator, from: win.HANDLE, dir: win.HANDLE, file: []const u8) Error!void {
    const data = try readHandle(gpa, from, max_binary_bytes);
    defer gpa.free(data);
    try writeNewAt(dir, file, data, null);
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

/// Encrypt and store the configuration text (the caller wipes `text`) in
/// the tunnel's open directory.
pub fn storeConfig(gpa: std.mem.Allocator, dirs: *const Dirs, text: []const u8) Error!void {
    const blob = try protect(gpa, text);
    defer gpa.free(blob);
    try writeNewAt(dirs.dir orelse return error.NotFound, conf_file, blob, null);
}

/// Read and decrypt the stored configuration (the service, SYSTEM: the
/// whole path is administrators-only). Caller wipes and frees.
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

test "paths come from the Program Files known folder, not the environment" {
    const p = try Paths.init("laptop");
    try testing.expect(std.ascii.endsWithIgnoreCase(p.root(), "\\zwg"));
    try testing.expect(std.mem.endsWith(u8, p.conf(), "\\zwg\\tunnels\\laptop\\tunnel.conf.dpapi"));
    try testing.expect(std.mem.endsWith(u8, p.log(), "\\zwg\\logs\\laptop.log"));
    try testing.expectEqualStrings("laptop", p.name());
    try testing.expect(std.fs.path.isAbsoluteWindows(p.root()));
    var pf_buf: [260]u8 = undefined;
    const pf = try programFiles(&pf_buf);
    try testing.expect(std.mem.startsWith(u8, p.root(), pf));
    // Not under ProgramData (Users may create folders there).
    try testing.expect(std.ascii.findIgnoreCase(p.root(), "ProgramData") == null);
}

/// A temporary directory: its absolute path and an open handle to it.
const TmpDir = struct {
    tmp: testing.TmpDir,
    path_buf: [300]u8 = undefined,
    path_len: usize = 0,
    handle: win.HANDLE = undefined,

    const access = dir_access & ~win.WRITE_OWNER;

    fn init(t: *TmpDir) !void {
        t.* = .{ .tmp = testing.tmpDir(.{}) };
        errdefer t.tmp.cleanup();
        t.path_len = try t.tmp.dir.realPath(testing.io, &t.path_buf);
        var wbuf: [300]u16 = undefined;
        const w = try win.W(&wbuf, t.path());
        t.handle = win.CreateFileW(w.ptr, access, dir_share, null, win.OPEN_EXISTING, win.FILE_FLAG_BACKUP_SEMANTICS | win.FILE_FLAG_OPEN_REPARSE_POINT, null);
        if (t.handle == win.INVALID_HANDLE_VALUE) return error.Unexpected;
    }

    fn path(t: *const TmpDir) []const u8 {
        return t.path_buf[0..t.path_len];
    }

    fn sub(t: *const TmpDir, buf: []u8, wbuf: []u16, name: []const u8) ![:0]u16 {
        return win.W(wbuf, try std.fmt.bufPrint(buf, "{s}\\{s}", .{ t.path(), name }));
    }

    fn deinit(t: *TmpDir) void {
        _ = win.CloseHandle(t.handle);
        t.tmp.cleanup();
    }
};

test "write a file with an explicit DACL relative to the directory handle, read it back, wipe it" {
    // A DACL for the current user only (the production one names
    // Administrators as owner, which an unelevated test cannot set).
    var sid_buf: [184]u8 = undefined;
    const sid = try win.currentUserSid(&sid_buf);
    var sddl_buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&sddl_buf, "D:P(A;;FA;;;{s})", .{sid});

    var t: TmpDir = undefined;
    try t.init();
    defer t.deinit();
    var path_buf: [400]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}\\secret.bin", .{t.path()});

    try writeNewAt(t.handle, "secret.bin", "secret", s);
    try writeNewAt(t.handle, "secret.bin", "secret2", s); // replaces, never appends
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

    try wipeAt(t.handle, "secret.bin");
    try testing.expect(!exists(path));
    try wipeAt(t.handle, "secret.bin"); // already gone: fine
    try writeNewAt(t.handle, "other.bin", "x", null);
    try deleteAt(t.handle, "other.bin");
    try deleteAt(t.handle, "other.bin"); // already gone: fine
    // Exactly one component: nothing escapes the directory handle.
    try testing.expectError(error.NotFound, writeNewAt(t.handle, "..\\escape.bin", "x", null));
    try testing.expectError(error.NotFound, writeNewAt(t.handle, "a/b", "x", null));
    try testing.expectError(error.NotFound, writeNewAt(t.handle, "..", "x", null));
}

// FSCTL_SET_REPARSE_POINT with a mount point (junction) buffer: what
// `mklink /J` does; needs no privilege on a directory the user owns.
const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
extern "kernel32" fn DeviceIoControl(h: win.HANDLE, code: u32, in: ?*const anyopaque, in_len: u32, out: ?*anyopaque, out_len: u32, returned: ?*u32, ov: ?*win.OVERLAPPED) callconv(.winapi) win.BOOL;

/// Make the new directory `link` (absolute) a junction to `target` (absolute).
fn makeJunction(link: [:0]const u16, target: []const u8) !void {
    if (win.CreateDirectoryW(link.ptr, null) == 0) return error.Unexpected;
    const h = win.CreateFileW(link.ptr, win.GENERIC_WRITE, 0, null, win.OPEN_EXISTING, win.FILE_FLAG_BACKUP_SEMANTICS | win.FILE_FLAG_OPEN_REPARSE_POINT, null);
    if (h == win.INVALID_HANDLE_VALUE) return error.Unexpected;
    defer _ = win.CloseHandle(h);
    // REPARSE_DATA_BUFFER, MountPointReparseBuffer: substitute name
    // "\??\<target>" then print name "<target>", each NUL-terminated.
    var sub_buf: [300]u8 = undefined;
    var sub: [300]u16 = undefined;
    const sub_n = try std.unicode.utf8ToUtf16Le(&sub, try std.fmt.bufPrint(&sub_buf, "\\??\\{s}", .{target}));
    var pr: [300]u16 = undefined;
    const pr_n = try std.unicode.utf8ToUtf16Le(&pr, target);
    var buf: [2048]u8 align(4) = @splat(0);
    const path_bytes = (sub_n + 1 + pr_n + 1) * 2;
    std.mem.writeInt(u32, buf[0..4], IO_REPARSE_TAG_MOUNT_POINT, .little);
    std.mem.writeInt(u16, buf[4..6], @intCast(8 + path_bytes), .little); // ReparseDataLength
    std.mem.writeInt(u16, buf[8..10], 0, .little); // SubstituteNameOffset
    std.mem.writeInt(u16, buf[10..12], @intCast(sub_n * 2), .little); // SubstituteNameLength
    std.mem.writeInt(u16, buf[12..14], @intCast((sub_n + 1) * 2), .little); // PrintNameOffset
    std.mem.writeInt(u16, buf[14..16], @intCast(pr_n * 2), .little); // PrintNameLength
    @memcpy(buf[16..][0 .. sub_n * 2], std.mem.sliceAsBytes(sub[0..sub_n]));
    @memcpy(buf[16 + (sub_n + 1) * 2 ..][0 .. pr_n * 2], std.mem.sliceAsBytes(pr[0..pr_n]));
    var ret: u32 = 0;
    if (DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &buf, @intCast(16 + path_bytes), null, 0, &ret, null) == 0) return error.Unexpected;
}

test "a junction is rejected: by path (the root) and relative to a verified parent" {
    var t: TmpDir = undefined;
    try t.init();
    defer t.deinit();
    var b1: [400]u8 = undefined;
    var w1: [400]u16 = undefined;
    var b2: [400]u8 = undefined;
    var w2: [400]u16 = undefined;
    try testing.expect(win.CreateDirectoryW((try t.sub(&b1, &w1, "target")).ptr, null) != 0);
    const target = b1[0 .. t.path().len + "\\target".len];
    const link_w = try t.sub(&b2, &w2, "link");
    const link = b2[0 .. t.path().len + "\\link".len];
    try makeJunction(link_w, target);
    {
        // It works as a junction: a directory made through it lands in target.
        var b3: [400]u8 = undefined;
        var w3: [400]u16 = undefined;
        try testing.expect(win.CreateDirectoryW((try t.sub(&b3, &w3, "link\\x")).ptr, null) != 0);
        var b4: [400]u8 = undefined;
        try testing.expect(exists(try std.fmt.bufPrint(&b4, "{s}\\target\\x", .{t.path()})));
    }

    // The root, by path: the reparse point itself is opened and refused,
    // before its owner is even looked at.
    try testing.expectError(error.UntrustedDirectory, openRoot(link, null));
    // A child, relative to an open parent: refused the same way.
    try testing.expectError(error.UntrustedDirectory, openChild(t.handle, "link", null));
    // A plain directory passes the link check; owned by this (unelevated)
    // user rather than Administrators/SYSTEM, it then fails the owner check.
    const plain = try ntCreate(t.handle, "target", TmpDir.access, dir_share, .OPEN, dir_options, null);
    defer _ = win.CloseHandle(plain);
    try checkPlainDir(plain);
    if (!win.isElevated()) {
        try testing.expectError(error.UntrustedDirectory, checkOwner(plain));
        try testing.expectError(error.UntrustedDirectory, openRoot(target, null));
    }
    // A file where a directory is expected.
    try writeNewAt(t.handle, "file", "x", null);
    try testing.expectError(error.UntrustedDirectory, openChild(t.handle, "file", null));
    // Missing: NotFound (openExisting turns that into null).
    try testing.expectError(error.NotFound, openChild(t.handle, "missing", null));
    try testing.expectEqual(@as(?win.HANDLE, null), try optional(openChild(t.handle, "missing", null)));
}

test "a held store directory cannot be renamed or deleted (no FILE_SHARE_DELETE)" {
    var t: TmpDir = undefined;
    try t.init();
    defer t.deinit();
    var b1: [400]u8 = undefined;
    var w1: [400]u16 = undefined;
    const held = try t.sub(&b1, &w1, "held");
    try testing.expect(win.CreateDirectoryW(held.ptr, null) != 0);
    const h = try ntCreate(t.handle, "held", TmpDir.access, dir_share, .OPEN, dir_options, null);
    var b2: [400]u8 = undefined;
    var w2: [400]u16 = undefined;
    const moved = try t.sub(&b2, &w2, "moved");
    try testing.expect(win.MoveFileExW(held.ptr, moved.ptr, 0) == 0);
    try testing.expect(win.RemoveDirectoryW(held.ptr) == 0);
    // Files can still be made inside it (the installer writes through it).
    try writeNewAt(h, "inside", "x", null);
    try deleteAt(h, "inside");
    _ = win.CloseHandle(h);
    try testing.expect(win.RemoveDirectoryW(held.ptr) != 0);
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
    try testing.expectEqualStrings("laptop", p.name());
}
