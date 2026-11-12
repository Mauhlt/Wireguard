//! Every Win32 declaration the tunnel service needs, in one place (Windows
//! only): the service control manager, named pipes, security descriptors,
//! DPAPI, UAC re-launch and a few file calls. std's Windows layer is mostly
//! ntdll and has none of these.
//!
//! Conventions: BOOL results are `c_int` (0 = failure, see GetLastError);
//! strings are NUL-terminated UTF-16 (`W` helpers below convert).

const std = @import("std");

pub const HANDLE = std.os.windows.HANDLE;
pub const BOOL = c_int;
pub const SC_HANDLE = *opaque {};
pub const SERVICE_STATUS_HANDLE = *opaque {};
pub const PSID = *anyopaque;
pub const PSECURITY_DESCRIPTOR = *anyopaque;
pub const LPWSTR = [*:0]u16;
pub const LPCWSTR = [*:0]const u16;

pub const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(~@as(usize, 0));
pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_IO_COMPLETION: u32 = 0xC0;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;

// ---- errors ----------------------------------------------------------------

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_BROKEN_PIPE: u32 = 109;
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
pub const ERROR_SEM_TIMEOUT: u32 = 121;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_PIPE_BUSY: u32 = 231;
pub const ERROR_NO_DATA: u32 = 232;
pub const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_PIPE_CONNECTED: u32 = 535;
pub const ERROR_OPERATION_ABORTED: u32 = 995;
pub const ERROR_IO_INCOMPLETE: u32 = 996;
pub const ERROR_IO_PENDING: u32 = 997;
pub const ERROR_SERVICE_REQUEST_TIMEOUT: u32 = 1053;
pub const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
pub const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
pub const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u32 = 1061;
pub const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
pub const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
pub const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
pub const ERROR_SERVICE_EXISTS: u32 = 1073;
pub const ERROR_CANCELLED: u32 = 1223;

// ---- kernel32 ----------------------------------------------------------------

pub const OVERLAPPED = extern struct {
    internal: usize = 0,
    internal_high: usize = 0,
    offset: u32 = 0,
    offset_high: u32 = 0,
    event: ?HANDLE = null,
};

pub const SECURITY_ATTRIBUTES = extern struct {
    length: u32 = @sizeOf(SECURITY_ATTRIBUTES),
    descriptor: ?PSECURITY_DESCRIPTOR = null,
    inherit: BOOL = 0,
};

pub const SRWLOCK = extern struct { ptr: ?*anyopaque = null };

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004; // = FILE_CREATE_PIPE_INSTANCE on a pipe
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_SHARE_READ: u32 = 1;
pub const FILE_SHARE_WRITE: u32 = 2;
pub const FILE_SHARE_DELETE: u32 = 4;
pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
pub const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
pub const MOVEFILE_REPLACE_EXISTING: u32 = 1;

pub const PIPE_ACCESS_DUPLEX: u32 = 3;
pub const PIPE_TYPE_BYTE: u32 = 0;
pub const PIPE_READMODE_BYTE: u32 = 0;
pub const PIPE_WAIT: u32 = 0;
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;

pub const PROCESS_SYNCHRONIZE: u32 = SYNCHRONIZE;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

pub extern "kernel32" fn GetLastError() callconv(.winapi) u32;
pub extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreateEventW(attrs: ?*SECURITY_ATTRIBUTES, manual_reset: BOOL, initial: BOOL, name: ?LPCWSTR) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn SetEvent(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn ResetEvent(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: u32) callconv(.winapi) u32;
pub extern "kernel32" fn WaitForMultipleObjects(n: u32, handles: [*]const HANDLE, wait_all: BOOL, ms: u32) callconv(.winapi) u32;
pub extern "kernel32" fn SleepEx(ms: u32, alertable: BOOL) callconv(.winapi) u32;
pub extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
pub extern "kernel32" fn LocalFree(mem: ?*anyopaque) callconv(.winapi) ?*anyopaque;
pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
pub extern "kernel32" fn OpenProcess(access: u32, inherit: BOOL, pid: u32) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetModuleFileNameW(module: ?HANDLE, buf: [*]u16, len: u32) callconv(.winapi) u32;
pub extern "kernel32" fn GetFullPathNameW(name: LPCWSTR, len: u32, buf: [*]u16, file_part: ?*?LPWSTR) callconv(.winapi) u32;
pub extern "kernel32" fn GetSystemTimeAsFileTime(ft: *u64) callconv(.winapi) void;
pub extern "kernel32" fn AcquireSRWLockExclusive(l: *SRWLOCK) callconv(.winapi) void;
pub extern "kernel32" fn ReleaseSRWLockExclusive(l: *SRWLOCK) callconv(.winapi) void;

pub extern "kernel32" fn CreateFileW(name: LPCWSTR, access: u32, share: u32, sa: ?*SECURITY_ATTRIBUTES, disposition: u32, flags: u32, template: ?HANDLE) callconv(.winapi) HANDLE;
pub extern "kernel32" fn ReadFile(h: HANDLE, buf: [*]u8, len: u32, read: ?*u32, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;
pub extern "kernel32" fn WriteFile(h: HANDLE, buf: [*]const u8, len: u32, written: ?*u32, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;
pub extern "kernel32" fn FlushFileBuffers(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetFileSizeEx(h: HANDLE, size: *i64) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetFileAttributesW(name: LPCWSTR) callconv(.winapi) u32;
pub extern "kernel32" fn CreateDirectoryW(name: LPCWSTR, sa: ?*SECURITY_ATTRIBUTES) callconv(.winapi) BOOL;
pub extern "kernel32" fn RemoveDirectoryW(name: LPCWSTR) callconv(.winapi) BOOL;
pub extern "kernel32" fn DeleteFileW(name: LPCWSTR) callconv(.winapi) BOOL;
pub extern "kernel32" fn MoveFileExW(from: LPCWSTR, to: LPCWSTR, flags: u32) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateNamedPipeW(name: LPCWSTR, open_mode: u32, pipe_mode: u32, max_instances: u32, out_size: u32, in_size: u32, default_timeout: u32, sa: ?*SECURITY_ATTRIBUTES) callconv(.winapi) HANDLE;
pub extern "kernel32" fn ConnectNamedPipe(h: HANDLE, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;
pub extern "kernel32" fn DisconnectNamedPipe(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitNamedPipeW(name: LPCWSTR, ms: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetOverlappedResult(h: HANDLE, ov: *OVERLAPPED, n: *u32, wait: BOOL) callconv(.winapi) BOOL;
pub extern "kernel32" fn CancelIoEx(h: HANDLE, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;

// ---- advapi32: tokens, SIDs, security descriptors ---------------------------

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ALL_ACCESS: u32 = 0xF01FF;
pub const TokenUser: c_int = 1;
pub const TokenIntegrityLevel: c_int = 25;
pub const SE_GROUP_INTEGRITY: u32 = 0x20;
pub const DISABLE_MAX_PRIVILEGE: u32 = 1;
pub const LUA_TOKEN: u32 = 4;

pub const SID_AND_ATTRIBUTES = extern struct { sid: ?PSID, attributes: u32 };
pub const TOKEN_USER = extern struct { user: SID_AND_ATTRIBUTES };
pub const TOKEN_MANDATORY_LABEL = extern struct { label: SID_AND_ATTRIBUTES };

pub const SDDL_REVISION_1: u32 = 1;
pub const SE_FILE_OBJECT: c_int = 1;
pub const OWNER_SECURITY_INFORMATION: u32 = 1;
pub const DACL_SECURITY_INFORMATION: u32 = 4;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
pub const WinLocalSystemSid: c_int = 22;
pub const WinBuiltinAdministratorsSid: c_int = 26;

pub const ACL = extern struct { revision: u8, sbz1: u8, size: u16, ace_count: u16, sbz2: u16 };
pub const ACE_HEADER = extern struct { kind: u8, flags: u8, size: u16 };
pub const ACCESS_ALLOWED_ACE = extern struct { header: ACE_HEADER, mask: u32, sid_start: u32 };
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
pub const OBJECT_INHERIT_ACE: u8 = 1;
pub const CONTAINER_INHERIT_ACE: u8 = 2;
pub const SE_DACL_PROTECTED: u16 = 0x1000;

pub extern "advapi32" fn OpenProcessToken(process: HANDLE, access: u32, token: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetTokenInformation(token: HANDLE, class: c_int, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn SetTokenInformation(token: HANDLE, class: c_int, info: *const anyopaque, len: u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateRestrictedToken(existing: HANDLE, flags: u32, disable_count: u32, disable: ?[*]const SID_AND_ATTRIBUTES, delete_priv_count: u32, delete_privs: ?*const anyopaque, restrict_count: u32, restrict: ?[*]const SID_AND_ATTRIBUTES, new_token: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn ImpersonateLoggedOnUser(token: HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn RevertToSelf() callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertSidToStringSidW(sid: PSID, out: *?LPWSTR) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertStringSidToSidW(s: LPCWSTR, out: *?PSID) callconv(.winapi) BOOL;
pub extern "advapi32" fn IsValidSid(sid: PSID) callconv(.winapi) BOOL;
pub extern "advapi32" fn EqualSid(a: PSID, b: PSID) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetLengthSid(sid: PSID) callconv(.winapi) u32;
pub extern "advapi32" fn IsWellKnownSid(sid: PSID, kind: c_int) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: LPCWSTR, revision: u32, sd: *?PSECURITY_DESCRIPTOR, size: ?*u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorDacl(sd: PSECURITY_DESCRIPTOR, present: *BOOL, dacl: *?*ACL, defaulted: *BOOL) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorOwner(sd: PSECURITY_DESCRIPTOR, owner: *?PSID, defaulted: *BOOL) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorControl(sd: PSECURITY_DESCRIPTOR, control: *u16, revision: *u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetAce(acl: *ACL, index: u32, ace: *?*anyopaque) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetNamedSecurityInfoW(name: LPCWSTR, kind: c_int, info: u32, owner: ?*?PSID, group: ?*?PSID, dacl: ?*?*ACL, sacl: ?*?*ACL, sd: *?PSECURITY_DESCRIPTOR) callconv(.winapi) u32;
pub extern "advapi32" fn SetNamedSecurityInfoW(name: LPWSTR, kind: c_int, info: u32, owner: ?PSID, group: ?PSID, dacl: ?*ACL, sacl: ?*ACL) callconv(.winapi) u32;

// ---- advapi32: service control manager -------------------------------------

pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;

pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
pub const SERVICE_START: u32 = 0x0010;
pub const SERVICE_STOP: u32 = 0x0020;
pub const SERVICE_INTERROGATE: u32 = 0x0080;
pub const SERVICE_ALL_ACCESS: u32 = 0xF01FF;

pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
pub const SERVICE_WIN32: u32 = 0x30;
pub const SERVICE_AUTO_START: u32 = 2;
pub const SERVICE_DEMAND_START: u32 = 3;
pub const SERVICE_ERROR_NORMAL: u32 = 1;
pub const SERVICE_STATE_ALL: u32 = 3;
pub const SC_ENUM_PROCESS_INFO: c_int = 0;
pub const SC_STATUS_PROCESS_INFO: c_int = 0;

pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_STOP_PENDING: u32 = 3;
pub const SERVICE_RUNNING: u32 = 4;
pub const SERVICE_CONTINUE_PENDING: u32 = 5;
pub const SERVICE_PAUSE_PENDING: u32 = 6;
pub const SERVICE_PAUSED: u32 = 7;

pub const SERVICE_CONTROL_STOP: u32 = 1;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 4;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 5;
pub const SERVICE_ACCEPT_STOP: u32 = 1;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 4;

pub const SERVICE_CONFIG_DESCRIPTION: u32 = 1;
pub const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u32 = 4;
pub const SERVICE_CONFIG_SERVICE_SID_INFO: u32 = 5;
pub const SERVICE_SID_TYPE_UNRESTRICTED: u32 = 1;
pub const SC_ACTION_NONE: u32 = 0;
pub const SC_ACTION_RESTART: u32 = 1;

pub const SERVICE_NOTIFY_STATUS_CHANGE: u32 = 2;
pub const SERVICE_NOTIFY_STOPPED: u32 = 0x1;
pub const SERVICE_NOTIFY_START_PENDING: u32 = 0x2;
pub const SERVICE_NOTIFY_STOP_PENDING: u32 = 0x4;
pub const SERVICE_NOTIFY_RUNNING: u32 = 0x8;
pub const SERVICE_NOTIFY_CONTINUE_PENDING: u32 = 0x10;
pub const SERVICE_NOTIFY_PAUSE_PENDING: u32 = 0x20;
pub const SERVICE_NOTIFY_PAUSED: u32 = 0x40;

pub const SERVICE_STATUS = extern struct {
    service_type: u32 = SERVICE_WIN32_OWN_PROCESS,
    current_state: u32 = SERVICE_STOPPED,
    controls_accepted: u32 = 0,
    win32_exit_code: u32 = 0,
    service_specific_exit_code: u32 = 0,
    check_point: u32 = 0,
    wait_hint: u32 = 0,
};

pub const SERVICE_STATUS_PROCESS = extern struct {
    status: SERVICE_STATUS = .{},
    process_id: u32 = 0,
    service_flags: u32 = 0,
};

pub const ENUM_SERVICE_STATUS_PROCESSW = extern struct {
    service_name: LPWSTR,
    display_name: LPWSTR,
    status: SERVICE_STATUS_PROCESS,
};

pub const ServiceMainFn = *const fn (argc: u32, argv: ?[*]?LPWSTR) callconv(.winapi) void;
pub const HandlerExFn = *const fn (control: u32, event_type: u32, event_data: ?*anyopaque, context: ?*anyopaque) callconv(.winapi) u32;

pub const SERVICE_TABLE_ENTRYW = extern struct {
    name: ?LPCWSTR,
    proc: ?ServiceMainFn,
};

pub const SERVICE_DESCRIPTIONW = extern struct { description: ?LPCWSTR };
pub const SC_ACTION = extern struct { kind: u32, delay_ms: u32 };
pub const SERVICE_FAILURE_ACTIONSW = extern struct {
    reset_period_s: u32,
    reboot_msg: ?LPCWSTR = null,
    command: ?LPCWSTR = null,
    action_count: u32,
    actions: ?[*]const SC_ACTION,
};
pub const SERVICE_FAILURE_ACTIONS_FLAG = extern struct { on_non_crash_failures: BOOL };
pub const SERVICE_SID_INFO = extern struct { sid_type: u32 };

pub const SERVICE_NOTIFYW = extern struct {
    version: u32 = SERVICE_NOTIFY_STATUS_CHANGE,
    callback: ?*const fn (param: ?*anyopaque) callconv(.winapi) void = null,
    context: ?*anyopaque = null,
    notification_status: u32 = 0,
    status: SERVICE_STATUS_PROCESS = .{},
    notification_triggered: u32 = 0,
    service_names: ?LPWSTR = null,
};

pub extern "advapi32" fn OpenSCManagerW(machine: ?LPCWSTR, database: ?LPCWSTR, access: u32) callconv(.winapi) ?SC_HANDLE;
pub extern "advapi32" fn CloseServiceHandle(h: SC_HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateServiceW(scm: SC_HANDLE, name: LPCWSTR, display: ?LPCWSTR, access: u32, service_type: u32, start_type: u32, error_control: u32, binary_path: LPCWSTR, load_order_group: ?LPCWSTR, tag_id: ?*u32, dependencies: ?[*]const u16, start_name: ?LPCWSTR, password: ?LPCWSTR) callconv(.winapi) ?SC_HANDLE;
pub extern "advapi32" fn OpenServiceW(scm: SC_HANDLE, name: LPCWSTR, access: u32) callconv(.winapi) ?SC_HANDLE;
pub extern "advapi32" fn DeleteService(svc: SC_HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn StartServiceW(svc: SC_HANDLE, argc: u32, argv: ?[*]const LPCWSTR) callconv(.winapi) BOOL;
pub extern "advapi32" fn ControlService(svc: SC_HANDLE, control: u32, status: *SERVICE_STATUS) callconv(.winapi) BOOL;
pub extern "advapi32" fn QueryServiceStatusEx(svc: SC_HANDLE, level: c_int, buf: [*]u8, len: u32, needed: *u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn ChangeServiceConfig2W(svc: SC_HANDLE, level: u32, info: *const anyopaque) callconv(.winapi) BOOL;
pub extern "advapi32" fn SetServiceObjectSecurity(svc: SC_HANDLE, info: u32, sd: PSECURITY_DESCRIPTOR) callconv(.winapi) BOOL;
pub extern "advapi32" fn EnumServicesStatusExW(scm: SC_HANDLE, level: c_int, service_type: u32, state: u32, buf: ?[*]u8, len: u32, needed: *u32, returned: *u32, resume_handle: ?*u32, group: ?LPCWSTR) callconv(.winapi) BOOL;
pub extern "advapi32" fn NotifyServiceStatusChangeW(svc: SC_HANDLE, mask: u32, notify: *SERVICE_NOTIFYW) callconv(.winapi) u32;
pub extern "advapi32" fn StartServiceCtrlDispatcherW(table: [*]const SERVICE_TABLE_ENTRYW) callconv(.winapi) BOOL;
pub extern "advapi32" fn RegisterServiceCtrlHandlerExW(name: LPCWSTR, handler: HandlerExFn, context: ?*anyopaque) callconv(.winapi) ?SERVICE_STATUS_HANDLE;
pub extern "advapi32" fn SetServiceStatus(h: SERVICE_STATUS_HANDLE, status: *const SERVICE_STATUS) callconv(.winapi) BOOL;

// ---- crypt32: DPAPI ----------------------------------------------------------

pub const DATA_BLOB = extern struct { len: u32, data: ?[*]u8 };
pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
pub const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

pub extern "crypt32" fn CryptProtectData(in: *const DATA_BLOB, description: ?LPCWSTR, entropy: ?*const DATA_BLOB, reserved: ?*anyopaque, prompt: ?*anyopaque, flags: u32, out: *DATA_BLOB) callconv(.winapi) BOOL;
pub extern "crypt32" fn CryptUnprotectData(in: *const DATA_BLOB, description: ?*?LPWSTR, entropy: ?*const DATA_BLOB, reserved: ?*anyopaque, prompt: ?*anyopaque, flags: u32, out: *DATA_BLOB) callconv(.winapi) BOOL;

// ---- shell32 / ole32: UAC re-launch, known folders ---------------------------

pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x40;
pub const SEE_MASK_NOASYNC: u32 = 0x100;
pub const SEE_MASK_FLAG_NO_UI: u32 = 0x400;
pub const SW_HIDE: c_int = 0;

pub const SHELLEXECUTEINFOW = extern struct {
    size: u32 = @sizeOf(SHELLEXECUTEINFOW),
    mask: u32 = 0,
    hwnd: ?HANDLE = null,
    verb: ?LPCWSTR = null,
    file: ?LPCWSTR = null,
    parameters: ?LPCWSTR = null,
    directory: ?LPCWSTR = null,
    show: c_int = 0,
    inst_app: ?HANDLE = null,
    id_list: ?*anyopaque = null,
    class: ?LPCWSTR = null,
    hkey_class: ?HANDLE = null,
    hot_key: u32 = 0,
    icon_or_monitor: ?HANDLE = null,
    process: ?HANDLE = null,
};

pub const GUID = extern struct { data1: u32, data2: u16, data3: u16, data4: [8]u8 };
/// FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
pub const FOLDERID_ProgramData: GUID = .{ .data1 = 0x62AB5D82, .data2 = 0xFDC1, .data3 = 0x4DC3, .data4 = .{ 0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97 } };

pub extern "shell32" fn ShellExecuteExW(info: *SHELLEXECUTEINFOW) callconv(.winapi) BOOL;
pub extern "shell32" fn SHGetKnownFolderPath(id: *const GUID, flags: u32, token: ?HANDLE, path: *?LPWSTR) callconv(.winapi) i32;
pub extern "ole32" fn CoTaskMemFree(p: ?*anyopaque) callconv(.winapi) void;

// ---- helpers -----------------------------------------------------------------

/// UTF-8 -> NUL-terminated UTF-16 in `buf`. error.NameTooLong if it does not fit.
pub fn W(buf: []u16, utf8: []const u8) error{ NameTooLong, InvalidUtf8 }![:0]u16 {
    if (buf.len == 0) return error.NameTooLong;
    // UTF-16 never needs more units than UTF-8 has bytes.
    if (utf8.len > buf.len - 1) {
        const n = std.unicode.calcUtf16LeLen(utf8) catch return error.InvalidUtf8;
        if (n > buf.len - 1) return error.NameTooLong;
    }
    const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], utf8) catch return error.InvalidUtf8;
    buf[n] = 0;
    return buf[0..n :0];
}

/// NUL-terminated UTF-16 -> UTF-8 (lossy for unpaired surrogates).
pub fn toUtf8(gpa: std.mem.Allocator, w: [*:0]const u16) error{OutOfMemory}![]u8 {
    return std.unicode.utf16LeToUtf8Alloc(gpa, std.mem.span(w)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => gpa.dupe(u8, "?"),
    };
}

/// The current process token's user SID as a string ("S-1-5-21-...").
pub fn currentUserSid(buf: []u8) error{ Unexpected, NameTooLong }![]u8 {
    var token: HANDLE = undefined;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return error.Unexpected;
    defer _ = CloseHandle(token);
    var info: [256]u8 align(8) = undefined;
    var len: u32 = 0;
    if (GetTokenInformation(token, TokenUser, &info, info.len, &len) == 0) return error.Unexpected;
    const tu: *const TOKEN_USER = @ptrCast(&info);
    var s: ?LPWSTR = null;
    if (ConvertSidToStringSidW(tu.user.sid.?, &s) == 0) return error.Unexpected;
    defer _ = LocalFree(s);
    const span = std.mem.span(s.?);
    if (span.len > buf.len) return error.NameTooLong;
    for (span, 0..) |c, i| {
        if (c > 0x7f) return error.Unexpected;
        buf[i] = @intCast(c);
    }
    return buf[0..span.len];
}

/// Path of the running executable (UTF-16, NUL-terminated, in `buf`).
pub fn selfExePath(buf: []u16) error{Unexpected}![:0]u16 {
    const n = GetModuleFileNameW(null, buf.ptr, @intCast(buf.len));
    if (n == 0 or n >= buf.len) return error.Unexpected;
    buf[n] = 0;
    return buf[0..n :0];
}

/// True when the process token is elevated.
pub fn isElevated() bool {
    var token: HANDLE = undefined;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return false;
    defer _ = CloseHandle(token);
    var elevation: u32 = 0;
    var len: u32 = 0;
    const TokenElevation: c_int = 20;
    if (GetTokenInformation(token, TokenElevation, &elevation, @sizeOf(u32), &len) == 0) return false;
    return elevation != 0;
}

pub const SecurityDescriptor = struct {
    sd: PSECURITY_DESCRIPTOR,

    /// Parse an SDDL string (ASCII). Free with `deinit`.
    pub fn fromSddl(sddl: []const u8) error{ InvalidSddl, NameTooLong }!SecurityDescriptor {
        var wbuf: [1024]u16 = undefined;
        const w = W(&wbuf, sddl) catch |e| switch (e) {
            error.NameTooLong => return error.NameTooLong,
            error.InvalidUtf8 => return error.InvalidSddl,
        };
        var sd: ?PSECURITY_DESCRIPTOR = null;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(w.ptr, SDDL_REVISION_1, &sd, null) == 0) return error.InvalidSddl;
        return .{ .sd = sd.? };
    }

    pub fn deinit(s: *SecurityDescriptor) void {
        _ = LocalFree(s.sd);
        s.* = undefined;
    }

    pub fn attributes(s: *const SecurityDescriptor) SECURITY_ATTRIBUTES {
        return .{ .descriptor = s.sd };
    }

    pub fn dacl(s: *const SecurityDescriptor) ?*ACL {
        var present: BOOL = 0;
        var defaulted: BOOL = 0;
        var acl: ?*ACL = null;
        if (GetSecurityDescriptorDacl(s.sd, &present, &acl, &defaulted) == 0 or present == 0) return null;
        return acl;
    }
};
