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
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;

// ---- errors ----------------------------------------------------------------

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_BROKEN_PIPE: u32 = 109;
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
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
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004; // = FILE_CREATE_PIPE_INSTANCE on a pipe
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_LIST_DIRECTORY: u32 = 0x0001;
pub const FILE_ADD_FILE: u32 = 0x0002;
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
pub const FILE_TRAVERSE: u32 = 0x0020;
pub const FILE_SHARE_READ: u32 = 1;
pub const FILE_SHARE_WRITE: u32 = 2;
pub const FILE_SHARE_DELETE: u32 = 4;
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
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
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
pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
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
pub extern "kernel32" fn MoveFileExW(from: LPCWSTR, to: LPCWSTR, flags: u32) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateNamedPipeW(name: LPCWSTR, open_mode: u32, pipe_mode: u32, max_instances: u32, out_size: u32, in_size: u32, default_timeout: u32, sa: ?*SECURITY_ATTRIBUTES) callconv(.winapi) HANDLE;
pub extern "kernel32" fn ConnectNamedPipe(h: HANDLE, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;
pub extern "kernel32" fn DisconnectNamedPipe(h: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn WaitNamedPipeW(name: LPCWSTR, ms: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetOverlappedResult(h: HANDLE, ov: *OVERLAPPED, n: *u32, wait: BOOL) callconv(.winapi) BOOL;
pub extern "kernel32" fn CancelIoEx(h: HANDLE, ov: ?*OVERLAPPED) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreatePipe(read: *HANDLE, write: *HANDLE, sa: ?*SECURITY_ATTRIBUTES, size: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetSystemDirectoryW(buf: [*]u16, len: u32) callconv(.winapi) u32;
pub extern "kernel32" fn GetFileInformationByHandleEx(h: HANDLE, class: c_int, info: *anyopaque, len: u32) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetFileInformationByHandle(h: HANDLE, class: c_int, info: *const anyopaque, len: u32) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateFileMappingW(file: HANDLE, sa: ?*SECURITY_ATTRIBUTES, protect: u32, size_high: u32, size_low: u32, name: ?LPCWSTR) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn MapViewOfFile(mapping: HANDLE, access: u32, off_high: u32, off_low: u32, size: usize) callconv(.winapi) ?*anyopaque;
pub extern "kernel32" fn UnmapViewOfFile(base: *const anyopaque) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetModuleHandleW(name: ?LPCWSTR) callconv(.winapi) ?*anyopaque;
/// STATUS_SUCCESS (0) when both views are backed by the same file: the
/// loader's own "is this the file that image came from" check.
pub extern "ntdll" fn NtAreMappedFilesTheSame(image_view: *const anyopaque, file_view: *const anyopaque) callconv(.winapi) u32;
pub const PAGE_READONLY: u32 = 0x02;
pub const FILE_MAP_READ: u32 = 0x04;

pub const FileDispositionInfo: c_int = 4;
pub const FileAttributeTagInfo: c_int = 9;
pub const FILE_ATTRIBUTE_TAG_INFO = extern struct { attributes: u32, reparse_tag: u32 };
pub const FILE_DISPOSITION_INFO = extern struct { delete_file: u8 };

// Child processes under another token (the end-to-end driver runs zwg.exe
// as an ordinary user).
pub const STARTF_USESTDHANDLES: u32 = 0x100;
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

pub const STARTUPINFOW = extern struct {
    cb: u32 = @sizeOf(STARTUPINFOW),
    reserved: ?LPWSTR = null,
    desktop: ?LPWSTR = null,
    title: ?LPWSTR = null,
    x: u32 = 0,
    y: u32 = 0,
    x_size: u32 = 0,
    y_size: u32 = 0,
    x_count_chars: u32 = 0,
    y_count_chars: u32 = 0,
    fill_attribute: u32 = 0,
    flags: u32 = 0,
    show_window: u16 = 0,
    cb_reserved2: u16 = 0,
    reserved2: ?*u8 = null,
    std_input: ?HANDLE = null,
    std_output: ?HANDLE = null,
    std_error: ?HANDLE = null,
};
pub const STARTUPINFOEXW = extern struct {
    startup_info: STARTUPINFOW = .{ .cb = @sizeOf(STARTUPINFOEXW) },
    attribute_list: ?*anyopaque = null,
};
pub const PROCESS_INFORMATION = extern struct {
    process: ?HANDLE = null,
    thread: ?HANDLE = null,
    process_id: u32 = 0,
    thread_id: u32 = 0,
};
pub extern "kernel32" fn InitializeProcThreadAttributeList(list: ?*anyopaque, count: u32, flags: u32, size: *usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn UpdateProcThreadAttribute(list: *anyopaque, flags: u32, attribute: usize, value: *const anyopaque, size: usize, prev: ?*anyopaque, ret_size: ?*usize) callconv(.winapi) BOOL;
pub extern "kernel32" fn DeleteProcThreadAttributeList(list: *anyopaque) callconv(.winapi) void;

// ---- advapi32: tokens, SIDs, security descriptors ---------------------------

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ALL_ACCESS: u32 = 0xF01FF;
pub const TokenUser: c_int = 1;
pub const TokenIntegrityLevel: c_int = 25;
pub const SE_GROUP_INTEGRITY: u32 = 0x20;
pub const DISABLE_MAX_PRIVILEGE: u32 = 1;
pub const LUA_TOKEN: u32 = 4;
pub const TokenType: c_int = 8;
pub const TokenPrimary: c_int = 1;
pub const SecurityImpersonation: c_int = 2;

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
pub const SE_DACL_PROTECTED: u16 = 0x1000;

pub extern "advapi32" fn OpenProcessToken(process: HANDLE, access: u32, token: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetTokenInformation(token: HANDLE, class: c_int, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn SetTokenInformation(token: HANDLE, class: c_int, info: *const anyopaque, len: u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateRestrictedToken(existing: HANDLE, flags: u32, disable_count: u32, disable: ?[*]const SID_AND_ATTRIBUTES, delete_priv_count: u32, delete_privs: ?*const anyopaque, restrict_count: u32, restrict: ?[*]const SID_AND_ATTRIBUTES, new_token: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn ImpersonateLoggedOnUser(token: HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn RevertToSelf() callconv(.winapi) BOOL;
pub extern "advapi32" fn DuplicateTokenEx(existing: HANDLE, access: u32, sa: ?*SECURITY_ATTRIBUTES, level: c_int, kind: c_int, new_token: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateProcessAsUserW(token: HANDLE, app: ?LPCWSTR, cmdline: ?LPWSTR, process_sa: ?*SECURITY_ATTRIBUTES, thread_sa: ?*SECURITY_ATTRIBUTES, inherit: BOOL, flags: u32, env: ?*anyopaque, cwd: ?LPCWSTR, si: *STARTUPINFOEXW, pi: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertSidToStringSidW(sid: PSID, out: *?LPWSTR) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertStringSidToSidW(s: LPCWSTR, out: *?PSID) callconv(.winapi) BOOL;
pub extern "advapi32" fn LookupAccountSidW(system: ?LPCWSTR, sid: PSID, name: ?[*]u16, name_len: *u32, domain: ?[*]u16, domain_len: *u32, use: *c_int) callconv(.winapi) BOOL;
pub const SidTypeUser: c_int = 1;
pub extern "advapi32" fn EqualSid(a: PSID, b: PSID) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetLengthSid(sid: PSID) callconv(.winapi) u32;
pub extern "advapi32" fn IsWellKnownSid(sid: PSID, kind: c_int) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: LPCWSTR, revision: u32, sd: *?PSECURITY_DESCRIPTOR, size: ?*u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorDacl(sd: PSECURITY_DESCRIPTOR, present: *BOOL, dacl: *?*ACL, defaulted: *BOOL) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorOwner(sd: PSECURITY_DESCRIPTOR, owner: *?PSID, defaulted: *BOOL) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorControl(sd: PSECURITY_DESCRIPTOR, control: *u16, revision: *u32) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetAce(acl: *ACL, index: u32, ace: *?*anyopaque) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetNamedSecurityInfoW(name: LPCWSTR, kind: c_int, info: u32, owner: ?*?PSID, group: ?*?PSID, dacl: ?*?*ACL, sacl: ?*?*ACL, sd: *?PSECURITY_DESCRIPTOR) callconv(.winapi) u32;
pub extern "advapi32" fn GetSecurityInfo(h: HANDLE, kind: c_int, info: u32, owner: ?*?PSID, group: ?*?PSID, dacl: ?*?*ACL, sacl: ?*?*ACL, sd: *?PSECURITY_DESCRIPTOR) callconv(.winapi) u32;
pub extern "advapi32" fn SetSecurityInfo(h: HANDLE, kind: c_int, info: u32, owner: ?PSID, group: ?PSID, dacl: ?*ACL, sacl: ?*ACL) callconv(.winapi) u32;

// ---- advapi32: service control manager -------------------------------------

pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;

pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
pub const SERVICE_START: u32 = 0x0010;
pub const SERVICE_STOP: u32 = 0x0020;
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
/// FOLDERID_ProgramFiles {905E63B6-C1BF-494E-B29C-65B732D3D21A}
pub const FOLDERID_ProgramFiles: GUID = .{ .data1 = 0x905E63B6, .data2 = 0xC1BF, .data3 = 0x494E, .data4 = .{ 0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A } };

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

/// Does Windows know `sid` (a SID string) as a user account
/// (LookupAccountSidW: SidTypeUser), not a group, alias or well-known SID?
pub fn isUserAccountSid(sid: []const u8) bool {
    var wbuf: [200]u16 = undefined;
    const w = W(&wbuf, sid) catch return false;
    var psid: ?PSID = null;
    if (ConvertStringSidToSidW(w.ptr, &psid) == 0) return false;
    defer _ = LocalFree(psid);
    var name: [257]u16 = undefined;
    var domain: [257]u16 = undefined;
    var name_len: u32 = name.len;
    var domain_len: u32 = domain.len;
    var use: c_int = 0;
    if (LookupAccountSidW(null, psid.?, &name, &name_len, &domain, &domain_len, &use) == 0) return false;
    return use == SidTypeUser;
}

/// Path of the running executable (UTF-16, NUL-terminated, in `buf`).
pub fn selfExePath(buf: []u16) error{Unexpected}![:0]u16 {
    const n = GetModuleFileNameW(null, buf.ptr, @intCast(buf.len));
    if (n == 0 or n >= buf.len) return error.Unexpected;
    buf[n] = 0;
    return buf[0..n :0];
}

/// This process's executable, opened for reading while denying writes and
/// deletes to everyone else, and verified to be the very file the running
/// image was mapped from (not something put at the same path since: a
/// running .exe can be renamed away). Caller closes.
pub fn openRunningImage() error{ Unexpected, NotRunningImage }!HANDLE {
    var buf: [600]u16 = undefined;
    const path = try selfExePath(&buf);
    const h = CreateFileW(path.ptr, GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (h == INVALID_HANDLE_VALUE) return error.NotRunningImage;
    errdefer _ = CloseHandle(h);
    if (!isRunningImage(h)) return error.NotRunningImage;
    return h;
}

/// Is the open file `h` the one this process's image was loaded from?
pub fn isRunningImage(h: HANDLE) bool {
    const mapping = CreateFileMappingW(h, null, PAGE_READONLY, 0, 0, null) orelse return false;
    defer _ = CloseHandle(mapping);
    const view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) orelse return false;
    defer _ = UnmapViewOfFile(view);
    const image = GetModuleHandleW(null) orelse return false;
    return NtAreMappedFilesTheSame(image, view) == 0;
}

/// True when the process token is elevated (one implementation, shared
/// with the Wintun backend).
pub const isElevated = @import("../tun/windows.zig").isElevated;

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

/// A primary token derived from this process's token that looks like an
/// ordinary unelevated user: Administrators deny-only, LUA, privileges
/// stripped, medium integrity. With `deny_user`, the user's own SID is
/// deny-only too (a stand-in for "some other user"). For the tests and the
/// elevated end-to-end driver, which impersonate it to check DACLs.
pub fn restrictedToken(deny_user: bool) error{Unexpected}!HANDLE {
    var token: HANDLE = undefined;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token) == 0) return error.Unexpected;
    defer _ = CloseHandle(token);
    var info: [256]u8 align(8) = undefined;
    var len: u32 = 0;
    if (GetTokenInformation(token, TokenUser, &info, info.len, &len) == 0) return error.Unexpected;
    const tu: *const TOKEN_USER = @ptrCast(&info);

    var ba: ?PSID = null;
    if (ConvertStringSidToSidW(std.unicode.utf8ToUtf16LeStringLiteral("S-1-5-32-544"), &ba) == 0) return error.Unexpected;
    defer _ = LocalFree(ba);
    var medium: ?PSID = null;
    if (ConvertStringSidToSidW(std.unicode.utf8ToUtf16LeStringLiteral("S-1-16-8192"), &medium) == 0) return error.Unexpected;
    defer _ = LocalFree(medium);

    const disable = [_]SID_AND_ATTRIBUTES{ .{ .sid = ba, .attributes = 0 }, .{ .sid = tu.user.sid, .attributes = 0 } };
    var out: HANDLE = undefined;
    if (CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, if (deny_user) 2 else 1, &disable, 0, null, 0, null, &out) == 0)
        return error.Unexpected;
    errdefer _ = CloseHandle(out);
    const label: TOKEN_MANDATORY_LABEL = .{ .label = .{ .sid = medium, .attributes = SE_GROUP_INTEGRITY } };
    if (SetTokenInformation(out, TokenIntegrityLevel, &label, @sizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(medium.?)) == 0)
        return error.Unexpected;
    return out;
}

pub const ChildResult = struct {
    exit_code: u32,
    /// What the child wrote to stdout and stderr (interleaved), truncated
    /// to the caller's buffer.
    output: []u8,
};

/// Run `cmdline` (UTF-8, quoted as for CreateProcess) as a child whose
/// primary token is `token` (`restrictedToken`: a restricted version of this
/// process's own token needs no SeAssignPrimaryTokenPrivilege; an
/// impersonation token is duplicated into a primary one), with stdout and
/// stderr captured into `out`. Only the pipe's write end is inherited.
/// Blocks on the pipe until the child closes it, then on the process handle
/// for at most `timeout_ms`. For the tests and the end-to-end driver.
pub fn runAsToken(token: HANDLE, cmdline: []const u8, out: []u8, timeout_ms: u32) error{ Unexpected, NameTooLong, InvalidUtf8, Timeout }!ChildResult {
    var kind: c_int = 0;
    var len: u32 = 0;
    if (GetTokenInformation(token, TokenType, &kind, @sizeOf(c_int), &len) == 0) return error.Unexpected;
    var primary = token;
    if (kind != TokenPrimary) {
        if (DuplicateTokenEx(token, TOKEN_ALL_ACCESS, null, SecurityImpersonation, TokenPrimary, &primary) == 0) return error.Unexpected;
    }
    defer if (primary != token) {
        _ = CloseHandle(primary);
    };

    var sa: SECURITY_ATTRIBUTES = .{ .inherit = 1 };
    var rd: HANDLE = undefined;
    var wr: HANDLE = undefined;
    if (CreatePipe(&rd, &wr, &sa, 0) == 0) return error.Unexpected;
    defer _ = CloseHandle(rd);
    var wr_open = true;
    defer if (wr_open) {
        _ = CloseHandle(wr);
    };

    var attr_size: usize = 0;
    _ = InitializeProcThreadAttributeList(null, 1, 0, &attr_size);
    var attr_buf: [256]u8 align(16) = undefined;
    if (attr_size == 0 or attr_size > attr_buf.len) return error.Unexpected;
    if (InitializeProcThreadAttributeList(&attr_buf, 1, 0, &attr_size) == 0) return error.Unexpected;
    defer DeleteProcThreadAttributeList(&attr_buf);
    const inherit_list = [1]HANDLE{wr};
    if (UpdateProcThreadAttribute(&attr_buf, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherit_list, @sizeOf(@TypeOf(inherit_list)), null, null) == 0)
        return error.Unexpected;

    var si: STARTUPINFOEXW = .{ .attribute_list = &attr_buf };
    si.startup_info.flags = STARTF_USESTDHANDLES;
    si.startup_info.std_output = wr;
    si.startup_info.std_error = wr;
    var cmd_w: [2048]u16 = undefined;
    const cmd = try W(&cmd_w, cmdline);
    var pi: PROCESS_INFORMATION = .{};
    if (CreateProcessAsUserW(primary, null, cmd.ptr, null, null, 1, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, null, null, &si, &pi) == 0)
        return error.Unexpected;
    defer _ = CloseHandle(pi.process.?);
    _ = CloseHandle(pi.thread.?);
    // Our copy of the write end must go, or the reads below never see EOF.
    _ = CloseHandle(wr);
    wr_open = false;

    var n: usize = 0;
    var sink: [512]u8 = undefined;
    while (true) {
        const dst = if (n < out.len) out[n..] else sink[0..];
        var got: u32 = 0;
        // Blocks until the child writes or exits (ERROR_BROKEN_PIPE ends it).
        if (ReadFile(rd, dst.ptr, @intCast(@min(dst.len, 1 << 20)), &got, null) == 0) break;
        if (n < out.len) n += got;
    }
    if (WaitForSingleObject(pi.process.?, timeout_ms) != WAIT_OBJECT_0) return error.Timeout;
    var code: u32 = 0;
    if (GetExitCodeProcess(pi.process.?, &code) == 0) return error.Unexpected;
    return .{ .exit_code = code, .output = out[0..n] };
}

test "user account SIDs: this user is one, SYSTEM / groups / aliases are not" {
    var buf: [184]u8 = undefined;
    try std.testing.expect(isUserAccountSid(try currentUserSid(&buf)));
    for ([_][]const u8{ "S-1-5-18", "S-1-1-0", "S-1-5-11", "S-1-5-32-544", "S-1-5-32-545", "not a sid" }) |s|
        try std.testing.expect(!isUserAccountSid(s));
}

test "the running image is recognised; a byte-identical copy is not it" {
    const h = try openRunningImage();
    defer _ = CloseHandle(h);
    try std.testing.expect(isRunningImage(h));
    // Writes are denied while it is held.
    var buf: [600]u16 = undefined;
    const self = try selfExePath(&buf);
    const w = CreateFileW(self.ptr, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (w != INVALID_HANDLE_VALUE) {
        _ = CloseHandle(w);
        return error.TestUnexpectedResult;
    }

    // A copy: same bytes, another file.
    var size: i64 = 0;
    try std.testing.expect(GetFileSizeEx(h, &size) != 0);
    const gpa = std.testing.allocator;
    const data = try gpa.alloc(u8, @intCast(size));
    defer gpa.free(data);
    var got: usize = 0;
    while (got < data.len) {
        var n: u32 = 0;
        var ov: OVERLAPPED = .{ .offset = @truncate(got), .offset_high = @truncate(@as(u64, got) >> 32) };
        try std.testing.expect(ReadFile(h, data.ptr + got, @intCast(@min(data.len - got, 1 << 20)), &n, &ov) != 0 and n != 0);
        got += n;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "copy.exe", .data = data });
    var pbuf: [600]u8 = undefined;
    const dn = try tmp.dir.realPath(std.testing.io, &pbuf);
    var cw: [700]u16 = undefined;
    var full: [700]u8 = undefined;
    const copy_path = try std.fmt.bufPrint(&full, "{s}\\copy.exe", .{pbuf[0..dn]});
    const c = CreateFileW((try W(&cw, copy_path)).ptr, GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    try std.testing.expect(c != INVALID_HANDLE_VALUE);
    defer _ = CloseHandle(c);
    try std.testing.expect(!isRunningImage(c));
}

test "runAsToken: a child under a restricted token, exit code and output" {
    const t = try restrictedToken(false);
    defer _ = CloseHandle(t);
    var sysdir: [260]u16 = undefined;
    const sn = GetSystemDirectoryW(&sysdir, sysdir.len);
    if (sn == 0 or sn >= sysdir.len) return error.SkipZigTest;
    var sys_utf8: [800]u8 = undefined;
    const sys = sys_utf8[0..try std.unicode.utf16LeToUtf8(&sys_utf8, sysdir[0..sn])];
    var cmd_buf: [1024]u8 = undefined;
    const cmd = try std.fmt.bufPrint(&cmd_buf, "\"{s}\\cmd.exe\" /d /c echo zwg-child& exit 7", .{sys});
    var out: [256]u8 = undefined;
    const r = try runAsToken(t, cmd, &out, 30_000);
    try std.testing.expectEqual(@as(u32, 7), r.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, r.output, "zwg-child") != null);
}
