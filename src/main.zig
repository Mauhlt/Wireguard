//! `zwg`: command-line front end (owned by the device agent; see DESIGN.md).
//!
//!   zwg genkey               new private key (base64) on stdout
//!   zwg pubkey               private key on stdin -> public key on stdout
//!   zwg show <file.conf>     the parsed configuration, `wg show` style, no secrets
//!   zwg up <file.conf>       run the tunnel in the foreground (Ctrl+C or `zwg down` stops it)
//!   zwg down <name|file.conf>  stop a running `zwg up` for that interface
//!
//! The interface name is the file name without ".conf" (as wg-quick and
//! WireGuard for Windows name tunnels).

const std = @import("std");
const wg = @import("WireGuard");
const dev = wg.device;
const keys = dev.keys;
const config = dev.config;

const usage =
    \\Usage: zwg <command> [arguments]
    \\
    \\  genkey                 print a new private key
    \\  pubkey                 read a private key on stdin, print its public key
    \\  show <file.conf>       show a configuration (keys other than public ones hidden)
    \\  up <file.conf>         bring the tunnel up (foreground; needs Administrator on Windows)
    \\  down <name|file.conf>  stop a tunnel started with `zwg up`
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(gpa);
    var it: std.process.Args.Iterator = try .initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, a);

    var out_buf: [4096]u8 = undefined;
    var out_w = std.Io.File.stdout().writer(io, &out_buf);
    const out = &out_w.interface;
    var err_buf: [1024]u8 = undefined;
    var err_w = std.Io.File.stderr().writer(io, &err_buf);
    const errw = &err_w.interface;

    const code = run(gpa, io, args.items, out, errw) catch |err| blk: {
        errw.print("zwg: {s}\n", .{@errorName(err)}) catch {};
        break :blk 1;
    };
    out.flush() catch {};
    errw.flush() catch {};
    std.process.exit(code);
}

fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    if (args.len == 0) {
        try errw.writeAll(usage);
        return 1;
    }
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "genkey") and args.len == 1) {
        var k = keys.generatePrivate(io);
        defer std.crypto.secureZero(u8, &k);
        var t = keys.encode(&k);
        defer std.crypto.secureZero(u8, &t);
        try out.print("{s}\n", .{&t});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "pubkey") and args.len == 1) {
        var buf: [256]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        var r = std.Io.File.stdin().readerStreaming(io, &.{});
        const n = try r.interface.readSliceShort(&buf);
        const text = std.mem.trim(u8, buf[0..n], " \t\r\n");
        var k = keys.decode(text) catch {
            try errw.writeAll("zwg: key is not the correct length or format\n");
            return 1;
        };
        defer std.crypto.secureZero(u8, &k);
        try out.print("{s}\n", .{&keys.encode(&keys.publicFromPrivate(&k))});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "show") and args.len == 2) {
        var c = (try loadConfig(gpa, io, args[1], errw)) orelse return 1;
        defer c.deinit();
        try dev.show.write(out, interfaceName(args[1]), &c, null, null, 0);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "up") and args.len == 2) {
        var c = (try loadConfig(gpa, io, args[1], errw)) orelse return 1;
        defer c.deinit();
        return up(gpa, io, interfaceName(args[1]), &c, out, errw);
    }
    if (std.mem.eql(u8, cmd, "down") and args.len == 2) {
        const name = interfaceName(args[1]);
        dev.os.StopSignal.signalExisting(name) catch |err| switch (err) {
            error.NotRunning => {
                try errw.print("zwg: no running tunnel named '{s}'\n", .{name});
                return 1;
            },
            else => return err,
        };
        try out.print("stopping {s}\n", .{name});
        return 0;
    }
    try errw.writeAll(usage);
    return 1;
}

/// "C:\tunnels\laptop.conf" -> "laptop"; a bare name stays as it is.
fn interfaceName(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    return if (std.ascii.endsWithIgnoreCase(base, ".conf")) base[0 .. base.len - 5] else base;
}

fn loadConfig(gpa: std.mem.Allocator, io: std.Io, path: []const u8, errw: *std.Io.Writer) !?config.Config {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(config.max_config_bytes)) catch |err| {
        try errw.print("zwg: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };
    defer {
        std.crypto.secureZero(u8, text); // the file holds the private key
        gpa.free(text);
    }
    var diag: config.Diagnostic = .{};
    const c = config.parse(gpa, text, &diag) catch |err| switch (err) {
        error.InvalidConfig => {
            try errw.print("zwg: {s}: {f}\n", .{ path, diag });
            return null;
        },
        else => return err,
    };
    for (c.warnings) |w| try errw.print("zwg: {s}: line {d}: warning: {s}\n", .{ path, w.line, w.message });
    return c;
}

fn up(gpa: std.mem.Allocator, io: std.Io, name: []const u8, c: *const config.Config, out: *std.Io.Writer, errw: *std.Io.Writer) !u8 {
    _ = gpa;
    _ = io;
    _ = c;
    _ = out;
    try errw.print("zwg: up {s}: the device loop is not wired in yet\n", .{name});
    return 1;
}
