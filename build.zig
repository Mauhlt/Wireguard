const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library: noise, session, device, tun (see DESIGN.md).
    const mod = b.addModule("WireGuard", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // `zwg`: bring a .conf up/down, show status, genkey/pubkey.
    const exe = b.addExecutable(.{
        .name = "zwg",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    // `-Dtest-filter=<substring>` builds only the matching tests, e.g. one fuzz
    // target: `zig build test --fuzz=1M -Doptimize=ReleaseSafe -Dtest-filter="fuzz: replay"`
    // (one process per target gives per-target coverage; see src/fuzz.zig).
    const test_filter = b.option([]const u8, "test-filter", "Only build and run tests whose name contains this");
    const tests = b.addTest(.{
        .root_module = mod,
        .filters = if (test_filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(&exe.step);

    // TUN backends for OSes we cannot run here: analysis-only cross builds of
    // src/tun (nothing is linked or run; see src/tun/root.zig).
    const tun_check = b.step("tun-check", "Cross-compile check the Linux/macOS/iOS TUN backends");
    const cross: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86_64, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .ios },
    };
    for (cross) |query| {
        const check = b.addObject(.{
            .name = "tun-check",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/tun/check.zig"),
                .target = b.resolveTargetQuery(query),
                .optimize = optimize,
            }),
        });
        tun_check.dependOn(&check.step);
    }
    test_step.dependOn(tun_check);

    // Interop / known-answer harness (tests/interop, see its README.md).
    const interop = b.step("interop", "Known-answer + cross-implementation tests, FakeTun/UdpTun loopback");
    const golden = b.addTest(.{
        .name = "interop-golden",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/golden.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = mod }},
        }),
    });
    interop.dependOn(&b.addRunArtifact(golden).step);

    // Two zwg processes over 127.0.0.1 with UdpTun TUNs (SKIPs until zwg
    // advertises `up <conf> --tun udp:<port>`).
    const loopback = b.addExecutable(.{
        .name = "zwg-interop-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = mod }},
        }),
    });
    const run_loopback = b.addRunArtifact(loopback);
    run_loopback.addArtifactArg(exe);
    interop.dependOn(&run_loopback.step);

    // The same runner against refpeer (reference model + UdpTun): proves the
    // harness and UdpTun across real processes before zwg exists.
    const refpeer = b.addExecutable(.{
        .name = "zwg-interop-refpeer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/refpeer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = mod }},
        }),
    });
    const run_loopback_ref = b.addRunArtifact(loopback);
    run_loopback_ref.addArtifactArg(refpeer);
    interop.dependOn(&run_loopback_ref.step);

    // Cross-implementation over real processes: zwg (A) <-> refpeer (B).
    const run_loopback_cross = b.addRunArtifact(loopback);
    run_loopback_cross.addArtifactArg(exe);
    run_loopback_cross.addArtifactArg(refpeer);
    interop.dependOn(&run_loopback_cross.step);

    // Live tests against Linux / WSL (tests/interop/README.md, "Live test:
    // Windows (Wintun) <-> WSL"). The Linux side is always built for Linux:
    // natively on Linux, cross-compiled (pure Zig, no libc) elsewhere, so the
    // Windows driver can run it inside WSL without a Zig install there.
    const linux_target = if (target.result.os.tag == .linux)
        target
    else
        b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux });
    const linux_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = linux_target,
        .optimize = optimize,
    });
    const zwg_linux = b.addExecutable(.{
        .name = "zwg",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = linux_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = linux_mod }},
        }),
    });
    const live_linux = b.addExecutable(.{
        .name = "zwg-live-linux",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/live_linux.zig"),
            .target = linux_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "WireGuard", .module = linux_mod }},
        }),
    });
    const to_linux_dir: std.Build.Step.InstallArtifact.Options = .{ .dest_dir = .{ .override = .{ .custom = "linux" } } };
    const live_linux_step = b.step("interop-live-linux", "Build zig-out/linux/{zwg,zwg-live-linux} (run `zwg-live-linux netns-test` as root)");
    live_linux_step.dependOn(&b.addInstallArtifact(zwg_linux, to_linux_dir).step);
    live_linux_step.dependOn(&b.addInstallArtifact(live_linux, to_linux_dir).step);
    interop.dependOn(&live_linux.step); // keep it compiling

    // Wintun: the official signed DLL, never committed. `-Dwintun=<folder>`
    // (or ZWG_WINTUN_DIR) points at the unzipped release from wintun.net;
    // `zig build` then copies wintun\bin\<arch>\wintun.dll next to zwg.exe.
    if (target.result.os.tag == .windows) {
        const wintun_dir = b.option([]const u8, "wintun", "Folder with the unzipped official Wintun release (copies wintun.dll next to zwg.exe)") orelse
            b.graph.environ_map.get("ZWG_WINTUN_DIR");
        if (wintun_dir) |dir| {
            const arch: []const u8 = switch (target.result.cpu.arch) {
                .x86_64 => "amd64",
                .aarch64 => "arm64",
                .x86 => "x86",
                else => "arm",
            };
            const candidates = [_][]const u8{
                b.pathJoin(&.{ dir, "wintun", "bin", arch, "wintun.dll" }),
                b.pathJoin(&.{ dir, "bin", arch, "wintun.dll" }),
                b.pathJoin(&.{ dir, "wintun.dll" }),
            };
            const found = for (candidates) |p| {
                std.Io.Dir.cwd().access(b.graph.io, p, .{}) catch continue;
                break p;
            } else null;
            if (found) |p| {
                b.getInstallStep().dependOn(&b.addInstallBinFile(.{ .cwd_relative = p }, "wintun.dll").step);
            } else {
                b.getInstallStep().dependOn(&b.addFail(b.fmt("-Dwintun={s}: no wintun\\bin\\{s}\\wintun.dll there (unzip the release from https://www.wintun.net/)", .{ dir, arch })).step);
            }
        }
    }

    // Live interop with WireGuard for Windows: built here, run by hand from an
    // elevated prompt (tests/interop/README.md).
    if (target.result.os.tag == .windows) {
        const live = b.addExecutable(.{
            .name = "zwg-interop-live",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/interop/live.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "WireGuard", .module = mod }},
            }),
        });
        const live_step = b.step("interop-live", "Build zwg-interop-live.exe (run it elevated; see tests/interop/README.md)");
        live_step.dependOn(&b.addInstallArtifact(live, .{}).step);
        live_step.dependOn(b.getInstallStep());
        interop.dependOn(&live.step); // keep it compiling

        // Live test Windows (real Wintun adapter) <-> WSL2: kernel WireGuard and
        // zwg for Linux inside WSL. Built here, run once elevated.
        const live_wsl = b.addExecutable(.{
            .name = "zwg-live-wsl",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/interop/live_wsl.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "WireGuard", .module = mod }},
            }),
        });
        const live_wsl_step = b.step("interop-live-wsl", "Build zwg-live-wsl.exe + zwg.exe (+ wintun.dll with -Dwintun) + the Linux side (run it elevated; see tests/interop/README.md)");
        live_wsl_step.dependOn(&b.addInstallArtifact(live_wsl, .{}).step);
        live_wsl_step.dependOn(b.getInstallStep());
        live_wsl_step.dependOn(live_linux_step);
        interop.dependOn(&live_wsl.step); // keep it compiling

        // The tunnel service (zwg installtunnel) end to end: built here,
        // run once by hand from an elevated prompt (tests/interop/README.md).
        const service_live = b.addExecutable(.{
            .name = "zwg-service-live",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/interop/service_live.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "WireGuard", .module = mod }},
            }),
        });
        const service_step = b.step("interop-service", "Build zwg-service-live.exe (run it elevated; see tests/interop/README.md)");
        service_step.dependOn(&b.addInstallArtifact(service_live, .{}).step);
        service_step.dependOn(b.getInstallStep());
        interop.dependOn(&service_live.step); // keep it compiling
    }
}
