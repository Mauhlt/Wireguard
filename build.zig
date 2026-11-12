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

    const tests = b.addTest(.{ .root_module = mod });
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
    }
}
