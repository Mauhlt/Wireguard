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
}
