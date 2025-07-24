const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });

    b.installArtifact(b.addLibrary(.{
        .linkage = .static,
        .name = "ipc_channel",
        .root_module = lib_mod,
    }));

    b.installArtifact(b.addLibrary(.{
        .linkage = .dynamic,
        .name = "ipc_channel",
        .root_module = lib_mod,
    }));

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addInstallArtifact(lib_unit_tests, .{}).step);
    test_step.dependOn(&run_lib_unit_tests.step);
}
