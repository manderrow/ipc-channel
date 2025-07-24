const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Forces stripping on all optimization modes") orelse switch (optimize) {
        .Debug => false,
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => true,
    };

    const lib = try createLib(b, target, optimize, strip);

    b.modules.put("ipc_channel", lib.mod) catch @panic("OOM");

    b.installArtifact(lib.static);

    b.installArtifact(lib.dynamic);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib.mod,
        // TODO: when Zig's backend stops producing code that segfaults on macOS, remove override
        .use_llvm = if (target.result.os.tag == .macos) true else null,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addInstallArtifact(lib_unit_tests, .{}).step);
    test_step.dependOn(&run_lib_unit_tests.step);

    const build_all_step = b.step("build-all", "Builds for all supported targets");

    inline for ([_]std.Build.ResolvedTarget{
        b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu }),
        b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .macos }),
        // TODO: Windows implementation
        // b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu }),
    }) |target_2| {
        const lib_2 = try createLib(b, target_2, optimize, strip);
        build_all_step.dependOn(&b.addInstallArtifact(lib_2.static, .{
            .dest_dir = .{ .override = .lib },
        }).step);
        build_all_step.dependOn(&b.addInstallArtifact(lib_2.dynamic, .{
            .dest_dir = .{ .override = .lib },
        }).step);
    }
}

fn createLib(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, strip: bool) !struct {
    mod: *std.Build.Module,
    static: *std.Build.Step.Compile,
    dynamic: *std.Build.Step.Compile,
} {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .link_libc = false,
    });
    return .{
        .mod = mod,
        .static = b.addLibrary(.{
            .linkage = .static,
            .name = "ipc_channel",
            .root_module = mod,
        }),
        .dynamic = b.addLibrary(.{
            .linkage = .dynamic,
            .name = "ipc_channel",
            .root_module = mod,
        }),
    };
}
