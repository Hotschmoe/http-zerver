const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create executable
    const exe = b.addExecutable(.{
        .name = "http-zerver",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link with required Windows libraries
    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("ws2_32");
        exe.linkSystemLibrary("kernel32");
    }

    // Install the executable
    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Add run step
    const run_step = b.step("run", "Run the HTTP server");
    run_step.dependOn(&run_cmd.step);
} 