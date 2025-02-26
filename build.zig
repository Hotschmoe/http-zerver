const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Generate version date file
    const gen_date_cmd = b.addSystemCommand(&[_][]const u8{
        "powershell",
        "-Command",
        "(Get-Date -Format 'yyyy-MM-dd').ToString() | Out-File -FilePath src/version_date.txt -NoNewline -Encoding ASCII",
    });

    // Create executable
    const exe = b.addExecutable(.{
        .name = "http-zerver",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Make exe depend on date generation
    exe.step.dependOn(&gen_date_cmd.step);

    // Link with required Windows libraries
    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("ws2_32");
        exe.linkSystemLibrary("kernel32");
        exe.linkSystemLibrary("psapi");
    }

    // Install the executable
    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Create a custom run step that:
    // 1. Deletes all files in /www
    // 2. Copies /assets to /www
    // 3. Copies the executable to /www
    // 4. Runs the server from /www on port 8000

    // Create a custom run step
    const custom_run_step = b.step("run", "Run the HTTP server from /www directory");

    // Add a command to clear the www directory
    const clear_www = b.addSystemCommand(&[_][]const u8{ "powershell", "-Command", "if (Test-Path www) { Remove-Item -Path www\\* -Recurse -Force }; if (-not (Test-Path www)) { New-Item -ItemType Directory -Path www }" });

    // Add a command to copy all files from /assets to /www
    const copy_assets = b.addSystemCommand(&[_][]const u8{ "powershell", "-Command", "if (Test-Path assets) { Copy-Item -Path assets\\* -Destination www\\ -Recurse -Force }" });
    copy_assets.step.dependOn(&clear_www.step);

    // Add a command to copy the executable to /www
    const copy_exe = b.addSystemCommand(&[_][]const u8{
        "powershell",                                        "-Command",            "Copy-Item",
        b.fmt("{s}/bin/http-zerver.exe", .{b.install_path}), "www/http-zerver.exe",
    });
    copy_exe.step.dependOn(b.getInstallStep());
    copy_exe.step.dependOn(&copy_assets.step);

    // Add a command to run the server from /www
    const run_server = b.addSystemCommand(&[_][]const u8{ "powershell", "-Command", "cd www; ./http-zerver.exe 8000 . -v" });
    run_server.step.dependOn(&copy_exe.step);

    custom_run_step.dependOn(&run_server.step);
}
