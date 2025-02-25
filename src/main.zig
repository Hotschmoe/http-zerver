// http-zerver: Main entry point
// Handles command-line arguments and starts the HTTP server

const http = @import("http.zig");

// External functions for command-line arguments
extern "kernel32" fn GetCommandLineA() callconv(.Stdcall) [*:0]const u8;
extern "kernel32" fn GetStdHandle(nStdHandle: u32) callconv(.Stdcall) usize;
extern "kernel32" fn WriteConsoleA(
    hConsoleOutput: usize,
    lpBuffer: [*]const u8,
    nNumberOfCharsToWrite: u32,
    lpNumberOfCharsWritten: *u32,
    lpReserved: ?*anyopaque,
) callconv(.Stdcall) i32;

// Print to console
fn print(message: []const u8) void {
    const stdout = GetStdHandle(0xFFFFFFF5); // STD_OUTPUT_HANDLE
    var written: u32 = 0;
    _ = WriteConsoleA(stdout, message.ptr, @intCast(message.len), &written, null);
}

// Parse command line arguments
fn parseArgs() struct { port: u16, directory: []const u8 } {
    const cmd = GetCommandLineA();
    
    // Default values
    var port: u16 = 8000;
    var directory: []const u8 = ".";
    
    // Skip the program name
    var i: usize = 0;
    while (cmd[i] != 0 and (cmd[i] != ' ' or inQuotes(cmd, i))) : (i += 1) {}
    
    // Skip whitespace
    while (cmd[i] != 0 and cmd[i] == ' ') : (i += 1) {}
    
    // Parse port if provided
    if (cmd[i] != 0) {
        var port_start = i;
        while (cmd[i] != 0 and cmd[i] != ' ') : (i += 1) {}
        
        if (i > port_start) {
            port = parsePort(cmd[port_start..i]);
        }
        
        // Skip whitespace
        while (cmd[i] != 0 and cmd[i] == ' ') : (i += 1) {}
        
        // Parse directory if provided
        if (cmd[i] != 0) {
            var dir_start = i;
            while (cmd[i] != 0) : (i += 1) {}
            
            if (i > dir_start) {
                directory = cmd[dir_start..i];
            }
        }
    }
    
    return .{ .port = port, .directory = directory };
}

// Check if character at position i is inside quotes
fn inQuotes(cmd: [*:0]const u8, i: usize) bool {
    var quote_count: usize = 0;
    var j: usize = 0;
    while (j < i) : (j += 1) {
        if (cmd[j] == '"') {
            quote_count += 1;
        }
    }
    return (quote_count % 2) == 1;
}

// Parse port number from string
fn parsePort(str: []const u8) u16 {
    var result: u16 = 0;
    for (str) |c| {
        if (c >= '0' and c <= '9') {
            result = result * 10 + (c - '0');
        } else {
            break;
        }
    }
    return if (result > 0) result else 8000;
}

// Entry point
pub fn main() !void {
    const args = parseArgs();
    
    print("http-zerver: Starting HTTP server\n");
    print("Port: ");
    printInt(args.port);
    print("\nDirectory: ");
    print(args.directory);
    print("\n\n");
    
    try http.serve(args.port, args.directory);
}

// Print integer to console
fn printInt(n: u16) void {
    var buffer: [8]u8 = undefined;
    var i: usize = 0;
    var value = n;

    // Convert to digits
    if (value == 0) {
        buffer[0] = '0';
        i = 1;
    } else {
        while (value > 0) {
            buffer[i] = @intCast('0' + (value % 10));
            value /= 10;
            i += 1;
        }
    }

    // Reverse the digits
    var j: usize = 0;
    var k: usize = i - 1;
    while (j < k) {
        const temp = buffer[j];
        buffer[j] = buffer[k];
        buffer[k] = temp;
        j += 1;
        k -= 1;
    }

    print(buffer[0..i]);
} 