// http-zerver: A minimal HTTP server for Windows without std
// Serves static files from a local directory

// Global configuration
var verbose_logging: bool = false;

// Windows API constants and types
const INVALID_SOCKET = 0xFFFFFFFFFFFFFFFF;
const SOCKET_ERROR = -1;
const AF_INET = 2;
const SOCK_STREAM = 1;
const IPPROTO_TCP = 6;
const SD_SEND = 1;
const FIONBIO = 0x8004667E;
const SOMAXCONN = 0x7fffffff;

// Socket options
const SOL_SOCKET = 0xFFFF;
const SO_RCVTIMEO = 0x1006;
const SO_SNDTIMEO = 0x1005;
const SO_REUSEADDR = 0x0004;
const TCP_NODELAY = 0x0001;

const GENERIC_READ = 0x80000000;
const FILE_SHARE_READ = 0x00000001;
const OPEN_EXISTING = 3;
const FILE_ATTRIBUTE_NORMAL = 0x80;
const INVALID_HANDLE_VALUE = @as(usize, 0xFFFFFFFFFFFFFFFF);

// Memory information constants
const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;

// Socket address structure
const sockaddr_in = extern struct {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8,
};

// Socket timeout structure
const TIMEVAL = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

// Memory status structure
const MEMORYSTATUSEX = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
};

// Process memory counters
const PROCESS_MEMORY_COUNTERS = extern struct {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
};

// Windows API functions
extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *WSAData) callconv(.C) i32;
extern "ws2_32" fn WSACleanup() callconv(.C) i32;
extern "ws2_32" fn socket(af: i32, type: i32, protocol: i32) callconv(.C) usize;
extern "ws2_32" fn bind(s: usize, name: *const sockaddr_in, namelen: i32) callconv(.C) i32;
extern "ws2_32" fn listen(s: usize, backlog: i32) callconv(.C) i32;
extern "ws2_32" fn accept(s: usize, addr: ?*sockaddr_in, addrlen: ?*i32) callconv(.C) usize;
extern "ws2_32" fn closesocket(s: usize) callconv(.C) i32;
extern "ws2_32" fn recv(s: usize, buf: [*]u8, len: i32, flags: i32) callconv(.C) i32;
extern "ws2_32" fn send(s: usize, buf: [*]const u8, len: i32, flags: i32) callconv(.C) i32;
extern "ws2_32" fn shutdown(s: usize, how: i32) callconv(.C) i32;
extern "ws2_32" fn htons(hostshort: u16) callconv(.C) u16;
extern "ws2_32" fn setsockopt(s: usize, level: i32, optname: i32, optval: [*]const u8, optlen: i32) callconv(.C) i32;
extern "ws2_32" fn WSAGetLastError() callconv(.C) i32;

// Memory information functions
extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *MEMORYSTATUSEX) callconv(.C) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.C) usize;
extern "psapi" fn GetProcessMemoryInfo(
    Process: usize,
    ppsmemCounters: *PROCESS_MEMORY_COUNTERS,
    cb: u32,
) callconv(.C) i32;

// File I/O functions
extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?*anyopaque,
) callconv(.C) usize;
extern "kernel32" fn ReadFile(
    hFile: usize,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *u32,
    lpOverlapped: ?*anyopaque,
) callconv(.C) i32;
extern "kernel32" fn CloseHandle(hObject: usize) callconv(.C) i32;
extern "kernel32" fn GetFileSize(hFile: usize, lpFileSizeHigh: ?*u32) callconv(.C) u32;
extern "kernel32" fn GetLastError() callconv(.C) u32;

// Console output
extern "kernel32" fn GetStdHandle(nStdHandle: u32) callconv(.C) usize;
extern "kernel32" fn WriteConsoleA(
    hConsoleOutput: usize,
    lpBuffer: [*]const u8,
    nNumberOfCharsToWrite: u32,
    lpNumberOfCharsWritten: *u32,
    lpReserved: ?*anyopaque,
) callconv(.C) i32;

// WSA data structure
const WSAData = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?*u8,
};

// HTTP request structure
const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    version: []const u8,
};

// MIME type mapping
fn getMimeType(path: []const u8) []const u8 {
    if (endsWith(path, ".html") or endsWith(path, ".htm")) {
        return "text/html";
    } else if (endsWith(path, ".css")) {
        return "text/css";
    } else if (endsWith(path, ".js")) {
        return "application/javascript";
    } else if (endsWith(path, ".wasm")) {
        return "application/wasm";
    } else if (endsWith(path, ".png")) {
        return "image/png";
    } else if (endsWith(path, ".jpg") or endsWith(path, ".jpeg")) {
        return "image/jpeg";
    } else if (endsWith(path, ".gif")) {
        return "image/gif";
    } else if (endsWith(path, ".svg")) {
        return "image/svg+xml";
    } else if (endsWith(path, ".json")) {
        return "application/json";
    } else {
        return "application/octet-stream";
    }
}

// String utilities
fn endsWith(str: []const u8, suffix: []const u8) bool {
    if (str.len < suffix.len) return false;
    return eql(str[str.len - suffix.len ..], suffix);
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    return eql(str[0..prefix.len], prefix);
}

// Parse HTTP request
fn parseRequest(buffer: []const u8) !HttpRequest {
    var method_end: usize = 0;
    while (method_end < buffer.len and buffer[method_end] != ' ') : (method_end += 1) {}
    if (method_end >= buffer.len) return error.InvalidRequest;

    const path_start = method_end + 1;
    var path_end = path_start;
    while (path_end < buffer.len and buffer[path_end] != ' ') : (path_end += 1) {}
    if (path_end >= buffer.len) return error.InvalidRequest;

    const version_start = path_end + 1;
    var version_end = version_start;
    while (version_end < buffer.len and buffer[version_end] != '\r') : (version_end += 1) {}
    if (version_end >= buffer.len) return error.InvalidRequest;

    return HttpRequest{
        .method = buffer[0..method_end],
        .path = buffer[path_start..path_end],
        .version = buffer[version_start..version_end],
    };
}

// Print to console
fn print(message: []const u8) void {
    const stdout = GetStdHandle(0xFFFFFFF5); // STD_OUTPUT_HANDLE
    var written: u32 = 0;
    _ = WriteConsoleA(stdout, message.ptr, @intCast(message.len), &written, null);
}

// Debug function to print file paths
fn debugPrint(prefix: []const u8, message: []const u8) void {
    if (verbose_logging) {
        print(prefix);
        print(": ");
        print(message);
        print("\n");
    }
}

// Log memory usage
fn logMemoryUsage(context: []const u8) void {
    if (!verbose_logging) return;

    print("[MEMORY] ");
    print(context);
    print(": ");

    // Get system memory information
    var memStatus = MEMORYSTATUSEX{
        .dwLength = @sizeOf(MEMORYSTATUSEX),
        .dwMemoryLoad = 0,
        .ullTotalPhys = 0,
        .ullAvailPhys = 0,
        .ullTotalPageFile = 0,
        .ullAvailPageFile = 0,
        .ullTotalVirtual = 0,
        .ullAvailVirtual = 0,
        .ullAvailExtendedVirtual = 0,
    };

    if (GlobalMemoryStatusEx(&memStatus) != 0) {
        print("System Memory: ");
        print("Load=");
        printInt(@intCast(memStatus.dwMemoryLoad));
        print("%, ");

        print("Available=");
        printSize(memStatus.ullAvailPhys);
        print("/");
        printSize(memStatus.ullTotalPhys);
        print(" ");
    } else {
        print("Failed to get system memory info. ");
    }

    // Get process memory information
    var procMem = PROCESS_MEMORY_COUNTERS{
        .cb = @sizeOf(PROCESS_MEMORY_COUNTERS),
        .PageFaultCount = 0,
        .PeakWorkingSetSize = 0,
        .WorkingSetSize = 0,
        .QuotaPeakPagedPoolUsage = 0,
        .QuotaPagedPoolUsage = 0,
        .QuotaPeakNonPagedPoolUsage = 0,
        .QuotaNonPagedPoolUsage = 0,
        .PagefileUsage = 0,
        .PeakPagefileUsage = 0,
    };

    const process = GetCurrentProcess();
    if (GetProcessMemoryInfo(process, &procMem, @sizeOf(PROCESS_MEMORY_COUNTERS)) != 0) {
        print("Process: ");
        print("Working Set=");
        printSize(procMem.WorkingSetSize);
        print(" (Peak=");
        printSize(procMem.PeakWorkingSetSize);
        print("), ");

        print("PageFile=");
        printSize(procMem.PagefileUsage);
        print(" (Peak=");
        printSize(procMem.PeakPagefileUsage);
        print(")");
    } else {
        print("Failed to get process memory info");
    }

    print("\n");
}

// Print size in human-readable format
fn printSize(size: usize) void {
    if (size < 1024) {
        printInt(@intCast(size));
        print(" B");
    } else if (size < 1024 * 1024) {
        printInt(@intCast(size / 1024));
        print(" KB");
    } else if (size < 1024 * 1024 * 1024) {
        printInt(@intCast(size / (1024 * 1024)));
        print(" MB");
    } else {
        printInt(@intCast(size / (1024 * 1024 * 1024)));
        print(" GB");
    }
}

// Main server function
pub fn serve(port: u16, directory: []const u8, verbose: bool) !void {
    // Set global verbose flag
    verbose_logging = verbose;

    // Log initial memory usage
    logMemoryUsage("Server starting");

    // Initialize Winsock
    var wsa_data: WSAData = undefined;
    const result = WSAStartup(0x0202, &wsa_data); // Version 2.2
    if (result != 0) {
        print("WSAStartup failed\n");
        return error.WSAStartupFailed;
    }
    defer _ = WSACleanup();

    // Create socket
    const server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        print("Socket creation failed\n");
        return error.SocketCreationFailed;
    }
    defer _ = closesocket(server_socket);

    // Set socket options for reuse
    var opt_val: i32 = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, @ptrCast(&opt_val), @sizeOf(i32)) == SOCKET_ERROR) {
        print("Failed to set SO_REUSEADDR\n");
        // Continue anyway, not critical
    }

    // Bind socket
    var server_addr = sockaddr_in{
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = 0, // INADDR_ANY
        .sin_zero = [_]u8{0} ** 8,
    };

    if (bind(server_socket, &server_addr, @sizeOf(sockaddr_in)) == SOCKET_ERROR) {
        print("Bind failed\n");
        return error.BindFailed;
    }

    // Listen for connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        print("Listen failed\n");
        return error.ListenFailed;
    }

    print("HTTP server started on port ");
    printInt(port);
    print("\nServing directory: ");
    print(directory);
    print("\nPress Ctrl+C to stop\n");

    // Debug: Print current working directory
    var cwd_buf: [260]u8 = undefined;
    const cwd_len = GetCurrentDirectoryA(cwd_buf.len, &cwd_buf);
    if (cwd_len > 0) {
        print("Current working directory: ");
        print(cwd_buf[0..cwd_len]);
        print("\n");
    }

    // Log memory usage after initialization
    logMemoryUsage("Server initialized");

    // Counter for periodic memory logging
    var request_counter: u32 = 0;
    var active_connections: u32 = 0;

    // Accept and handle connections
    while (true) {
        const client_socket = accept(server_socket, null, null);
        if (client_socket == INVALID_SOCKET) {
            print("Accept failed\n");
            continue;
        }

        // Set socket timeouts to prevent hanging connections
        var timeout = TIMEVAL{
            .tv_sec = 10, // 10 seconds timeout
            .tv_usec = 0,
        };

        // Set receive timeout
        if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, @ptrCast(&timeout), @sizeOf(TIMEVAL)) == SOCKET_ERROR) {
            debugPrint("Failed to set SO_RCVTIMEO", intToStr(@intCast(WSAGetLastError())));
            // Continue anyway
        }

        // Set send timeout
        if (setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, @ptrCast(&timeout), @sizeOf(TIMEVAL)) == SOCKET_ERROR) {
            debugPrint("Failed to set SO_SNDTIMEO", intToStr(@intCast(WSAGetLastError())));
            // Continue anyway
        }

        // Enable TCP_NODELAY to disable Nagle's algorithm
        if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, @ptrCast(&opt_val), @sizeOf(i32)) == SOCKET_ERROR) {
            debugPrint("Failed to set TCP_NODELAY", intToStr(@intCast(WSAGetLastError())));
            // Continue anyway
        }

        // Log memory usage periodically (every 10 requests)
        request_counter += 1;
        active_connections += 1;
        if (request_counter % 10 == 0) {
            logMemoryUsage("After handling 10 requests");
            print("Active connections: ");
            printInt(@intCast(active_connections));
            print("\n");
        }

        handleConnection(client_socket, directory);
        active_connections -= 1;
    }
}

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

fn handleConnection(client_socket: usize, directory: []const u8) void {
    defer {
        // Ensure socket is properly closed
        _ = shutdown(client_socket, SD_SEND);
        _ = closesocket(client_socket);

        if (verbose_logging) {
            debugPrint("Connection closed", "Socket resources released");
        }
    }

    var buffer: [4096]u8 = undefined;
    const bytes_received = recv(client_socket, &buffer, buffer.len, 0);

    if (bytes_received <= 0) {
        if (verbose_logging) {
            if (bytes_received == 0) {
                debugPrint("Connection closed by client", "");
            } else {
                debugPrint("Receive error", intToStr(@intCast(WSAGetLastError())));
            }
        }
        return;
    }

    // Log memory usage for large requests
    if (bytes_received > 2048 and verbose_logging) {
        logMemoryUsage("Large request received");
    }

    const request = parseRequest(buffer[0..@intCast(bytes_received)]) catch {
        sendErrorResponse(client_socket, 400, "Bad Request");
        return;
    };

    // Debug: Print request details
    debugPrint("Request method", request.method);
    debugPrint("Request path", request.path);
    debugPrint("Request version", request.version);

    // Only handle GET requests
    if (!eql(request.method, "GET")) {
        sendErrorResponse(client_socket, 405, "Method Not Allowed");
        return;
    }

    // Normalize path and remove query parameters
    var path_buf: [260]u8 = undefined; // MAX_PATH
    var path_len: usize = 0;

    // Start with the directory
    debugPrint("Directory parameter", directory);
    for (directory) |c| {
        path_buf[path_len] = c;
        path_len += 1;
    }

    // Add trailing backslash if needed
    if (path_len > 0 and path_buf[path_len - 1] != '\\' and path_buf[path_len - 1] != '/') {
        path_buf[path_len] = '\\';
        path_len += 1;
    }

    // Add path from request (skip leading slash)
    var req_path = request.path;
    if (req_path.len > 0 and req_path[0] == '/') {
        req_path = req_path[1..];
    }

    // Remove query parameters if present
    var query_pos: usize = 0;
    while (query_pos < req_path.len) : (query_pos += 1) {
        if (req_path[query_pos] == '?') {
            req_path = req_path[0..query_pos];
            break;
        }
    }

    debugPrint("Request path (normalized)", req_path);

    // If path is empty, serve index.html
    if (req_path.len == 0) {
        const index = "index.html";
        debugPrint("Using default file", index);
        for (index) |c| {
            path_buf[path_len] = c;
            path_len += 1;
        }
    } else {
        // Otherwise use the requested path
        for (req_path) |c| {
            // Convert forward slashes to backslashes for Windows
            if (c == '/') {
                path_buf[path_len] = '\\';
            } else {
                path_buf[path_len] = c;
            }
            path_len += 1;
        }
    }

    // Null terminate for Windows API
    path_buf[path_len] = 0;

    // Debug: Print full file path
    debugPrint("Full file path", path_buf[0..path_len]);

    // Log memory before file operations
    if (verbose_logging) {
        logMemoryUsage("Before file operations");
    }

    // Check if file exists before trying to open it
    const file_attrs = GetFileAttributesA(@ptrCast(&path_buf));
    if (file_attrs == 0xFFFFFFFF) { // INVALID_FILE_ATTRIBUTES
        const error_code = GetLastError();
        debugPrint("File not found, error code", intToStr(error_code));
        sendErrorResponse(client_socket, 404, "Not Found");
        return;
    }

    // Check if it's a directory
    if ((file_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        debugPrint("Path is a directory", path_buf[0..path_len]);

        // Check if the request path ends with a slash
        const should_redirect = req_path.len > 0 and req_path[req_path.len - 1] != '/';

        if (should_redirect) {
            // Redirect to add trailing slash
            print("Redirecting to add trailing slash\n");

            var redirect_buf: [1024]u8 = undefined;
            var redirect_len: usize = 0;

            // HTTP/1.1 301 Moved Permanently
            const status = "HTTP/1.1 301 Moved Permanently\r\n";
            for (status) |c| {
                redirect_buf[redirect_len] = c;
                redirect_len += 1;
            }

            // Location header
            const location = "Location: ";
            for (location) |c| {
                redirect_buf[redirect_len] = c;
                redirect_len += 1;
            }

            // Add the request path
            for (request.path) |c| {
                redirect_buf[redirect_len] = c;
                redirect_len += 1;
            }

            // Add trailing slash
            redirect_buf[redirect_len] = '/';
            redirect_len += 1;

            // End of header
            redirect_buf[redirect_len] = '\r';
            redirect_len += 1;
            redirect_buf[redirect_len] = '\n';
            redirect_len += 1;

            // Content-Length: 0
            const content_length = "Content-Length: 0\r\n";
            for (content_length) |c| {
                redirect_buf[redirect_len] = c;
                redirect_len += 1;
            }

            // Connection: close
            const connection_close = "Connection: close\r\n";
            for (connection_close) |c| {
                redirect_buf[redirect_len] = c;
                redirect_len += 1;
            }

            // End of headers
            redirect_buf[redirect_len] = '\r';
            redirect_len += 1;
            redirect_buf[redirect_len] = '\n';
            redirect_len += 1;

            // Send redirect
            _ = send(client_socket, &redirect_buf, @intCast(redirect_len), 0);
            _ = shutdown(client_socket, SD_SEND);
            return;
        }

        // Look for index.html in the directory
        var index_path_buf: [512]u8 = undefined;
        var index_path_len: usize = 0;

        for (path_buf[0..path_len]) |c| {
            index_path_buf[index_path_len] = c;
            index_path_len += 1;
        }

        // Remove null terminator if present
        if (index_path_len > 0 and index_path_buf[index_path_len - 1] == 0) {
            index_path_len -= 1;
        }

        // Add index.html
        const index_file = "\\index.html";
        for (index_file) |c| {
            index_path_buf[index_path_len] = c;
            index_path_len += 1;
        }

        // Null terminate
        index_path_buf[index_path_len] = 0;

        // Check if index.html exists
        const index_attrs = GetFileAttributesA(@ptrCast(&index_path_buf));
        if (index_attrs != 0xFFFFFFFF and (index_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            // Index file exists, serve it
            debugPrint("Serving index file", index_path_buf[0..index_path_len]);

            // Open the index file
            const file_handle = CreateFileA(@ptrCast(&index_path_buf), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);

            if (file_handle == INVALID_HANDLE_VALUE) {
                const error_code = GetLastError();
                debugPrint("Failed to open index file, error code", intToStr(error_code));
                sendErrorResponse(client_socket, 500, "Internal Server Error");
                return;
            }
            defer _ = CloseHandle(file_handle);

            // Get file size
            const file_size = GetFileSize(file_handle, null);
            if (file_size == 0xFFFFFFFF) { // INVALID_FILE_SIZE
                sendErrorResponse(client_socket, 500, "Internal Server Error");
                return;
            }

            // Log memory usage for large files
            if (file_size > 1024 * 1024 and verbose_logging) { // Log for files > 1MB
                logMemoryUsage("Before sending large index file");
            }

            // Determine MIME type
            const mime_type = getMimeType("index.html");

            // Send HTTP headers
            var header_buf: [1024]u8 = undefined;
            var header_len: usize = 0;

            // HTTP/1.1 200 OK
            const status = "HTTP/1.1 200 OK\r\n";
            for (status) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }

            // Content-Type
            const content_type = "Content-Type: ";
            for (content_type) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }
            for (mime_type) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }
            header_buf[header_len] = '\r';
            header_len += 1;
            header_buf[header_len] = '\n';
            header_len += 1;

            // Content-Length
            const content_length = "Content-Length: ";
            for (content_length) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }

            // Convert file size to string
            var size_buf: [20]u8 = undefined;
            var size_len: usize = 0;
            var size_val = file_size;

            if (size_val == 0) {
                size_buf[0] = '0';
                size_len = 1;
            } else {
                while (size_val > 0) {
                    size_buf[size_len] = @intCast('0' + (size_val % 10));
                    size_val /= 10;
                    size_len += 1;
                }

                // Reverse the digits
                var j: usize = 0;
                var k: usize = size_len - 1;
                while (j < k) {
                    const temp = size_buf[j];
                    size_buf[j] = size_buf[k];
                    size_buf[k] = temp;
                    j += 1;
                    k -= 1;
                }
            }

            for (size_buf[0..size_len]) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }

            header_buf[header_len] = '\r';
            header_len += 1;
            header_buf[header_len] = '\n';
            header_len += 1;

            // Connection: close header
            const connection_close = "Connection: close\r\n";
            for (connection_close) |c| {
                header_buf[header_len] = c;
                header_len += 1;
            }

            // End of headers
            header_buf[header_len] = '\r';
            header_len += 1;
            header_buf[header_len] = '\n';
            header_len += 1;

            // Send headers
            debugPrint("Sending HTTP headers for index file", header_buf[0..header_len]);
            _ = send(client_socket, &header_buf, @intCast(header_len), 0);

            // Send file content
            if (!sendFileContent(client_socket, file_handle, file_size)) {
                debugPrint("Failed to send index file content", "");
                return;
            }

            // Log memory usage after sending large files
            if (file_size > 1024 * 1024 and verbose_logging) {
                logMemoryUsage("After sending large index file");
            }

            // Close the connection
            debugPrint("Closing connection after serving index file", "");
            _ = shutdown(client_socket, SD_SEND);
            return;
        } else {
            // No index file, generate directory listing
            listDirectory(client_socket, path_buf[0..path_len], request.path);
            return;
        }
    }

    // Open the file
    const file_handle = CreateFileA(@ptrCast(&path_buf), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);

    if (file_handle == INVALID_HANDLE_VALUE) {
        const error_code = GetLastError();
        debugPrint("Failed to open file, error code", intToStr(error_code));
        sendErrorResponse(client_socket, 404, "Not Found");
        return;
    }
    defer _ = CloseHandle(file_handle);

    debugPrint("File opened successfully", "");

    // Get file size
    const file_size = GetFileSize(file_handle, null);
    if (file_size == 0xFFFFFFFF) { // INVALID_FILE_SIZE
        sendErrorResponse(client_socket, 500, "Internal Server Error");
        return;
    }

    // Log memory usage for large files
    if (file_size > 1024 * 1024 and verbose_logging) { // Log for files > 1MB
        logMemoryUsage("Before sending large file");
    }

    // Determine MIME type
    const mime_type = getMimeType(path_buf[0..path_len]);

    // Send HTTP headers
    var header_buf: [1024]u8 = undefined;
    var header_len: usize = 0;

    // HTTP/1.1 200 OK
    const status = "HTTP/1.1 200 OK\r\n";
    for (status) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // Content-Type
    const content_type = "Content-Type: ";
    for (content_type) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }
    for (mime_type) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }
    header_buf[header_len] = '\r';
    header_len += 1;
    header_buf[header_len] = '\n';
    header_len += 1;

    // Content-Length
    const content_length = "Content-Length: ";
    for (content_length) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // Convert file size to string
    var size_buf: [20]u8 = undefined;
    var size_len: usize = 0;
    var size_val = file_size;

    if (size_val == 0) {
        size_buf[0] = '0';
        size_len = 1;
    } else {
        while (size_val > 0) {
            size_buf[size_len] = @intCast('0' + (size_val % 10));
            size_val /= 10;
            size_len += 1;
        }

        // Reverse the digits
        var j: usize = 0;
        var k: usize = size_len - 1;
        while (j < k) {
            const temp = size_buf[j];
            size_buf[j] = size_buf[k];
            size_buf[k] = temp;
            j += 1;
            k -= 1;
        }
    }

    for (size_buf[0..size_len]) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    header_buf[header_len] = '\r';
    header_len += 1;
    header_buf[header_len] = '\n';
    header_len += 1;

    // Connection: close header
    const connection_close = "Connection: close\r\n";
    for (connection_close) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // End of headers
    header_buf[header_len] = '\r';
    header_len += 1;
    header_buf[header_len] = '\n';
    header_len += 1;

    // Send headers
    debugPrint("Sending HTTP headers", header_buf[0..header_len]);
    _ = send(client_socket, &header_buf, @intCast(header_len), 0);

    // Send file content
    if (!sendFileContent(client_socket, file_handle, file_size)) {
        debugPrint("Failed to send file content", "");
        return;
    }

    // Log memory usage after sending large files
    if (file_size > 1024 * 1024 and verbose_logging) {
        logMemoryUsage("After sending large file");
    }

    // Close the connection
    debugPrint("Closing connection", "");
    _ = shutdown(client_socket, SD_SEND);
}

fn sendErrorResponse(client_socket: usize, status_code: u32, status_text: []const u8) void {
    debugPrint("Sending error response", intToStr(status_code));

    var response_buf: [1024]u8 = undefined;
    var response_len: usize = 0;

    // HTTP status line
    const http_ver = "HTTP/1.1 ";
    for (http_ver) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    // Status code
    var code_buf: [8]u8 = undefined;
    var code_len: usize = 0;
    var code_val = status_code;

    if (code_val == 0) {
        code_buf[0] = '0';
        code_len = 1;
    } else {
        while (code_val > 0) {
            code_buf[code_len] = @intCast('0' + (code_val % 10));
            code_val /= 10;
            code_len += 1;
        }

        // Reverse the digits
        var j: usize = 0;
        var k: usize = code_len - 1;
        while (j < k) {
            const temp = code_buf[j];
            code_buf[j] = code_buf[k];
            code_buf[k] = temp;
            j += 1;
            k -= 1;
        }
    }

    for (code_buf[0..code_len]) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    response_buf[response_len] = ' ';
    response_len += 1;

    // Status text
    for (status_text) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    response_buf[response_len] = '\r';
    response_len += 1;
    response_buf[response_len] = '\n';
    response_len += 1;

    // Headers
    const content_type = "Content-Type: text/html\r\n";
    for (content_type) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    // Create error message
    var body_buf: [256]u8 = undefined;
    var body_len: usize = 0;

    const html_start = "<html><body><h1>";
    for (html_start) |c| {
        body_buf[body_len] = c;
        body_len += 1;
    }

    for (code_buf[0..code_len]) |c| {
        body_buf[body_len] = c;
        body_len += 1;
    }

    body_buf[body_len] = ' ';
    body_len += 1;

    for (status_text) |c| {
        body_buf[body_len] = c;
        body_len += 1;
    }

    const html_end = "</h1></body></html>";
    for (html_end) |c| {
        body_buf[body_len] = c;
        body_len += 1;
    }

    // Content length
    const content_length = "Content-Length: ";
    for (content_length) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    var size_buf: [8]u8 = undefined;
    var size_len: usize = 0;
    var size_val = body_len;

    if (size_val == 0) {
        size_buf[0] = '0';
        size_len = 1;
    } else {
        while (size_val > 0) {
            size_buf[size_len] = @intCast('0' + (size_val % 10));
            size_val /= 10;
            size_len += 1;
        }

        // Reverse the digits
        var j: usize = 0;
        var k: usize = size_len - 1;
        while (j < k) {
            const temp = size_buf[j];
            size_buf[j] = size_buf[k];
            size_buf[k] = temp;
            j += 1;
            k -= 1;
        }
    }

    for (size_buf[0..size_len]) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    response_buf[response_len] = '\r';
    response_len += 1;
    response_buf[response_len] = '\n';
    response_len += 1;

    // Connection: close header
    const connection_close = "Connection: close\r\n";
    for (connection_close) |c| {
        response_buf[response_len] = c;
        response_len += 1;
    }

    // End of headers
    response_buf[response_len] = '\r';
    response_len += 1;
    response_buf[response_len] = '\n';
    response_len += 1;

    // Send headers
    debugPrint("Sending error headers", response_buf[0..response_len]);
    _ = send(client_socket, &response_buf, @intCast(response_len), 0);

    // Send body
    debugPrint("Sending error body", body_buf[0..body_len]);
    _ = send(client_socket, &body_buf, @intCast(body_len), 0);

    // Close the connection
    debugPrint("Closing connection after error", "");
    _ = shutdown(client_socket, SD_SEND);
}

// Helper function to convert integer to string for debugging
fn intToStr(value: u32) []u8 {
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var val = value;

    if (val == 0) {
        buffer[0] = '0';
        i = 1;
    } else {
        while (val > 0) {
            buffer[i] = @intCast('0' + (val % 10));
            val /= 10;
            i += 1;
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
    }

    return buffer[0..i];
}

// Add GetCurrentDirectoryA function declaration
extern "kernel32" fn GetCurrentDirectoryA(nBufferLength: u32, lpBuffer: [*]u8) callconv(.C) u32;
extern "kernel32" fn GetFileAttributesA(lpFileName: [*:0]const u8) callconv(.C) u32;

// Directory listing functions
extern "kernel32" fn FindFirstFileA(lpFileName: [*:0]const u8, lpFindFileData: *WIN32_FIND_DATA) callconv(.C) usize;
extern "kernel32" fn FindNextFileA(hFindFile: usize, lpFindFileData: *WIN32_FIND_DATA) callconv(.C) i32;
extern "kernel32" fn FindClose(hFindFile: usize) callconv(.C) i32;

// File attribute constants
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;

// WIN32_FIND_DATA structure
const WIN32_FIND_DATA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u8,
    cAlternateFileName: [14]u8,
};

const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

// List directory contents and generate HTML
fn listDirectory(client_socket: usize, path: []const u8, request_path: []const u8) void {
    print("Listing directory: ");
    print(path);
    print("\n");

    // Log memory usage before directory listing
    if (verbose_logging) {
        logMemoryUsage("Before directory listing");
    }

    // Create search pattern (path\*)
    var search_pattern: [512]u8 = undefined;
    var pattern_len: usize = 0;

    for (path) |c| {
        search_pattern[pattern_len] = c;
        pattern_len += 1;
    }

    // Add wildcard
    search_pattern[pattern_len] = '\\';
    pattern_len += 1;
    search_pattern[pattern_len] = '*';
    pattern_len += 1;
    search_pattern[pattern_len] = 0; // Null terminate

    // Find first file
    var find_data: WIN32_FIND_DATA = undefined;
    const find_handle = FindFirstFileA(@ptrCast(&search_pattern), &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) {
        sendErrorResponse(client_socket, 500, "Error listing directory");
        return;
    }
    defer _ = FindClose(find_handle);

    // Start building HTML response
    var html_buf: [8192]u8 = undefined;
    var html_len: usize = 0;

    // HTML header
    const html_header =
        "<!DOCTYPE HTML>\n" ++
        "<html lang=\"en\">\n" ++
        "<head>\n" ++
        "    <meta charset=\"utf-8\">\n" ++
        "    <title>Directory listing for ";

    for (html_header) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Add the request path to the title
    for (request_path) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Continue with HTML
    const html_header2 =
        "</title>\n" ++
        "    <style>\n" ++
        "        body { font-family: Arial, sans-serif; margin: 20px; }\n" ++
        "        h1 { border-bottom: 1px solid #ccc; padding-bottom: 10px; }\n" ++
        "        ul { list-style-type: none; padding: 0; }\n" ++
        "        li { margin: 5px 0; }\n" ++
        "        a { text-decoration: none; color: #0366d6; }\n" ++
        "        a:hover { text-decoration: underline; }\n" ++
        "    </style>\n" ++
        "</head>\n" ++
        "<body>\n" ++
        "    <h1>Directory listing for ";

    for (html_header2) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Add the request path again
    for (request_path) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Start the file list
    const html_list_start =
        "</h1>\n" ++
        "    <hr>\n" ++
        "    <ul>\n";

    for (html_list_start) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Add parent directory link if not at root
    if (request_path.len > 1) {
        const parent_link = "        <li><a href=\"..\">..</a> (Parent Directory)</li>\n";
        for (parent_link) |c| {
            html_buf[html_len] = c;
            html_len += 1;
        }
    }

    // Process all files in the directory
    var has_more_files = true;
    var file_count: u32 = 0;

    while (has_more_files) {
        // Get filename as a slice
        var filename_len: usize = 0;
        while (filename_len < find_data.cFileName.len and find_data.cFileName[filename_len] != 0) {
            filename_len += 1;
        }
        const filename = find_data.cFileName[0..filename_len];

        // Skip . and .. entries
        if (!eql(filename, ".") and !eql(filename, "..")) {
            // Start list item
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = '<';
            html_len += 1;
            html_buf[html_len] = 'l';
            html_len += 1;
            html_buf[html_len] = 'i';
            html_len += 1;
            html_buf[html_len] = '>';
            html_len += 1;
            html_buf[html_len] = '<';
            html_len += 1;
            html_buf[html_len] = 'a';
            html_len += 1;
            html_buf[html_len] = ' ';
            html_len += 1;
            html_buf[html_len] = 'h';
            html_len += 1;
            html_buf[html_len] = 'r';
            html_len += 1;
            html_buf[html_len] = 'e';
            html_len += 1;
            html_buf[html_len] = 'f';
            html_len += 1;
            html_buf[html_len] = '=';
            html_len += 1;
            html_buf[html_len] = '"';
            html_len += 1;

            // Add the filename as the link
            for (filename) |c| {
                html_buf[html_len] = c;
                html_len += 1;
            }

            // Add trailing slash for directories
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                html_buf[html_len] = '/';
                html_len += 1;
            }

            html_buf[html_len] = '"';
            html_len += 1;
            html_buf[html_len] = '>';
            html_len += 1;

            // Add the filename as the link text
            for (filename) |c| {
                html_buf[html_len] = c;
                html_len += 1;
            }

            // Add indicators for directories
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                html_buf[html_len] = '/';
                html_len += 1;
            }

            // Close the link and list item
            const item_end = "</a></li>\n";
            for (item_end) |c| {
                html_buf[html_len] = c;
                html_len += 1;
            }

            file_count += 1;

            // Log memory usage periodically for large directories
            if (file_count % 100 == 0 and verbose_logging) {
                logMemoryUsage("During directory listing (files processed)");
            }
        }

        // Find next file
        if (FindNextFileA(find_handle, &find_data) == 0) {
            has_more_files = false;
        }
    }

    // Log memory usage after processing all files
    if (file_count > 100 and verbose_logging) {
        logMemoryUsage("After processing directory with many files");
    }

    // Close the HTML
    const html_footer =
        "    </ul>\n" ++
        "    <hr>\n" ++
        "    <p>http-zerver</p>\n" ++
        "</body>\n" ++
        "</html>\n";

    for (html_footer) |c| {
        html_buf[html_len] = c;
        html_len += 1;
    }

    // Send HTTP headers
    var header_buf: [1024]u8 = undefined;
    var header_len: usize = 0;

    // HTTP/1.1 200 OK
    const status = "HTTP/1.1 200 OK\r\n";
    for (status) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // Content-Type
    const content_type = "Content-Type: text/html; charset=utf-8\r\n";
    for (content_type) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // Content-Length
    const content_length = "Content-Length: ";
    for (content_length) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // Convert HTML length to string
    var size_buf: [20]u8 = undefined;
    var size_len: usize = 0;
    var size_val = html_len;

    if (size_val == 0) {
        size_buf[0] = '0';
        size_len = 1;
    } else {
        while (size_val > 0) {
            size_buf[size_len] = @intCast('0' + (size_val % 10));
            size_val /= 10;
            size_len += 1;
        }

        // Reverse the digits
        var j: usize = 0;
        var k: usize = size_len - 1;
        while (j < k) {
            const temp = size_buf[j];
            size_buf[j] = size_buf[k];
            size_buf[k] = temp;
            j += 1;
            k -= 1;
        }
    }

    for (size_buf[0..size_len]) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    header_buf[header_len] = '\r';
    header_len += 1;
    header_buf[header_len] = '\n';
    header_len += 1;

    // Connection: close header
    const connection_close = "Connection: close\r\n";
    for (connection_close) |c| {
        header_buf[header_len] = c;
        header_len += 1;
    }

    // End of headers
    header_buf[header_len] = '\r';
    header_len += 1;
    header_buf[header_len] = '\n';
    header_len += 1;

    // Send headers
    print("Sending directory listing headers\n");
    _ = send(client_socket, &header_buf, @intCast(header_len), 0);

    // Send HTML content
    print("Sending directory listing HTML\n");
    _ = send(client_socket, &html_buf, @intCast(html_len), 0);

    // Log memory usage after sending directory listing
    if (verbose_logging) {
        logMemoryUsage("After sending directory listing");
    }

    // Close the connection
    print("Closing connection after directory listing\n");
    _ = shutdown(client_socket, SD_SEND);
}

// Send file content with improved error handling
fn sendFileContent(client_socket: usize, file_handle: usize, file_size: u32) bool {
    var read_buf: [8192]u8 = undefined;
    var bytes_read: u32 = 0;
    var total_bytes_sent: u32 = 0;
    var send_result: i32 = 0;

    while (ReadFile(file_handle, &read_buf, read_buf.len, &bytes_read, null) != 0 and bytes_read > 0) {
        debugPrint("Reading file content bytes", intToStr(bytes_read));

        // Send the data with error handling
        send_result = send(client_socket, &read_buf, @intCast(bytes_read), 0);

        if (send_result == SOCKET_ERROR) {
            const error_code = WSAGetLastError();
            debugPrint("Send error", intToStr(@intCast(error_code)));
            return false;
        }

        total_bytes_sent += @intCast(send_result);

        // Log memory usage periodically during large file transfers
        if (file_size > 1024 * 1024 and total_bytes_sent % (1024 * 1024) < bytes_read and verbose_logging) {
            logMemoryUsage("During file transfer");
        }
    }

    // Check if we sent all the data
    if (total_bytes_sent != file_size) {
        debugPrint("Warning: Sent bytes", intToStr(total_bytes_sent));
        debugPrint("Expected file size", intToStr(file_size));
    }

    return true;
}
