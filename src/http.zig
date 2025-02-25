// http-zerver: A minimal HTTP server for Windows without std
// Serves static files from a local directory

// Windows API constants and types
const INVALID_SOCKET = 0xFFFFFFFFFFFFFFFF;
const SOCKET_ERROR = -1;
const AF_INET = 2;
const SOCK_STREAM = 1;
const IPPROTO_TCP = 6;
const SD_SEND = 1;
const FIONBIO = 0x8004667E;
const SOMAXCONN = 0x7fffffff;

const GENERIC_READ = 0x80000000;
const FILE_SHARE_READ = 0x00000001;
const OPEN_EXISTING = 3;
const FILE_ATTRIBUTE_NORMAL = 0x80;
const INVALID_HANDLE_VALUE = @as(usize, 0xFFFFFFFFFFFFFFFF);

// Socket address structure
const sockaddr_in = extern struct {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8,
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
    print(prefix);
    print(": ");
    print(message);
    print("\n");
}

// Main server function
pub fn serve(port: u16, directory: []const u8) !void {
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

    // Accept and handle connections
    while (true) {
        const client_socket = accept(server_socket, null, null);
        if (client_socket == INVALID_SOCKET) {
            print("Accept failed\n");
            continue;
        }

        handleConnection(client_socket, directory);
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
    defer _ = closesocket(client_socket);

    var buffer: [4096]u8 = undefined;
    const bytes_received = recv(client_socket, &buffer, buffer.len, 0);

    if (bytes_received <= 0) {
        return;
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

    // Normalize path
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

    // Check if file exists before trying to open it
    const file_attrs = GetFileAttributesA(@ptrCast(&path_buf));
    if (file_attrs == 0xFFFFFFFF) { // INVALID_FILE_ATTRIBUTES
        const error_code = GetLastError();
        debugPrint("File not found, error code", intToStr(error_code));
        sendErrorResponse(client_socket, 404, "Not Found");
        return;
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
    var read_buf: [8192]u8 = undefined;
    var bytes_read: u32 = 0;

    while (ReadFile(file_handle, &read_buf, read_buf.len, &bytes_read, null) != 0 and bytes_read > 0) {
        debugPrint("Sending file content bytes", intToStr(bytes_read));
        _ = send(client_socket, &read_buf, @intCast(bytes_read), 0);
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
