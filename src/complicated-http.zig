// half way one-shot by claude

const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

// Socket types and constants - OS dependent
const SOCKET = if (is_windows) usize else i32;
const SOCKET_ERROR = if (is_windows) @as(SOCKET, @bitCast(@as(usize, 0) -% 1)) else -1;
const INVALID_SOCKET = if (is_windows) @as(SOCKET, @bitCast(@as(usize, 0) -% 1)) else -1;

// Common constants
const DEFAULT_PORT = 8000;
const BUFFER_SIZE = 8192;

// OS-specific imports
const os = if (is_windows) struct {
    const windows = @cImport({
        @cInclude("winsock2.h");
        @cInclude("ws2tcpip.h");
        @cInclude("windows.h");
    });

    const AF_INET = windows.AF_INET;
    const SOCK_STREAM = windows.SOCK_STREAM;
    const SOMAXCONN = windows.SOMAXCONN;
    const sockaddr = windows.sockaddr;
    const sockaddr_in = windows.sockaddr_in;
    const socket = windows.socket;
    const bind = windows.bind;
    const listen = windows.listen;
    const accept = windows.accept;
    const closesocket = windows.closesocket;
    const recv = windows.recv;
    const send = windows.send;
    const WSAStartup = windows.WSAStartup;
    const WSACleanup = windows.WSACleanup;
    const inet_ntoa = windows.inet_ntoa;
    const htons = windows.htons;
    const WSADATA = windows.WSADATA;
    const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
    const CreateFileA = windows.CreateFileA;
    const ReadFile = windows.ReadFile;
    const CloseHandle = windows.CloseHandle;
    const GetFileSize = windows.GetFileSize;
    const GENERIC_READ = windows.GENERIC_READ;
    const FILE_SHARE_READ = windows.FILE_SHARE_READ;
    const OPEN_EXISTING = windows.OPEN_EXISTING;
    const FILE_ATTRIBUTE_NORMAL = windows.FILE_ATTRIBUTE_NORMAL;
    const GetCurrentDirectoryA = windows.GetCurrentDirectoryA;
    const FindFirstFileA = windows.FindFirstFileA;
    const FindNextFileA = windows.FindNextFileA;
    const FindClose = windows.FindClose;
    const WIN32_FIND_DATAA = windows.WIN32_FIND_DATAA;
    const FILE_ATTRIBUTE_DIRECTORY = windows.FILE_ATTRIBUTE_DIRECTORY;
} else struct {
    const c = @cImport({
        @cInclude("sys/socket.h");
        @cInclude("netinet/in.h");
        @cInclude("arpa/inet.h");
        @cInclude("unistd.h");
        @cInclude("fcntl.h");
        @cInclude("dirent.h");
        @cInclude("sys/stat.h");
        @cInclude("string.h");
    });

    const AF_INET = c.AF_INET;
    const SOCK_STREAM = c.SOCK_STREAM;
    const sockaddr = c.sockaddr;
    const sockaddr_in = c.sockaddr_in;
    const socket = c.socket;
    const bind = c.bind;
    const listen = c.listen;
    const accept = c.accept;
    const close = c.close;
    const recv = c.recv;
    const send = c.send;
    const inet_ntoa = c.inet_ntoa;
    const htons = c.htons;
    const SOMAXCONN = 128; // Common value for Linux/macOS
    const open = c.open;
    const read = c.read;
    const O_RDONLY = c.O_RDONLY;
    const S_ISDIR = c.S_ISDIR;
    const S_ISREG = c.S_ISREG;
    const stat = c.stat;
    const stat_t = c.stat;
    const opendir = c.opendir;
    const readdir = c.readdir;
    const closedir = c.closedir;
    const DIR = c.DIR;
    const dirent = c.dirent;
    const getcwd = c.getcwd;
};

// Simple memory allocator
var memory_buffer: [1024 * 1024 * 10]u8 = undefined; // 10MB static buffer
var memory_index: usize = 0;

fn allocate(size: usize) ?[*]u8 {
    if (memory_index + size > memory_buffer.len) {
        return null; // Out of memory
    }
    const result = &memory_buffer[memory_index];
    memory_index += size;
    return result;
}

fn allocateSlice(size: usize) ?[]u8 {
    const ptr = allocate(size) orelse return null;
    return ptr[0..size];
}

// String helpers
fn copyString(dest: []u8, src: []const u8) void {
    var i: usize = 0;
    while (i < src.len and i < dest.len) : (i += 1) {
        dest[i] = src[i];
    }
    if (i < dest.len) {
        dest[i] = 0; // Null terminate
    }
}

fn parseInt(str: []const u8) ?u16 {
    var result: u16 = 0;
    for (str) |c| {
        if (c < '0' or c > '9') return null;
        const digit = c - '0';
        if (result > (65535 - digit) / 10) return null; // Overflow check
        result = result * 10 + digit;
    }
    return result;
}

fn strLen(str: [*:0]const u8) usize {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return len;
}

fn strEquals(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |char, i| {
        if (char != b[i]) return false;
    }
    return true;
}

fn strContains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const limit = haystack.len - needle.len + 1;
    var i: usize = 0;
    while (i < limit) : (i += 1) {
        if (strEquals(haystack[i .. i + needle.len], needle)) {
            return true;
        }
    }
    return false;
}

fn strStartsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    return strEquals(str[0..prefix.len], prefix);
}

// File system operations
fn getFileContents(path: []const u8) ?struct { data: []u8, size: usize } {
    if (is_windows) {
        var path_with_null = allocateSlice(path.len + 1) orelse return null;
        copyString(path_with_null, path);
        path_with_null[path.len] = 0;

        const handle = os.CreateFileA(
            path_with_null.ptr,
            os.GENERIC_READ,
            os.FILE_SHARE_READ,
            null,
            os.OPEN_EXISTING,
            os.FILE_ATTRIBUTE_NORMAL,
            null
        );

        if (handle == os.INVALID_HANDLE_VALUE) {
            return null;
        }
        defer _ = os.CloseHandle(handle);

        const file_size = os.GetFileSize(handle, null);
        if (file_size == 0xFFFFFFFF) {
            return null;
        }

        var buffer = allocateSlice(file_size) orelse return null;
        var bytes_read: u32 = 0;
        if (os.ReadFile(handle, buffer.ptr, @intCast(buffer.len), &bytes_read, null) == 0) {
            return null;
        }

        return .{ .data = buffer, .size = bytes_read };
    } else {
        var path_with_null = allocateSlice(path.len + 1) orelse return null;
        copyString(path_with_null, path);
        path_with_null[path.len] = 0;

        const fd = os.open(path_with_null.ptr, os.O_RDONLY, 0);
        if (fd < 0) {
            return null;
        }
        defer _ = os.close(fd);

        var st: os.stat_t = undefined;
        if (os.stat(path_with_null.ptr, &st) != 0) {
            return null;
        }

        const file_size = @intCast(st.st_size);
        var buffer = allocateSlice(file_size) orelse return null;
        const bytes_read = os.read(fd, buffer.ptr, buffer.len);
        
        if (bytes_read < 0) {
            return null;
        }

        return .{ .data = buffer, .size = @intCast(bytes_read) };
    }
}

fn isDirectory(path: []const u8) bool {
    var path_with_null = allocateSlice(path.len + 1) orelse return false;
    copyString(path_with_null, path);
    path_with_null[path.len] = 0;

    if (is_windows) {
        var find_data: os.WIN32_FIND_DATAA = undefined;
        const handle = os.FindFirstFileA(path_with_null.ptr, &find_data);
        if (handle == os.INVALID_HANDLE_VALUE) {
            return false;
        }
        defer _ = os.FindClose(handle);
        return (find_data.dwFileAttributes & os.FILE_ATTRIBUTE_DIRECTORY) != 0;
    } else {
        var st: os.stat_t = undefined;
        if (os.stat(path_with_null.ptr, &st) != 0) {
            return false;
        }
        return os.S_ISDIR(st.st_mode) != 0;
    }
}

fn isRegularFile(path: []const u8) bool {
    var path_with_null = allocateSlice(path.len + 1) orelse return false;
    copyString(path_with_null, path);
    path_with_null[path.len] = 0;

    if (is_windows) {
        var find_data: os.WIN32_FIND_DATAA = undefined;
        const handle = os.FindFirstFileA(path_with_null.ptr, &find_data);
        if (handle == os.INVALID_HANDLE_VALUE) {
            return false;
        }
        defer _ = os.FindClose(handle);
        return (find_data.dwFileAttributes & os.FILE_ATTRIBUTE_DIRECTORY) == 0;
    } else {
        var st: os.stat_t = undefined;
        if (os.stat(path_with_null.ptr, &st) != 0) {
            return false;
        }
        return os.S_ISREG(st.st_mode) != 0;
    }
}

// HTTP operations
fn getMimeType(path: []const u8) []const u8 {
    // Simple extension-based MIME type detection
    if (strContains(path, ".html") or strContains(path, ".htm")) {
        return "text/html";
    } else if (strContains(path, ".css")) {
        return "text/css";
    } else if (strContains(path, ".js")) {
        return "application/javascript";
    } else if (strContains(path, ".json")) {
        return "application/json";
    } else if (strContains(path, ".png")) {
        return "image/png";
    } else if (strContains(path, ".jpg") or strContains(path, ".jpeg")) {
        return "image/jpeg";
    } else if (strContains(path, ".gif")) {
        return "image/gif";
    } else if (strContains(path, ".svg")) {
        return "image/svg+xml";
    } else if (strContains(path, ".xml")) {
        return "application/xml";
    } else if (strContains(path, ".pdf")) {
        return "application/pdf";
    } else if (strContains(path, ".zip")) {
        return "application/zip";
    } else if (strContains(path, ".txt")) {
        return "text/plain";
    } else {
        return "application/octet-stream";
    }
}

fn sendResponse(client_socket: SOCKET, status_code: u16, content_type: []const u8, content: []const u8, content_length: usize) void {
    var response_buffer = allocateSlice(BUFFER_SIZE) orelse return;
    
    // Format status line and headers
    var status_text = switch (status_code) {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        else => "Unknown",
    };
    
    var len: usize = 0;
    const header = "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n";
    
    // Simple sprintf-like formatting
    var i: usize = 0;
    while (i < header.len and len < response_buffer.len) : (i += 1) {
        if (header[i] == '{') {
            if (i + 1 < header.len) {
                if (header[i + 1] == 'd') {
                    // Parse number
                    const num = if (strStartsWith(header[i..], "{d}")) status_code else content_length;
                    
                    // Convert number to string
                    var num_buffer: [20]u8 = undefined;
                    var num_len: usize = 0;
                    var n = num;
                    if (n == 0) {
                        if (len < response_buffer.len) {
                            response_buffer[len] = '0';
                            len += 1;
                        }
                    } else {
                        while (n > 0 and num_len < num_buffer.len) : (num_len += 1) {
                            num_buffer[num_len] = @intCast('0' + (n % 10));
                            n /= 10;
                        }
                        var j: usize = 0;
                        while (j < num_len and len < response_buffer.len) : (j += 1) {
                            response_buffer[len] = num_buffer[num_len - j - 1];
                            len += 1;
                        }
                    }
                    i += 2;
                } else if (header[i + 1] == 's') {
                    // Parse string
                    const str = if (strStartsWith(header[i..], "{s}")) 
                        (if (strEquals(status_text, "OK")) @as([]const u8, "OK") 
                        else if (strEquals(status_text, "Not Found")) @as([]const u8, "Not Found") 
                        else @as([]const u8, "Internal Server Error"))
                    else content_type;
                    
                    var j: usize = 0;
                    while (j < str.len and len < response_buffer.len) : (j += 1) {
                        response_buffer[len] = str[j];
                        len += 1;
                    }
                    i += 2;
                } else {
                    if (len < response_buffer.len) {
                        response_buffer[len] = header[i];
                        len += 1;
                    }
                }
            } else {
                if (len < response_buffer.len) {
                    response_buffer[len] = header[i];
                    len += 1;
                }
            }
        } else {
            if (len < response_buffer.len) {
                response_buffer[len] = header[i];
                len += 1;
            }
        }
    }
    
    // Send headers
    _ = if (is_windows) 
        os.send(client_socket, response_buffer.ptr, @intCast(len), 0) 
    else 
        os.send(client_socket, response_buffer.ptr, len, 0);
    
    // Send content
    if (content.len > 0) {
        _ = if (is_windows) 
            os.send(client_socket, content.ptr, @intCast(content_length), 0) 
        else 
            os.send(client_socket, content.ptr, content_length, 0);
    }
}

fn handleError(client_socket: SOCKET, status_code: u16, message: []const u8) void {
    var body = allocateSlice(1024) orelse return;
    var len: usize = 0;
    
    // Format HTML error page
    const html_start = "<!DOCTYPE html><html><head><title>Error ";
    const html_middle = "</title></head><body><h1>Error ";
    const html_end = "</h1><p>";
    const html_close = "</p></body></html>";
    
    copyString(body[len..], html_start);
    len += html_start.len;
    
    // Convert status code to string
    var code_str: [4]u8 = undefined;
    var code_len: usize = 0;
    var n = status_code;
    if (n == 0) {
        code_str[0] = '0';
        code_len = 1;
    } else {
        while (n > 0 and code_len < code_str.len) : (code_len += 1) {
            code_str[code_len] = @intCast('0' + (n % 10));
            n /= 10;
        }
        var i: usize = 0;
        while (i < code_len) : (i += 1) {
            body[len] = code_str[code_len - i - 1];
            len += 1;
        }
    }
    
    copyString(body[len..], html_middle);
    len += html_middle.len;
    
    // Add status code again
    var i: usize = 0;
    while (i < code_len) : (i += 1) {
        body[len] = code_str[code_len - i - 1];
        len += 1;
    }
    
    copyString(body[len..], html_end);
    len += html_end.len;
    
    copyString(body[len..], message);
    len += message.len;
    
    copyString(body[len..], html_close);
    len += html_close.len;
    
    sendResponse(client_socket, status_code, "text/html", body, len);
}

fn handleRequest(client_socket: SOCKET, request: []const u8, root_dir: []const u8) void {
    // Very basic HTTP request parsing - just get the requested path
    if (!strStartsWith(request, "GET ")) {
        handleError(client_socket, 500, "Only GET method is supported");
        return;
    }
    
    // Extract path
    var path_start: usize = 4; // After "GET "
    var path_end: usize = path_start;
    while (path_end < request.len and request[path_end] != ' ' and request[path_end] != '?') : (path_end += 1) {}
    
    var path = request[path_start..path_end];
    
    // URL decode
    var decoded_path = allocateSlice(path.len) orelse {
        handleError(client_socket, 500, "Memory allocation error");
        return;
    };
    var decoded_len: usize = 0;
    
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '%' and i + 2 < path.len) {
            // Hex decode
            var value: u8 = 0;
            for (path[i+1..i+3]) |c| {
                value = value * 16;
                if (c >= '0' and c <= '9') {
                    value += c - '0';
                } else if (c >= 'a' and c <= 'f') {
                    value += c - 'a' + 10;
                } else if (c >= 'A' and c <= 'F') {
                    value += c - 'A' + 10;
                }
            }
            decoded_path[decoded_len] = value;
            decoded_len += 1;
            i += 2;
        } else if (path[i] == '+') {
            decoded_path[decoded_len] = ' ';
            decoded_len += 1;
        } else {
            decoded_path[decoded_len] = path[i];
            decoded_len += 1;
        }
    }
    
    path = decoded_path[0..decoded_len];
    
    // Construct full path
    var full_path = allocateSlice(root_dir.len + path.len + 10) orelse {
        handleError(client_socket, 500, "Memory allocation error");
        return;
    };
    
    copyString(full_path, root_dir);
    var full_path_len = root_dir.len;
    
    // Add path separator if needed
    if (full_path_len > 0 and full_path[full_path_len - 1] != '/' and full_path[full_path_len - 1] != '\\') {
        full_path[full_path_len] = if (is_windows) '\\' else '/';
        full_path_len += 1;
    }
    
    // Normalize path (remove leading slash)
    if (path.len > 0 and (path[0] == '/' or path[0] == '\\')) {
        copyString(full_path[full_path_len..], path[1..]);
        full_path_len += path.len - 1;
    } else {
        copyString(full_path[full_path_len..], path);
        full_path_len += path.len;
    }
    
    full_path = full_path[0..full_path_len];
    
    // Handle directory requests
    if (isDirectory(full_path)) {
        // Check for index.html
        var index_path = allocateSlice(full_path.len + 12) orelse {
            handleError(client_socket, 500, "Memory allocation error");
            return;
        };
        copyString(index_path, full_path);
        var index_path_len = full_path.len;
        
        // Add path separator if needed
        if (index_path_len > 0 and index_path[index_path_len - 1] != '/' and index_path[index_path_len - 1] != '\\') {
            index_path[index_path_len] = if (is_windows) '\\' else '/';
            index_path_len += 1;
        }
        
        // Add "index.html"
        const index_file = "index.html";
        copyString(index_path[index_path_len..], index_file);
        index_path_len += index_file.len;
        
        index_path = index_path[0..index_path_len];
        
        if (isRegularFile(index_path)) {
            // Serve index.html
            if (getFileContents(index_path)) |file| {
                sendResponse(client_socket, 200, "text/html", file.data, file.size);
                return;
            }
        }
        
        // Simple directory listing
        var listing = allocateSlice(16384) orelse {
            handleError(client_socket, 500, "Memory allocation error");
            return;
        };
        var listing_len: usize = 0;
        
        const html_header = "<!DOCTYPE html><html><head><title>Directory listing</title></head><body><h1>Directory listing for ";
        copyString(listing[listing_len..], html_header);
        listing_len += html_header.len;
        
        copyString(listing[listing_len..], path);
        listing_len += path.len;
        
        listing[listing_len] = '<';
        listing[listing_len + 1] = '/';
        listing[listing_len + 2] = 'h';
        listing[listing_len + 3] = '1';
        listing[listing_len + 4] = '>';
        listing_len += 5;
        
        listing[listing_len] = '<';
        listing[listing_len + 1] = 'u';
        listing[listing_len + 2] = 'l';
        listing[listing_len + 3] = '>';
        listing_len += 4;
        
        // List parent directory
        const parent_entry = "<li><a href=\"..\">Parent Directory</a></li>";
        copyString(listing[listing_len..], parent_entry);
        listing_len += parent_entry.len;
        
        if (is_windows) {
            var search_path = allocateSlice(full_path.len + 3) orelse {
                handleError(client_socket, 500, "Memory allocation error");
                return;
            };
            copyString(search_path, full_path);
            var search_path_len = full_path.len;
            
            // Add path separator and wildcard if needed
            if (search_path_len > 0 and search_path[search_path_len - 1] != '\\') {
                search_path[search_path_len] = '\\';
                search_path_len += 1;
            }
            search_path[search_path_len] = '*';
            search_path[search_path_len + 1] = 0;
            search_path_len += 2;
            
            var find_data: os.WIN32_FIND_DATAA = undefined;
            const find_handle = os.FindFirstFileA(search_path.ptr, &find_data);
            
            if (find_handle != os.INVALID_HANDLE_VALUE) {
                // Process files
                while (true) {
                    const filename = find_data.cFileName[0..strLen(&find_data.cFileName)];
                    
                    // Skip . and ..
                    if (!strEquals(filename, ".") and !strEquals(filename, "..")) {
                        // Entry start
                        listing[listing_len] = '<';
                        listing[listing_len + 1] = 'l';
                        listing[listing_len + 2] = 'i';
                        listing[listing_len + 3] = '>';
                        listing[listing_len + 4] = '<';
                        listing[listing_len + 5] = 'a';
                        listing[listing_len + 6] = ' ';
                        listing[listing_len + 7] = 'h';
                        listing[listing_len + 8] = 'r';
                        listing[listing_len + 9] = 'e';
                        listing[listing_len + 10] = 'f';
                        listing[listing_len + 11] = '=';
                        listing[listing_len + 12] = '"';
                        listing_len += 13;
                        
                        // Link target
                        copyString(listing[listing_len..], filename);
                        listing_len += filename.len;
                        
                        // Is this a directory?
                        if ((find_data.dwFileAttributes & os.FILE_ATTRIBUTE_DIRECTORY) != 0) {
                            listing[listing_len] = '/';
                            listing_len += 1;
                        }
                        
                        listing