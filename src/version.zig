// Version information for http-zerver
pub const VERSION = "1.0.0";
pub const BUILD_DATE = @embedFile("version_date.txt");

pub fn getVersionString() []const u8 {
    return "Version " ++ VERSION ++ " (Built: " ++ BUILD_DATE ++ ")";
}
