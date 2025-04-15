pub const os = @import("os.zig");

test {
    _ = os;
}

comptime {
    // export the C API
    _ = @import("c.zig");
}
