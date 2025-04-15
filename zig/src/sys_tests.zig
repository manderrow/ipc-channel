const std = @import("std");

const common = @import("common.zig");
const sys = @import("root.zig").sys;

test "simple" {
    var channel = try sys.channel();
    defer channel.rd.deinit() catch {};
    defer channel.sd.deinit() catch {};

    const data = "1234567";
    try channel.sd.send(data, &.{}, &.{});
    const ipc_message = try channel.rd.recv();
    try std.testing.expectEqualStrings(data, ipc_message.data);
    try std.testing.expectEqual(0, ipc_message.os_ipc_channels.len);
    try std.testing.expectEqual(0, ipc_message.os_ipc_shared_memory_regions.len);
}
