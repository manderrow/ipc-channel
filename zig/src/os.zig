const builtin = @import("builtin");
const std = @import("std");

pub const os = switch (builtin.os.tag) {
    .macos => @import("os/macos.zig"),
    else => |os_tag| @compileError("Unsupported OS: " ++ @tagName(os_tag)),
};

pub const channel = os.channel;
pub const Channel = os.OsIpcChannel;
pub const Sender = os.OsIpcSender;
pub const Receiver = os.OsIpcReceiver;
pub const OpaqueChannel = os.OsOpaqueIpcChannel;
pub const SharedMemory = os.OsIpcSharedMemory;

pub const IpcMessage = struct {
    data: []u8,
    os_ipc_channels: []OpaqueChannel,
    os_ipc_shared_memory_regions: []SharedMemory,
};

test "simple" {
    var chan = try channel();
    defer chan.rd.deinit() catch {};
    defer chan.sd.deinit() catch {};

    const data = "1234567";
    try chan.sd.send(data, &.{}, &.{});
    const ipc_message = try chan.rd.recv();
    try std.testing.expectEqualStrings(data, ipc_message.data);
    try std.testing.expectEqual(0, ipc_message.os_ipc_channels.len);
    try std.testing.expectEqual(0, ipc_message.os_ipc_shared_memory_regions.len);
}
