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

    pub fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        alloc.free(self.data);
        for (self.os_ipc_channels) |*chan| {
            chan.deinit();
        }
        for (self.os_ipc_shared_memory_regions) |*smr| {
            smr.deinit();
        }
    }
};

fn expectEqualStringMessages(
    expected_data: []const u8,
    expected_channel_count: usize,
    expected_shared_memory_region_count: usize,
    msg: IpcMessage,
) !void {
    try std.testing.expectEqualStrings(expected_data, msg.data);
    try std.testing.expectEqual(expected_channel_count, msg.os_ipc_channels.len);
    try std.testing.expectEqual(expected_shared_memory_region_count, msg.os_ipc_shared_memory_regions.len);
}

test "simple" {
    const alloc = std.testing.allocator;

    var chan = try channel();
    defer chan.rd.deinit();
    defer chan.sd.deinit();

    const data = "1234567";
    try chan.sd.send(alloc, data, &.{}, &.{});
    var ipc_message = try chan.rd.recv(alloc);
    defer ipc_message.deinit(alloc);
    try expectEqualStringMessages(data, 0, 0, ipc_message);
}

test "sender transfer" {
    const alloc = std.testing.allocator;

    var super = try channel();
    defer super.rd.deinit();
    defer super.sd.deinit();

    var sub = try channel();
    defer sub.rd.deinit();
    // sub.sd is immediately handed off to super.sd.send(...), so don't defer dealloc

    const data = "foo";
    var ports: [1]Channel = .{.{ .sender = sub.sd }};
    try super.sd
        .send(alloc, data, &ports, &.{});
    {
        var ipc_message = try super.rd.recv(alloc);
        defer ipc_message.deinit(alloc);

        try std.testing.expectEqual(1, ipc_message.os_ipc_channels.len);
        var sub_tx = try ipc_message.os_ipc_channels[ipc_message.os_ipc_channels.len - 1].toSender();
        defer sub_tx.deinit();

        try sub_tx.send(alloc, data, &.{}, &.{});
    }

    var ipc_message = try sub.rd.recv(alloc);
    defer ipc_message.deinit(alloc);
    try expectEqualStringMessages(data, 0, 0, ipc_message);
}
