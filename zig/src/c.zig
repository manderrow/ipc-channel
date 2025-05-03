const std = @import("std");

const os = @import("os.zig");

const alloc = std.heap.smp_allocator;

pub fn Slice(comptime T: type) type {
    return extern struct {
        ptr: [*]T,
        len: usize,

        pub fn from(items: []T) @This() {
            return .{ .ptr = items.ptr, .len = items.len };
        }

        pub fn slice(self: @This()) []T {
            return self.ptr[0..self.len];
        }
    };
}

pub const Message = extern struct {
    data: Slice(u8),
    channels: Slice(os.OpaqueChannel),
    shared_memory_regions: Slice(os.SharedMemory),
};

pub export fn ipc_channel_create(
    sender: *os.Sender,
    receiver: *os.Receiver,
) u16 {
    const result = os.channel() catch |e| return @intFromError(e);
    sender.* = result.sd;
    receiver.* = result.rc;
    return 0;
}

pub export fn ipc_channel_send(
    self: *os.Sender,
    data: [*]const u8,
    data_len: usize,
    ports: [*]os.Channel,
    ports_len: usize,
    shared_memory_regions: [*]os.SharedMemory,
    shared_memory_regions_len: usize,
) u16 {
    self.send(
        alloc,
        data[0..data_len],
        ports[0..ports_len],
        shared_memory_regions[0..shared_memory_regions_len],
    ) catch |e| return @intFromError(e);
    return 0;
}

pub export fn ipc_channel_recv(
    self: *os.Receiver,
    message: *Message,
) u16 {
    const msg = self.recv(alloc) catch |e| return @intFromError(e);
    message.data = .from(msg.data);
    message.channels = .from(msg.channels);
    message.shared_memory_regions = .from(msg.shared_memory_regions);
    return 0;
}

pub const FreeMessageFlags = packed struct(u32) {
    /// Whether to free the data array.
    free_data: bool,
    /// Whether to free the channels array. This will not free the contents.
    free_channels: bool,
    /// Whether to free the shared memory regions array. This will not free the contents.
    free_shared_memory_regions: bool,
    pad: u29 = 0,
};

pub export fn ipc_channel_free_message(
    message: *Message,
    flags: FreeMessageFlags,
) u16 {
    if (flags.free_data) {
        alloc.free(message.data.slice());
    }
    if (flags.free_channels) {
        alloc.free(message.channels.slice());
    }
    if (flags.free_shared_memory_regions) {
        alloc.free(message.shared_memory_regions.slice());
    }
    return 0;
}
