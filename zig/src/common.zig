const std = @import("std");

const sys = @import("root.zig").sys;

pub const alloc = std.heap.smp_allocator;

pub const IpcMessage = struct {
    data: []u8,
    os_ipc_channels: []sys.OsOpaqueIpcChannel,
    os_ipc_shared_memory_regions: []sys.OsIpcSharedMemory,
};
