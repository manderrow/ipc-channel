pub const os = @import("os.zig");

test {
    _ = os;
}

export fn ipc_channel_os_ipc_sender_send(
    self: *os.Sender,
    data: [*]const u8,
    data_len: usize,
    ports: [*]os.Channel,
    ports_len: usize,
    shared_memory_regions: [*]os.SharedMemory,
    shared_memory_regions_len: usize,
) u16 {
    self.send(
        data[0..data_len],
        ports[0..ports_len],
        shared_memory_regions[0..shared_memory_regions_len],
    ) catch |e| return @intFromError(e);
    return 0;
}
