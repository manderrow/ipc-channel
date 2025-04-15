const std = @import("std");

const os = @import("../os.zig");
const util = @import("../util.zig");

const bootstrap = @import("macos/bootstrap.zig");
const mach = @import("macos/mach.zig");

const IpcMessage = os.IpcMessage;

const kern_return_t = mach.kern_return_t;

const KernelError = mach.KernelError;
const MachError = mach.MachError;
const Port = mach.Port;

/// The size that we preallocate on the stack to receive messages. If the message is larger than
/// this, we retry and spill to the heap.
const SMALL_MESSAGE_SIZE: usize = 4096;

const BOOTSTRAP_NAME_IN_USE: kern_return_t = 1101;
const BOOTSTRAP_SUCCESS: kern_return_t = 0;
const MACH_MSG_OOL_DESCRIPTOR: u32 = 1;
const MACH_MSG_PORT_DESCRIPTOR: u32 = 0;
const MACH_MSG_SUCCESS: kern_return_t = 0;
const MACH_MSG_TIMEOUT_NONE: std.c.mach_msg_timeout_t = 0;
const MACH_NOTIFY_FIRST: i32 = 64;
const MACH_NOTIFY_NO_SENDERS: i32 = MACH_NOTIFY_FIRST + 6;
const MACH_PORT_LIMITS_INFO: i32 = 1;
const MACH_PORT_QLIMIT_LARGE: mach.mach_port_msgcount_t = 1024;
const MACH_PORT_QLIMIT_MAX: mach.mach_port_msgcount_t = MACH_PORT_QLIMIT_LARGE;
const MACH_RCV_LARGE: i32 = 4;
const MACH_RCV_MSG: i32 = 2;
const MACH_RCV_TIMEOUT: i32 = 0x100;
const MACH_RCV_TOO_LARGE: kern_return_t = 0x10004004;
const MACH_SEND_MSG: i32 = 1;
const TASK_BOOTSTRAP_PORT: i32 = 4;
const VM_INHERIT_SHARE: std.c.vm_inherit_t = 0;

pub fn channel() !struct { sd: OsIpcSender, rc: OsIpcReceiver } {
    const receiver = try OsIpcReceiver.new();
    const sender = try receiver.sender();
    try receiver.request_no_senders_notification();
    return .{ .sd = sender, .rc = receiver };
}

pub const OsIpcReceiver = struct {
    port: Port,

    pub fn new() !OsIpcReceiver {
        const port = try Port.alloc(.recv);
        var limits: mach.mach_port_limits = .{
            .mpl_qlimit = MACH_PORT_QLIMIT_MAX,
        };
        try port.setAttributes(
            MACH_PORT_LIMITS_INFO,
            @ptrCast(&limits),
            1,
        );
        return .{ .port = port };
    }

    pub fn deinit(self: *OsIpcReceiver) void {
        defer self.port = .null;
        self.port.release(.recv) catch |e| std.debug.panic("mach_port_mod_refs: {}", .{e});
    }

    pub fn select(self: OsIpcReceiver, alloc: std.mem.Allocator, blocking_mode: BlockingMode) !OsIpcSelectionResult {
        var buffer: [SMALL_MESSAGE_SIZE]u8 align(4) = undefined;
        try setupReceiveBuffer(&buffer, self.port);
        var message: *Message = @ptrCast(&buffer);
        const flags = switch (blocking_mode) {
            .blocking => MACH_RCV_MSG | MACH_RCV_LARGE,
            .nonblocking => MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
            .timeout => MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
        };
        const timeout = switch (blocking_mode) {
            .blocking => MACH_MSG_TIMEOUT_NONE,
            .nonblocking => 0,
            .timeout => |duration| duration,
        };
        var rt: mach.mach_msg_return_t = @enumFromInt(std.c.mach_msg(
            @ptrCast(&message.header),
            flags,
            0,
            message.header.msgh_size,
            self.port.name,
            timeout,
            Port.null.name,
        ));

        var allocated_buffer: std.ArrayListAlignedUnmanaged(u8, 4) = .{};
        defer allocated_buffer.deinit(alloc);

        while (true) {
            switch (rt) {
                .RCV_TOO_LARGE => {
                    const max_trailer_size = @sizeOf(mach.mach_msg_max_trailer_t);
                    // the actual size gets written into msgh_size by the kernel
                    const actual_size = message.header.msgh_size + max_trailer_size;
                    allocated_buffer.clearRetainingCapacity();
                    try allocated_buffer.ensureTotalCapacityPrecise(alloc, actual_size);
                    try setupReceiveBuffer(allocated_buffer.allocatedSlice(), self.port);
                    message = @ptrCast(allocated_buffer.allocatedSlice());
                    rt = @enumFromInt(std.c.mach_msg(
                        @ptrCast(&message.header),
                        flags,
                        0,
                        actual_size,
                        self.port.name,
                        timeout,
                        Port.null.name,
                    ));
                },
                else => {
                    try mach.checkMachReturn(rt);
                    break;
                },
            }
        }

        const local_port = message.header.msgh_local_port;
        if (message.header.msgh_id == MACH_NOTIFY_NO_SENDERS) {
            return .{ .id = .{ .id = local_port.name }, .event = .closed };
        }

        var descriptors: [*]mach.mach_msg_descriptor = @ptrCast(@as([*]Message, @ptrCast(message)) + 1);
        var remaining = message.body.msgh_descriptor_count;

        var ports: std.ArrayListUnmanaged(OsOpaqueIpcChannel) = .{};
        // TODO: errdefer cleanup ports
        while (remaining > 0 and descriptors[0].type == .port) : (remaining -= 1) {
            const port_descriptors: [*]mach.mach_msg_port_descriptor_t = @ptrCast(descriptors);
            try ports.append(alloc, .{
                .port = port_descriptors[0].name,
                .right = switch (port_descriptors[0].disposition.type) {
                    .move_recv => .recv,
                    .copy_send, .make_send, .move_send => .send,
                    .make_send_once, .move_send_once => .send,
                    else => return error.InvalidMessage,
                },
            });
            descriptors = @ptrCast(port_descriptors + 1);
        }

        var shared_memory_regions: std.ArrayListUnmanaged(OsIpcSharedMemory) = .{};
        // TODO: errdefer cleanup smrs
        while (remaining > 0 and descriptors[0].type == .ool) : (remaining -= 1) {
            const ool_descriptors: [*]mach.mach_msg_ool_descriptor_t = @ptrCast(descriptors);
            try shared_memory_regions.append(alloc, .{
                .data = @as([*]u8, @ptrCast(ool_descriptors[0].address))[0..ool_descriptors[0].size],
            });
            descriptors = @ptrCast(ool_descriptors + 1);
        }

        if (remaining > 0) {
            return error.InvalidMessage;
        }

        const is_inline: *bool = @as(*bool, @ptrCast(descriptors));
        const payload = if (is_inline.*) blk: {
            const ptrs = getInlineSizeAndData(is_inline);
            // TODO: if we've already allocated a buffer for the message, don't reallocate, just
            //       wrap it up nicely and return it.
            break :blk try alloc.dupe(u8, ptrs.data[0..ptrs.size.*]);
        } else blk: {
            break :blk (shared_memory_regions.pop() orelse return error.InvalidMessage).data;
        };

        return .{
            .id = .{ .id = local_port.name },
            .event = .{ .received = .{
                .data = payload,
                .channels = try ports.toOwnedSlice(alloc),
                .shared_memory_regions = try shared_memory_regions.toOwnedSlice(alloc),
            } },
        };
    }

    pub fn sender(self: OsIpcReceiver) !OsIpcSender {
        return .{ .port = try self.port.extractRight(.make_send) };
    }

    fn request_no_senders_notification(self: OsIpcReceiver) !void {
        std.debug.assert(!self.port.isNull());
        _ = try self.port.requestNotification(
            MACH_NOTIFY_NO_SENDERS,
            0,
            self.port,
            .make_send_once,
        );
    }

    fn recv_with_blocking_mode(
        self: OsIpcReceiver,
        alloc: std.mem.Allocator,
        blocking_mode: BlockingMode,
    ) !IpcMessage {
        const result = try self.select(alloc, blocking_mode);
        return switch (result.event) {
            .received => |msg| msg,
            .closed => error.MACH_NOTIFY_NO_SENDERS,
        };
    }

    pub fn recv(self: OsIpcReceiver, alloc: std.mem.Allocator) !IpcMessage {
        return self.recv_with_blocking_mode(alloc, .blocking);
    }

    pub fn try_recv(self: OsIpcReceiver, alloc: std.mem.Allocator) !IpcMessage {
        return self.recv_with_blocking_mode(alloc, .nonblocking);
    }

    /// `duration` is measured in milliseconds.
    pub fn try_recv_timeout(self: OsIpcReceiver, alloc: std.mem.Allocator, duration: u64) !IpcMessage {
        self.recv_with_blocking_mode(alloc, .{ .timeout = duration });
    }
};

fn getInlineSizeAndData(is_inline: *bool) struct { size: *align(1) usize, data: [*]u8 } {
    const padding_start: [*]u8 = @ptrCast(@as([*]bool, @ptrCast(is_inline)) + 1);
    const padding_count = Message.payloadPadding(@intFromPtr(padding_start));
    const data_size: [*]align(1) usize = @ptrCast(padding_start + padding_count);
    return .{ .size = &data_size[0], .data = @ptrCast(data_size + 1) };
}

pub const OsIpcSender = struct {
    port: Port,

    pub fn connect(name: [:0]const u8) !OsIpcSender {
        const bootstrap_port = try mach.getSpecialPort(.bootstrap);
        return .{ .port = try bootstrap.look_up(bootstrap_port, name) };
    }

    pub fn deinit(self: *@This()) void {
        self.port.release(.send) catch |e| std.debug.panic("mach_port_deallocate: {}", .{e});
        self.port = undefined;
    }

    pub fn clone(self: @This()) KernelError!OsIpcSender {
        var cloned_port = self.port;
        try cloned_port.addRef(.send);
        return .{
            .port = cloned_port,
        };
    }

    pub fn getMaxFragmentSize() usize {
        return std.math.maxInt(usize);
    }

    /// Takes ownership of the elements of `ports` and `shared_memory_regions`.
    pub fn send(
        self: OsIpcSender,
        alloc: std.mem.Allocator,
        data: []const u8,
        ports: []OsIpcChannel,
        shared_memory_regions: []OsIpcSharedMemory,
    ) !void {
        errdefer {
            for (ports) |*port| {
                port.deinit();
            }
            for (shared_memory_regions) |*smr| {
                smr.deinit();
            }
        }

        const send_data = try SendData.new(data);
        const smr_count = shared_memory_regions.len + @intFromBool(send_data == .out_of_line);

        const size = std.math.cast(c_uint, Message.sizeOf(send_data, ports.len, smr_count)) orelse return error.SendTooLarge;

        const message_buf = try alloc.alignedAlloc(u8, @alignOf(Message), size);
        defer alloc.free(message_buf);

        const message: *Message = @ptrCast(message_buf);
        const port_descriptor_dest: []mach.mach_msg_port_descriptor_t = @as([*]mach.mach_msg_port_descriptor_t, @ptrCast(@as([*]Message, @ptrCast(message)) + 1))[0..ports.len];
        const shared_memory_descriptor_dest: []align(4) mach.mach_msg_ool_descriptor_t = @as([*]align(4) mach.mach_msg_ool_descriptor_t, @ptrCast(port_descriptor_dest[port_descriptor_dest.len..].ptr))[0..smr_count];
        const is_inline_dest: *bool = @as(*bool, @ptrCast(shared_memory_descriptor_dest[shared_memory_descriptor_dest.len..].ptr));

        message.* = .{
            .header = .{
                .msgh_bits = .{
                    .remote = .copy_send,
                    .complex = true,
                },
                .msgh_size = size,
                .msgh_remote_port = self.port,
                .msgh_local_port = Port.null,
                .msgh_voucher_port = Port.null,
                .msgh_id = 0,
            },
            .body = .{
                .msgh_descriptor_count = std.math.cast(c_uint, ports.len + shared_memory_regions.len) orelse return error.SendTooLarge,
            },
        };

        for (ports, port_descriptor_dest) |port, *dest| {
            dest.* = .{
                .name = switch (port) {
                    .sender => |sd| sd.port,
                    .receiver => |rc| rc.port,
                },
                .disposition = .{ .type = switch (port) {
                    .sender => .move_send,
                    .receiver => .move_recv,
                } },
            };
        }

        for (shared_memory_regions, shared_memory_descriptor_dest) |smr, *dest| {
            dest.* = .{
                .address = smr.data.ptr,
                .size = std.math.cast(mach.mach_msg_size_t, smr.data.len) orelse return error.SendTooLarge,
                .deallocate = 1,
                .copy = .VIRTUAL_COPY,
            };
        }
        switch (send_data) {
            .out_of_line => |smr| {
                std.debug.assert(shared_memory_descriptor_dest.len == shared_memory_regions.len + 1);
                shared_memory_descriptor_dest[shared_memory_descriptor_dest.len - 1] = .{
                    .address = smr.data.ptr,
                    .size = std.math.cast(mach.mach_msg_size_t, smr.data.len) orelse return error.SendTooLarge,
                    .deallocate = 1,
                    .copy = .VIRTUAL_COPY,
                };
            },
            .@"inline" => {},
        }

        is_inline_dest.* = send_data == .@"inline";

        if (send_data == .@"inline") {
            // TODO: what sort of paranoia is this for?
            // Zero out the last word for paranoia's sake.
            @memset(message_buf[size - 4 ..], 0);

            const ptrs = getInlineSizeAndData(is_inline_dest);
            ptrs.size.* = send_data.@"inline".len;
            @memcpy(ptrs.data, send_data.@"inline");
        }

        std.debug.assert(message.header.msgh_size == size);
        const send_size = size;
        const rt: mach.mach_msg_return_t = @enumFromInt(std.c.mach_msg(
            @ptrCast(&message.header),
            MACH_SEND_MSG,
            send_size,
            0,
            Port.null.name,
            MACH_MSG_TIMEOUT_NONE,
            Port.null.name,
        ));
        if (rt == .SEND_TOO_LARGE and send_data == .@"inline") {
            _ = max_inline_size.fetchMin(send_data.@"inline".len, .seq_cst);
            // FIXME: we want to free *before* calling this again, to conserve memory.
            return self.send(alloc, send_data.@"inline", ports, shared_memory_regions);
        }
        try mach.checkMachReturn(rt);
    }
};

var max_inline_size = std.atomic.Value(usize).init(std.math.maxInt(usize));

const SendData = union(enum) {
    @"inline": []const u8,
    out_of_line: OsIpcSharedMemory,

    pub fn new(data: []const u8) !SendData {
        if (data.len >= max_inline_size.load(.seq_cst)) {
            // Convert the data payload into a shared memory region to avoid exceeding
            // any message size limits.
            return .{ .out_of_line = try OsIpcSharedMemory.fromBytes(data) };
        } else {
            return .{ .@"inline" = data };
        }
    }
};

pub const OsIpcChannel = union(enum) {
    sender: OsIpcSender,
    receiver: OsIpcReceiver,

    pub fn deinit(self: *@This()) void {
        switch (self.*) {
            .sender => |*sd| sd.deinit(),
            .receiver => |*rc| rc.deinit(),
        }
    }
};

pub const OsOpaqueIpcChannel = struct {
    port: Port,
    right: mach.mach_port_right_t,

    pub fn deinit(self: *OsOpaqueIpcChannel) void {
        self.port.release(self.right) catch |e| std.debug.panic("release({}): {}", .{ self.port.name, e });
        self.* = undefined;
    }

    pub fn asSender(self: OsOpaqueIpcChannel) error{WrongType}!OsIpcSender {
        if (self.right != .send) return error.WrongType;
        return .{ .port = self.port };
    }

    pub fn asReceiver(self: OsOpaqueIpcChannel) error{WrongType}!OsIpcReceiver {
        if (self.right != .recv) return error.WrongType;
        return .{ .port = self.port };
    }
};

pub const OsIpcReceiverSet = struct {
    port: Port,
    ports: std.ArrayListUnmanaged(Port),

    pub fn new() !@This() {
        return .{
            .port = try Port.alloc(.port_set),
            .ports = .{},
        };
    }

    pub fn deinit(self: *@This(), alloc: std.mem.Allocator) !void {
        for (self.ports.items) |port| {
            port.release(.recv) catch |e| std.debug.panic("release({}): {}", .{ self.port.name, e });
        }
        self.ports.deinit(alloc);
        try self.port.release(.port_set);
        self.* = undefined;
    }

    /// The set takes ownership of `receiver`.
    pub fn add(self: *@This(), alloc: std.mem.Allocator, receiver: OsIpcReceiver) !OsIpcReceiverSetPortId {
        try receiver.port.moveMember(self.port);
        try self.ports.append(alloc, receiver.port);
        return .{ .id = @intCast(receiver.port.name) };
    }

    pub fn select(self: *@This()) !OsIpcSelectionResult {
        return (OsIpcReceiver{ .port = self.port }).select(.blocking);
    }
};

const BlockingMode = union(enum) {
    blocking,
    nonblocking,
    /// Measured in milliseconds.
    timeout: c_uint,
};

pub const OsIpcReceiverSetPortId = struct { id: u64 };

pub const OsIpcSelectionResult = struct {
    id: OsIpcReceiverSetPortId,
    event: union(enum) {
        closed,
        received: IpcMessage,
    },
};

pub const OneShotServer = struct {
    receiver: OsIpcReceiver,
    name: NameBuf,
    registration_port: Port,

    pub const name_fmt = "org.rust-lang.ipc-channel.{}";

    const NameBuf = struct {
        buf: [std.fmt.count(name_fmt, .{std.math.minInt(i64)}):0]u8,
        len: usize,

        pub const init: @This() = .{ .buf = undefined, .len = 0 };
    };

    pub fn new() !OneShotServer {
        var receiver = try OsIpcReceiver.new();
        errdefer receiver.deinit();

        const bootstrap_port = try mach.getSpecialPort(.bootstrap);

        // TODO: use .send_once instead
        const reg_port = try receiver.port.extractRight(.make_send);
        errdefer reg_port.release(.send) catch |e| std.debug.panic("mach_port_deallocate: {}", .{e});

        var name_buf = NameBuf.init;

        while (true) {
            const name = std.fmt.bufPrintZ(name_buf.buf[0 .. name_buf.buf.len + 1], name_fmt, .{std.crypto.random.int(i64)}) catch unreachable;
            name_buf.len = name.len;
            bootstrap.register2(bootstrap_port, name, reg_port, 0) catch |e| switch (e) {
                error.AlreadyExists => continue,
                else => return e,
            };
            return .{
                .receiver = receiver,
                .name = name_buf,
                .registration_port = reg_port,
            };
        }
    }

    pub fn deinit(self: *OneShotServer) void {
        const bootstrap_port = mach.getSpecialPort(.bootstrap) catch |e| std.debug.panic("task_get_special_port: {}", .{e});

        bootstrap.register2(bootstrap_port, self.getName(), .null, 0) catch |e| switch (e) {
            error.AlreadyExists => {
                // The Rust version of ipc_channel silently ignores this error.
                // TODO: check whether this call has the desired effect regardless of the error. If yes, document it, if no, figure out what the correct method for unregistration is.
            },
            else => std.debug.panic("bootstrap_register2: {}", .{e}),
        };
        self.registration_port.release(.send) catch |e| std.debug.panic("mach_port_deallocate: {}", .{e});
        self.receiver.deinit();
        self.* = undefined;
    }

    pub fn getName(self: *const @This()) [:0]const u8 {
        return self.name.buf[0..self.name.len :0];
    }

    /// On success, leaves `self` deinitialized.
    pub fn accept(self: *@This(), alloc: std.mem.Allocator) !struct { rc: OsIpcReceiver, msg: IpcMessage } {
        const msg = try self.receiver.recv(alloc);
        const rc = self.receiver;
        self.deinit();
        return .{ .rc = rc, .msg = msg };
    }
};

pub const OsIpcSharedMemory = struct {
    data: []u8,

    pub fn deinit(self: *@This()) void {
        const rt: mach.kern_return_t = @enumFromInt(std.c.vm_deallocate(mach.mach_task_self(), @intFromPtr(self.data.ptr), self.data.len));
        mach.checkKernelReturn(rt) catch |e| std.debug.panic("vm_deallocate: {}", .{e});
    }

    pub fn clone(self: *@This()) !OsIpcSharedMemory {
        var address: [*]u8 = undefined;
        const rt = mach.vm_remap(
            mach.mach_task_self(),
            &address,
            self.data.len,
            0,
            1,
            mach.mach_task_self(),
            self.data.ptr,
            0,
            &0,
            &0,
            VM_INHERIT_SHARE,
        );
        try mach.checkKernelReturn(rt);
        return .{ .data = address[0..self.data.len] };
    }

    pub fn fromByte(byte: u8, length: usize) !OsIpcSharedMemory {
        const address = try mach.vmAllocate(length);
        @memset(address, byte);
        return address;
    }

    pub fn fromBytes(bytes: []const u8) !OsIpcSharedMemory {
        const buf = try mach.vmAllocate(bytes.len);
        @memcpy(buf, bytes);
        return .{ .data = buf };
    }
};

fn setupReceiveBuffer(buffer: []align(4) u8, port: Port) !void {
    const header: *mach.mach_msg_header_t = @ptrCast(buffer);
    header.* = .{
        .msgh_bits = .{},
        .msgh_size = std.math.cast(c_uint, buffer.len) orelse return error.TooLarge,
        .msgh_remote_port = .null,
        .msgh_local_port = port,
        .msgh_voucher_port = .null,
        .msgh_id = 0,
    };
}

const Message = extern struct {
    header: mach.mach_msg_header_t,
    body: mach.mach_msg_body_t,

    pub fn payloadPadding(unaligned: usize) usize {
        return ((unaligned + 7) & ~@as(usize, 7)) - unaligned; // 8 byte alignment
    }

    pub fn sizeOf(data: SendData, port_length: usize, shared_memory_length: usize) usize {
        var size = @sizeOf(Message) + @sizeOf(mach.mach_msg_port_descriptor_t) * port_length + @sizeOf(mach.mach_msg_ool_descriptor_t) * shared_memory_length + @sizeOf(bool);

        if (data == .@"inline") {
            // rustc panics in debug mode for unaligned accesses.
            // so include padding to start payload at 8-byte aligned address
            size += payloadPadding(size);
            size += @sizeOf(usize) + data.@"inline".len;
        }

        // Round up to the next 4 bytes; mach_msg_send returns an error for unaligned sizes.
        if ((size & 0x3) != 0) {
            size = (size & ~@as(usize, 0x3)) + 4;
        }

        return size;
    }
};
