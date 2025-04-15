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

/// A string to prepend to our bootstrap ports.
const BOOTSTRAP_PREFIX = "org.rust-lang.ipc-channel.";

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

pub fn channel() !struct { sd: OsIpcSender, rd: OsIpcReceiver } {
    const receiver = try OsIpcReceiver.new();
    const sender = try receiver.sender();
    try receiver.request_no_senders_notification();
    return .{ .sd = sender, .rd = receiver };
}

pub const OsIpcReceiver = struct {
    port: Port,

    pub fn new() !OsIpcReceiver {
        const port = try Port.alloc(.RIGHT_RECEIVE);
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
        self.port.release(.RIGHT_RECEIVE) catch |e| std.debug.panic("mach_port_mod_refs: {}", .{e});
    }

    pub fn select(port: OsIpcReceiver, alloc: std.mem.Allocator, blocking_mode: BlockingMode) !OsIpcSelectionResult {
        _ = port;
        _ = alloc;
        _ = blocking_mode;
        return error.Todo;
    }

    pub fn sender(self: OsIpcReceiver) !OsIpcSender {
        const result = try self.port.extractRight(.make_send);
        return .{ .port = result[0] };
    }

    //     fn register_bootstrap_name(&self) -> Result<(u32, String), MachError> {
    //         let port = self.port.get();
    //         debug_assert!(port != MACH_PORT_NULL);
    //         unsafe {
    //             let mut bootstrap_port = 0;
    //             let os_result = mach_sys::task_get_special_port(
    //                 mach_task_self(),
    //                 TASK_BOOTSTRAP_PORT,
    //                 &mut bootstrap_port,
    //             );
    //             if os_result != KERN_SUCCESS {
    //                 return Err(KernelError::from(os_result).into());
    //             }
    //
    //             let (right, acquired_right) =
    //                 mach_port_extract_right(port, .MAKE_SEND)?;
    //             debug_assert!(acquired_right == .PORT_SEND);
    //
    //             let mut os_result;
    //             let mut name;
    //             loop {
    //                 name = format!("{}{}", BOOTSTRAP_PREFIX, rand::rng().random::<i64>());
    //                 let c_name = CString::new(name.clone()).unwrap();
    //                 os_result = bootstrap_register2(bootstrap_port, c_name.as_ptr(), right, 0);
    //                 if os_result == BOOTSTRAP_NAME_IN_USE {
    //                     continue;
    //                 }
    //                 if os_result != BOOTSTRAP_SUCCESS {
    //                     return Err(MachError::from(os_result));
    //                 }
    //                 break;
    //             }
    //             Ok((right, name))
    //         }
    //     }
    //
    //     fn unregister_global_name(name: String) -> Result<(), MachError> {
    //         unsafe {
    //             let mut bootstrap_port = 0;
    //             let os_result = mach_sys::task_get_special_port(
    //                 mach_task_self(),
    //                 TASK_BOOTSTRAP_PORT,
    //                 &mut bootstrap_port,
    //             );
    //             if os_result != KERN_SUCCESS {
    //                 return Err(KernelError::from(os_result).into());
    //             }
    //
    //             let c_name = CString::new(name).unwrap();
    //             let os_result = bootstrap_register2(bootstrap_port, c_name.as_ptr(), MACH_PORT_NULL, 0);
    //             if os_result == BOOTSTRAP_SUCCESS {
    //                 Ok(())
    //             } else {
    //                 Err(MachError::from(os_result))
    //             }
    //         }
    //     }

    fn request_no_senders_notification(self: OsIpcReceiver) !void {
        std.debug.assert(!self.port.isNull());
        _ = try self.port.requestNotification(
            MACH_NOTIFY_NO_SENDERS,
            0,
            self.port,
            .MAKE_SEND_ONCE,
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

pub const OsIpcSender = struct {
    port: Port,

    pub fn deinit(self: *@This()) void {
        self.port.dealloc() catch |e| std.debug.panic("mach_port_deallocate: {}", .{e});
        self.port = undefined;
    }

    pub fn clone(self: @This()) KernelError!OsIpcSender {
        var cloned_port = self.port;
        try cloned_port.addRef(.RIGHT_SEND);
        return .{
            .port = cloned_port,
        };
    }
    //     pub fn connect(name: String) -> Result<OsIpcSender, MachError> {
    //         unsafe {
    //             let mut bootstrap_port = 0;
    //             let os_result = mach_sys::task_get_special_port(
    //                 mach_task_self(),
    //                 TASK_BOOTSTRAP_PORT,
    //                 &mut bootstrap_port,
    //             );
    //             if os_result != KERN_SUCCESS {
    //                 return Err(KernelError::from(os_result).into());
    //             }
    //
    //             let mut port = 0;
    //             let c_name = CString::new(name).unwrap();
    //             let os_result = bootstrap_look_up(bootstrap_port, c_name.as_ptr(), &mut port);
    //             if os_result == BOOTSTRAP_SUCCESS {
    //                 Ok(OsIpcSender::from_name(port))
    //             } else {
    //                 Err(MachError::from(os_result))
    //             }
    //         }
    //     }

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
                    .remote = .COPY_SEND,
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
                    .receiver => |rd| rd.port,
                },
                .disposition = .{ .type = switch (port) {
                    .sender => .MOVE_SEND,
                    .receiver => .MOVE_RECEIVE,
                } },
            };
        }

        for (shared_memory_regions, shared_memory_descriptor_dest) |smr, *dest| {
            dest.* = .{
                .address = smr.data.ptr,
                .size = std.math.cast(mach.mach_msg_size_t, smr.data.len) orelse return error.SendTooLarge,
                .deallocate = true,
                .copy = .VIRTUAL_COPY,
            };
        }
        switch (send_data) {
            .out_of_line => |smr| {
                std.debug.assert(shared_memory_descriptor_dest.len == shared_memory_regions.len + 1);
                shared_memory_descriptor_dest[shared_memory_descriptor_dest.len - 1] = .{
                    .address = smr.data.ptr,
                    .size = std.math.cast(mach.mach_msg_size_t, smr.data.len) orelse return error.SendTooLarge,
                    .deallocate = true,
                    .copy = .VIRTUAL_COPY,
                };
            },
            .@"inline" => {},
        }

        is_inline_dest.* = send_data == .@"inline";

        if (send_data == .@"inline") {
            // Zero out the last word for paranoia's sake.
            @memset(message_buf[size - 4 ..], 0);

            const data_size = send_data.@"inline".len;
            const padding_start: [*]u8 = @ptrCast(@as([*]bool, @ptrCast(is_inline_dest)) + 1);
            const padding_count = Message.payloadPadding(@intFromPtr(padding_start));
            // Zero out padding
            @memset(padding_start[0..padding_count], 0);
            const data_size_dest: [*]align(1) usize = @ptrCast(padding_start + padding_count);
            data_size_dest[0] = data_size;

            const data_dest: [*]u8 = @ptrCast(data_size_dest + 1);
            @memcpy(data_dest, send_data.@"inline");
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
            .receiver => |*rd| rd.deinit(),
        }
    }
};

pub const OsOpaqueIpcChannel = struct {
    port: Port,

    pub fn deinit(self: *OsOpaqueIpcChannel) void {
        self.port.dealloc() catch |e| std.debug.panic("mach_port_deallocate: {}", .{e});
    }

    pub fn toSender(self: *OsOpaqueIpcChannel) error{WrongType}!OsIpcSender {
        // TODO: check type
        return .{ .port = self.port };
    }

    pub fn toReceiver(self: *OsOpaqueIpcChannel) error{WrongType}!OsIpcReceiver {
        // TODO: check type
        return .{ .port = self.port };
    }
};

pub const OsIpcReceiverSet = struct {
    port: Port,
    ports: std.ArrayListUnmanaged(Port),

    pub fn new() !@This() {
        return .{
            .port = try Port.alloc(.RIGHT_PORT_SET),
            .ports = .{},
        };
    }

    pub fn deinit(self: *@This()) !void {
        for (self.ports.items) |port| {
            port.release(.RIGHT_RECEIVE);
        }
        try self.port.release(.RIGHT_PORT_SET);
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
    timeout: u64,
};

pub const OsIpcReceiverSetPortId = struct { id: u64 };

pub const OsIpcSelectionResult = struct {
    id: OsIpcReceiverSetPortId,
    event: union(enum) {
        closed,
        received: IpcMessage,
    },
};

// fn select(
//     port: mach_port_t,
//     blocking_mode: BlockingMode,
// ) -> Result<OsIpcSelectionResult, MachError> {
//     debug_assert!(port != MACH_PORT_NULL);
//     unsafe {
//         let mut buffer = [MaybeUninit::<u8>::uninit(); SMALL_MESSAGE_SIZE];
//         let mut allocated_buffer_and_layout = None;
//         setup_receive_buffer(&mut buffer, port);
//         let mut message = NonNull::from(&mut buffer).cast::<Message>();
//         let (flags, timeout) = match blocking_mode {
//             BlockingMode::Blocking => (MACH_RCV_MSG | MACH_RCV_LARGE, MACH_MSG_TIMEOUT_NONE),
//             BlockingMode::Nonblocking => (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT, 0),
//             BlockingMode::Timeout(duration) => duration
//                 .as_millis()
//                 .try_into()
//                 .map(|ms| (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT, ms))
//                 .unwrap_or((MACH_RCV_MSG | MACH_RCV_LARGE, MACH_MSG_TIMEOUT_NONE)),
//         };
//         match mach_sys::mach_msg(
//             ptr::addr_of_mut!((*message.as_ptr()).header),
//             flags,
//             0,
//             *ptr::addr_of_mut!((*message.as_ptr()).header.msgh_size),
//             port,
//             timeout,
//             MACH_PORT_NULL,
//         ) {
//             MACH_RCV_TOO_LARGE => {
//                 println!("hit allocated buffer path");
//                 let max_trailer_size =
//                     mem::size_of::<mach_sys::mach_msg_max_trailer_t>() as mach_sys::mach_msg_size_t;
//                 // the actual size gets written into msgh_size by the kernel
//                 let mut actual_size =
//                     *ptr::addr_of_mut!((*message.as_ptr()).header.msgh_size) + max_trailer_size;
//                 loop {
//                     let Ok(layout) = std::alloc::Layout::array::<u8>(
//                         actual_size.try_into().map_err(|_| MachError::RcvTooLarge)?,
//                     ) else {
//                         return Err(MachError::RcvTooLarge);
//                     };
//                     let Some(allocated_buffer) = NonNull::new(std::alloc::alloc(layout)) else {
//                         std::alloc::handle_alloc_error(layout);
//                     };
//                     allocated_buffer_and_layout = Some((allocated_buffer, layout));
//                     setup_receive_buffer(
//                         NonNull::slice_from_raw_parts(
//                             allocated_buffer.cast::<MaybeUninit<u8>>(),
//                             actual_size as usize,
//                         )
//                         .as_mut(),
//                         port,
//                     );
//                     message = allocated_buffer.cast::<Message>();
//                     match mach_sys::mach_msg(
//                         ptr::addr_of_mut!((*message.as_ptr()).header),
//                         flags,
//                         0,
//                         actual_size,
//                         port,
//                         timeout,
//                         MACH_PORT_NULL,
//                     ) {
//                         MACH_MSG_SUCCESS => break,
//                         MACH_RCV_TOO_LARGE => {
//                             actual_size = *ptr::addr_of_mut!((*message.as_ptr()).header.msgh_size)
//                                 + max_trailer_size;
//                             std::alloc::dealloc(allocated_buffer.as_ptr(), layout);
//                             continue;
//                         },
//                         os_result => {
//                             std::alloc::dealloc(allocated_buffer.as_ptr(), layout);
//                             return Err(MachError::from(os_result));
//                         },
//                     }
//                 }
//             },
//             MACH_MSG_SUCCESS => {},
//             os_result => return Err(MachError::from(os_result)),
//         }
//
//         let local_port = *ptr::addr_of_mut!((*message.as_ptr()).header.msgh_local_port);
//         if *ptr::addr_of_mut!((*message.as_ptr()).header.msgh_id) == MACH_NOTIFY_NO_SENDERS {
//             return Ok(OsIpcSelectionResult::ChannelClosed(local_port as u64));
//         }
//
//         let (mut ports, mut shared_memory_regions) = (Vec::new(), Vec::new());
//         let mut port_descriptor = message.offset(1).cast::<mach_msg_port_descriptor_t>();
//         let mut descriptors_remaining =
//             *ptr::addr_of_mut!((*message.as_ptr()).body.msgh_descriptor_count);
//         while descriptors_remaining > 0 {
//             if port_descriptor.as_ref().type_() != MACH_MSG_PORT_DESCRIPTOR {
//                 break;
//             }
//             ports.push(OsOpaqueIpcChannel::from_name(port_descriptor.as_ref().name));
//             port_descriptor = port_descriptor.offset(1);
//             descriptors_remaining -= 1;
//         }
//
//         let mut shared_memory_descriptor = port_descriptor.cast::<mach_msg_ool_descriptor_t>();
//         while descriptors_remaining > 0 {
//             debug_assert!(shared_memory_descriptor.as_ref().type_() == MACH_MSG_OOL_DESCRIPTOR);
//             shared_memory_regions.push(OsIpcSharedMemory::from_raw_parts(
//                 shared_memory_descriptor.as_ref().address as *mut u8,
//                 shared_memory_descriptor.as_ref().size as usize,
//             ));
//             shared_memory_descriptor = shared_memory_descriptor.offset(1);
//             descriptors_remaining -= 1;
//         }
//
//         let has_inline_data_ptr = shared_memory_descriptor.cast::<bool>();
//         let has_inline_data = *has_inline_data_ptr.as_ref();
//         let payload = if has_inline_data {
//             let padding_start = has_inline_data_ptr.offset(1).cast::<u8>();
//             let padding_count = Message::payload_padding(padding_start.addr().get());
//             let payload_size_ptr = padding_start.add(padding_count).cast::<usize>();
//             let payload_size = *payload_size_ptr.as_ref();
//             let max_payload_size = message.addr().get()
//                 + (message.as_ref().header.msgh_size as usize)
//                 - shared_memory_descriptor.addr().get();
//             assert!(payload_size <= max_payload_size);
//             let payload_ptr = payload_size_ptr.offset(1).cast::<u8>();
//             NonNull::slice_from_raw_parts(payload_ptr, payload_size)
//                 .as_ref()
//                 .to_vec()
//         } else {
//             let ool_payload = shared_memory_regions
//                 .pop()
//                 .expect("Missing OOL shared memory region");
//             ool_payload.to_vec()
//         };
//
//         if let Some((allocated_buffer, layout)) = allocated_buffer_and_layout {
//             std::alloc::dealloc(allocated_buffer.cast().as_ptr(), layout)
//         }
//
//         Ok(OsIpcSelectionResult::DataReceived(
//             local_port as u64,
//             IpcMessage::new(payload, ports, shared_memory_regions),
//         ))
//     }
// }

// pub struct OsIpcOneShotServer {
//     receiver: OsIpcReceiver,
//     name: String,
//     registration_port: u32,
// }
//
// impl Drop for OsIpcOneShotServer {
//     fn drop(&mut self) {
//         let _ = OsIpcReceiver::unregister_global_name(std::mem::take(&mut self.name));
//         deallocate_mach_port(self.registration_port);
//     }
// }
//
// impl OsIpcOneShotServer {
//     pub fn new() -> Result<(OsIpcOneShotServer, String), MachError> {
//         let receiver = OsIpcReceiver::new()?;
//         let (registration_port, name) = receiver.register_bootstrap_name()?;
//         Ok((
//             OsIpcOneShotServer {
//                 receiver,
//                 name: name.clone(),
//                 registration_port,
//             },
//             name,
//         ))
//     }
//
//     pub fn accept(self) -> Result<(OsIpcReceiver, IpcMessage), MachError> {
//         let ipc_message = self.receiver.recv()?;
//         Ok((self.receiver.consume(), ipc_message))
//     }
// }

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

fn setupReceiveBuffer(buffer: []u8, port: Port) !void {
    const header: *mach.mach_msg_header_t = @ptrCast(buffer);
    header.* = .{
        .msgh_bits = 0,
        .msgh_size = std.math.cast(c_uint, buffer.len) orelse return error{TooLarge},
        .msgh_remote_port = 0,
        .msgh_local_port = port,
        .msgh_voucher_port = 0,
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

test {
    _ = std.testing.refAllDecls(@This());
}
