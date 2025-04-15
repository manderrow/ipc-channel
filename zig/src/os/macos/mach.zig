const std = @import("std");

const util = @import("../../util.zig");

pub const Port = extern struct {
    /// `mach_port_t` and `mach_port_name_t` seem to be interchangeable.
    name: std.c.mach_port_t,

    pub const @"null": Port = .{ .name = 0 };

    pub inline fn isNull(self: @This()) bool {
        return self.name == Port.null.name;
    }

    pub fn alloc(right: mach_port_right_t) KernelError!Port {
        var name: Port = undefined;
        const rt = mach_port_allocate(mach_task_self(), right, &name);
        try checkKernelReturn(rt);
        return name;
    }

    pub fn dealloc(self: Port) KernelError!void {
        std.debug.assert(!self.isNull());
        // mach_port_deallocate and mach_port_mod_refs are very similar, except that
        // mach_port_mod_refs returns an error when there are no receivers for the port,
        // causing the sender port to never be deallocated. mach_port_deallocate handles
        // this case correctly and is therefore important to avoid dangling port leaks.
        const rt = mach_port_deallocate(mach_task_self(), self);
        try checkKernelReturn(rt);
    }

    pub fn release(self: Port, right: mach_port_right_t) KernelError!void {
        std.debug.assert(!self.isNull());
        const rt = mach_port_mod_refs(mach_task_self(), self, right, -1);
        try checkKernelReturn(rt);
    }

    pub fn addRef(self: Port, right: mach_port_right_t) KernelError!void {
        std.debug.assert(!self.isNull());
        const rt = mach_port_mod_refs(mach_task_self(), self, right, 1);
        try checkKernelReturn(rt);
    }

    pub fn extractRight(self: Port, desired_type: MachPortExtractRightType) (error{
        /// The port was invalid, not denoting any rights.
        ///
        /// Corresponds to `KERN_INVALID_NAME`.
        InvalidPort,
        /// The port was valid, denoting a right, but not legal for this call.
        ///
        /// Corresponds to `KERN_INVALID_RIGHT`.
        IllegalPort,
        /// The desired type was invalid,
        ///
        /// Corresponds to `KERN_INVALID_VALUE`.
        InvalidType,
    } || MachError)!Port {
        std.debug.assert(!self.isNull());
        var out_name: Port = undefined;
        var acquired_right: MachPortType = undefined;
        const rt = mach_port_extract_right(mach_task_self(), self, desired_type, &out_name, &acquired_right);
        switch (rt) {
            .KERN_SUCCESS => {},
            // mach_task_self should never be invalid
            .KERN_INVALID_TASK => unreachable,
            .KERN_INVALID_NAME => return error.InvalidPort,
            .KERN_INVALID_RIGHT => return error.IllegalPort,
            .KERN_INVALID_VALUE => return error.InvalidType,
            else => try checkMachReturn(@enumFromInt(@intFromEnum(rt))),
        }
        std.debug.assert(acquired_right == @as(MachPortType, switch (desired_type) {
            .move_receive => .recv,
            .make_send, .move_send, .copy_send => .send,
            .make_send_once, .move_send_once => .send_once,
        }));
        return out_name;
    }

    pub fn moveMember(self: Port, set: Port) KernelError!void {
        std.debug.assert(!self.isNull());
        const rt = mach_port_move_member(mach_task_self(), self, set);
        try checkKernelReturn(rt);
    }

    pub fn requestNotification(
        self: Port,
        msgid: mach_msg_id_t,
        sync: mach_port_mscount_t,
        notify: Port,
        notify_poly: MachMsgTypeName,
    ) KernelError!struct { previous: Port } {
        std.debug.assert(!self.isNull());
        var previous: Port = .null;
        const rt = mach_port_request_notification(
            mach_task_self(),
            self,
            msgid,
            sync,
            notify,
            .{ .type = notify_poly },
            &previous,
        );
        try checkKernelReturn(rt);
        return .{ .previous = previous };
    }

    pub fn setAttributes(self: Port, flavor: mach_port_flavor_t, port_info: mach_port_info_t, port_info_cnt: mach_msg_type_number_t) KernelError!void {
        std.debug.assert(!self.isNull());
        const rt = mach_port_set_attributes(
            mach_task_self(),
            self,
            flavor,
            port_info,
            port_info_cnt,
        );
        try checkKernelReturn(rt);
    }
};

pub const KernelError = error{
    /// The supplied (port) capability is improper.
    InvalidCapability,
    /// Name doesn't denote a right in the task.
    InvalidName,
    /// Target task isn't an active task.
    InvalidTask,
    /// Name denotes a right, but not an appropriate right.
    InvalidRight,
    /// Blatant range error.
    InvalidValue,
    /// No room in IPC name space for another right.
    NoSpace,
    /// Receive right is not a member of a port set.
    NotInSet,
    /// Operation would overflow limit on user-references.
    UrefsOverflow,
    Unexpected,
};

pub fn checkKernelReturn(code: kern_return_t) KernelError!void {
    return switch (code) {
        .SUCCESS => {},
        .NO_SPACE => error.NoSpace,
        .INVALID_NAME => error.InvalidName,
        .INVALID_TASK => error.InvalidTask,
        .INVALID_RIGHT => error.InvalidRight,
        .INVALID_VALUE => error.InvalidValue,
        .INVALID_CAPABILITY => error.InvalidCapability,
        .UREFS_OVERFLOW => error.UrefsOverflow,
        .NOT_IN_SET => error.NotInSet,
        else => error.Unexpected,
    };
}

pub const kern_return_t = enum(std.c.kern_return_t) {
    SUCCESS = 0,
    NO_SPACE = 3,
    NOT_IN_SET = 12,
    INVALID_NAME = 15,
    INVALID_TASK = 16,
    INVALID_RIGHT = 17,
    INVALID_VALUE = 18,
    UREFS_OVERFLOW = 19,
    INVALID_CAPABILITY = 20,
    _,
};

pub const MachError = error{
    /// Kernel resource shortage handling an IPC capability.
    IpcKernel,
    /// No room in IPC name space for another capability name.
    IpcSpace,
    /// No senders exist for this port.
    NotifyNoSenders,
    /// Error receiving message body.  See special bits.
    RcvBodyError,
    /// Error receiving message header.  See special bits.
    RcvHeaderError,
    /// Thread is waiting for receive.  (Internal use only.)
    RcvInProgress,
    /// Waiting for receive with timeout. (Internal use only.)
    RcvInProgressTimed,
    /// compatibility: no longer a returned error
    RcvInSet,
    /// Software interrupt.
    RcvInterrupted,
    /// Bogus message buffer for inline data.
    RcvInvalidData,
    /// Bogus name for receive port/port-set.
    RcvInvalidName,
    /// Bogus notify port argument.
    RcvInvalidNotify,
    /// trailer type or number of trailer elements not supported
    RcvInvalidTrailer,
    /// Invalid msg-type specification in scatter list.
    RcvInvalidType,
    /// compatibility: no longer a returned error
    RcvPortChanged,
    /// Port/set was sent away/died during receive.
    RcvPortDied,
    /// Out-of-line overwrite region is not large enough
    RcvScatterSmall,
    /// Didn't get a message within the timeout value.
    RcvTimedOut,
    /// Message buffer is not large enough for inline data.
    RcvTooLarge,
    /// Thread is waiting to send.  (Internal use only.)
    SendInProgress,
    /// Software interrupt.
    SendInterrupted,
    /// Bogus in-line data.
    SendInvalidData,
    /// Bogus destination port.
    SendInvalidDest,
    /// A field in the header had a bad value.
    SendInvalidHeader,
    /// Invalid out-of-line memory pointer.
    SendInvalidMemory,
    /// Bogus notify port argument.
    SendInvalidNotify,
    /// Bogus reply port.
    SendInvalidReply,
    /// Bogus port rights in the message body.
    SendInvalidRight,
    /// compatibility: no longer a returned error
    SendInvalidRtOolSize,
    /// The trailer to be sent does not match kernel format.
    SendInvalidTrailer,
    /// Invalid msg-type specification.
    SendInvalidType,
    /// Bogus voucher port.
    SendInvalidVoucher,
    /// Data doesn't contain a complete message.
    SendMsgTooSmall,
    /// No message buffer is available.
    SendNoBuffer,
    /// Message not sent before timeout expired.
    SendTimedOut,
    /// Send is too large for port
    SendTooLarge,
    /// Kernel resource shortage handling out-of-line memory.
    VmKernel,
    /// No room in VM address space for out-of-line memory.
    VmSpace,
    Unexpected,
};

pub fn checkMachReturn(code: mach_msg_return_t) MachError!void {
    return switch (code) {
        .MSG_SUCCESS => {},
        .MSG_IPC_KERNEL => error.IpcKernel,
        .MSG_IPC_SPACE => error.IpcSpace,
        .MSG_VM_KERNEL => error.VmKernel,
        .MSG_VM_SPACE => error.VmSpace,
        .RCV_BODY_ERROR => error.RcvBodyError,
        .RCV_HEADER_ERROR => error.RcvHeaderError,
        .RCV_INTERRUPTED => error.RcvInterrupted,
        .RCV_INVALID_DATA => error.RcvInvalidData,
        .RCV_INVALID_NAME => error.RcvInvalidName,
        .RCV_INVALID_NOTIFY => error.RcvInvalidNotify,
        .RCV_INVALID_TRAILER => error.RcvInvalidTrailer,
        .RCV_INVALID_TYPE => error.RcvInvalidType,
        .RCV_IN_PROGRESS => error.RcvInProgress,
        .RCV_IN_PROGRESS_TIMED => error.RcvInProgressTimed,
        .RCV_IN_SET => error.RcvInSet,
        .RCV_PORT_CHANGED => error.RcvPortChanged,
        .RCV_PORT_DIED => error.RcvPortDied,
        .RCV_SCATTER_SMALL => error.RcvScatterSmall,
        .RCV_TIMED_OUT => error.RcvTimedOut,
        .RCV_TOO_LARGE => error.RcvTooLarge,
        .NOTIFY_NO_SENDERS => error.NotifyNoSenders,
        .SEND_INTERRUPTED => error.SendInterrupted,
        .SEND_INVALID_DATA => error.SendInvalidData,
        .SEND_INVALID_DEST => error.SendInvalidDest,
        .SEND_INVALID_HEADER => error.SendInvalidHeader,
        .SEND_INVALID_MEMORY => error.SendInvalidMemory,
        .SEND_INVALID_NOTIFY => error.SendInvalidNotify,
        .SEND_INVALID_REPLY => error.SendInvalidReply,
        .SEND_INVALID_RIGHT => error.SendInvalidRight,
        .SEND_INVALID_RT_OOL_SIZE => error.SendInvalidRtOolSize,
        .SEND_INVALID_TRAILER => error.SendInvalidTrailer,
        .SEND_INVALID_TYPE => error.SendInvalidType,
        .SEND_INVALID_VOUCHER => error.SendInvalidVoucher,
        .SEND_IN_PROGRESS => error.SendInProgress,
        .SEND_MSG_TOO_SMALL => error.SendMsgTooSmall,
        .SEND_NO_BUFFER => error.SendNoBuffer,
        .SEND_TIMED_OUT => error.SendTimedOut,
        .SEND_TOO_LARGE => error.SendTooLarge,
        _ => error.Unexpected,
    };
}

pub fn checkKernOrMachReturn(code: kern_or_mach_msg_return_t) (KernelError || MachError)!void {
    checkKernelReturn(@enumFromInt(@intFromEnum(code))) catch |e| switch (e) {
        error.Unexpected => try checkMachReturn(@enumFromInt(@intFromEnum(code))),
        else => return e,
    };
}

pub const mach_msg_return_t = enum(std.c.kern_return_t) {
    MSG_SUCCESS = 0,
    MSG_IPC_KERNEL = 0x00000800,
    MSG_IPC_SPACE = 0x00002000,
    MSG_VM_KERNEL = 0x00000400,
    MSG_VM_SPACE = 0x00001000,
    RCV_BODY_ERROR = 0x1000400c,
    RCV_HEADER_ERROR = 0x1000400b,
    RCV_INTERRUPTED = 0x10004005,
    RCV_INVALID_DATA = 0x10004008,
    RCV_INVALID_NAME = 0x10004002,
    RCV_INVALID_NOTIFY = 0x10004007,
    RCV_INVALID_TRAILER = 0x1000400f,
    RCV_INVALID_TYPE = 0x1000400d,
    RCV_IN_PROGRESS = 0x10004001,
    RCV_IN_PROGRESS_TIMED = 0x10004011,
    RCV_IN_SET = 0x1000400a,
    RCV_PORT_CHANGED = 0x10004006,
    RCV_PORT_DIED = 0x10004009,
    RCV_SCATTER_SMALL = 0x1000400e,
    RCV_TIMED_OUT = 0x10004003,
    RCV_TOO_LARGE = 0x10004004,
    NOTIFY_NO_SENDERS = MACH_NOTIFY_NO_SENDERS,
    SEND_INTERRUPTED = 0x10000007,
    SEND_INVALID_DATA = 0x10000002,
    SEND_INVALID_DEST = 0x10000003,
    SEND_INVALID_HEADER = 0x10000010,
    SEND_INVALID_MEMORY = 0x1000000c,
    SEND_INVALID_NOTIFY = 0x1000000b,
    SEND_INVALID_REPLY = 0x10000009,
    SEND_INVALID_RIGHT = 0x1000000a,
    SEND_INVALID_RT_OOL_SIZE = 0x10000015,
    SEND_INVALID_TRAILER = 0x10000011,
    SEND_INVALID_TYPE = 0x1000000f,
    SEND_INVALID_VOUCHER = 0x10000005,
    SEND_IN_PROGRESS = 0x10000001,
    SEND_MSG_TOO_SMALL = 0x10000008,
    SEND_NO_BUFFER = 0x1000000d,
    SEND_TIMED_OUT = 0x10000004,
    SEND_TOO_LARGE = 0x1000000e,
    _,
};

pub const kern_or_mach_msg_return_t = util.MergeEnums(kern_return_t, "KERN_", util.ExcludeEnumVariant(mach_msg_return_t, .MSG_SUCCESS), "MACH_");

const ipc_space_t = std.c.ipc_space_t;
const mach_msg_type_name_t = packed struct(std.c.mach_msg_type_name_t) {
    type: MachMsgTypeName,
    padding: std.meta.Int(.unsigned, @bitSizeOf(c_uint) - @bitSizeOf(MachMsgTypeName)) = 0,
};

pub const mach_msg_size_t = c_uint;
pub const mach_msg_type_number_t = c_uint;
pub const mach_port_delta_t = c_int;
pub const mach_port_flavor_t = c_int;
pub const mach_port_info_t = *c_int;
pub const mach_port_msgcount_t = c_uint;
pub const mach_msg_id_t = c_int;
pub const mach_port_mscount_t = c_uint;

pub const MACH_NOTIFY_FIRST: c_int = 64;
pub const MACH_NOTIFY_NO_SENDERS: c_int = MACH_NOTIFY_FIRST + 6;

pub const mach_msg_descriptor = struct {
    pub const Type = enum(u8) {
        PORT_DESCRIPTOR = 0,
        OOL_DESCRIPTOR = 1,
        OOL_PORTS_DESCRIPTOR = 2,
        OOL_VOLATILE_DESCRIPTOR = 3,
        GUARDED_PORT_DESCRIPTOR = 4,
    };
};

pub const MachMsgTypeName = enum(u5) {
    /// Must hold receive right
    MOVE_RECEIVE = 16,
    /// Must hold send right(s)
    MOVE_SEND = 17,
    /// Must hold sendonce right
    MOVE_SEND_ONCE = 18,
    /// Must hold send right(s)
    COPY_SEND = 19,
    /// Must hold receive right
    MAKE_SEND = 20,
    /// Must hold receive right
    MAKE_SEND_ONCE = 21,
    /// NOT VALID
    COPY_RECEIVE = 22,
    /// must hold receive right
    DISPOSE_RECEIVE = 24,
    /// must hold send right(s)
    DISPOSE_SEND = 25,
    /// must hold sendonce right
    DISPOSE_SEND_ONCE = 26,
};

pub const MachPortType = enum(std.c.mach_msg_type_name_t) {
    none = 0,
    /// According to Apple's `mach/message.h` header file:
    /// > Used to transfer a port name which should remain uninterpreted by the kernel.
    /// Port rights are not transferred, just the port name.
    ///
    /// TODO: by "name" do they mean simply the numerical name, or is there any kernel
    ///       state transferred? "uninterpreted by the kernel" sounds like no.
    name = 15,
    recv = @intFromEnum(MachMsgTypeName.MOVE_RECEIVE),
    send = @intFromEnum(MachMsgTypeName.MOVE_SEND),
    send_once = @intFromEnum(MachMsgTypeName.MOVE_SEND_ONCE),
};

pub const mach_port_right_t = enum(std.c.mach_port_right_t) {
    RIGHT_SEND = 0,
    RIGHT_RECEIVE = 1,
    RIGHT_SEND_ONCE = 2,
    RIGHT_PORT_SET = 3,
    RIGHT_DEAD_NAME = 4,
    /// obsolete right
    RIGHT_LABELH = 5,
    /// right not implemented
    RIGHT_NUMBER = 6,
    _,
};

pub const mach_msg_port_descriptor_t = extern struct {
    name: Port,
    pad1: mach_msg_size_t = 0,
    pad2: u16 = 0,
    disposition: packed struct(u8) {
        type: MachMsgTypeName,
        padding: u3 = 0,
    },
    type: mach_msg_descriptor.Type = .PORT_DESCRIPTOR,
};

pub const mach_msg_ool_descriptor_t = extern struct {
    address: *anyopaque,
    size: mach_msg_size_t,
    deallocate: bool,
    copy: enum(u8) {
        PHYSICAL_COPY = 0,
        VIRTUAL_COPY = 1,
        ALLOCATE = 2,
        /// deprecated
        OVERWRITE = 3,
        /// only if `MACH_KERNEL`
        KALLOC_COPY_T = 4,
    },
    pad1: u8 = 0,
    type: mach_msg_descriptor.Type = .OOL_DESCRIPTOR,
};

pub const mach_port_limits = extern struct {
    mpl_qlimit: mach_port_msgcount_t,
};

pub const NullableMachMsgTypeName = util.MergeEnums(MachMsgTypeName, null, enum(u5) {
    null = 0,
}, null);

pub const mach_msg_bits_t = packed struct(c_uint) {
    remote: NullableMachMsgTypeName = .null,
    unused1: u3 = 0,
    local: NullableMachMsgTypeName = .null,
    unused2: u3 = 0,
    voucher: NullableMachMsgTypeName = .null,
    unused3: u3 = 0,
    unused4: u4 = 0,
    /// Not "allowed" userland->kernel.
    uk: packed union {
        /// Assertion help, userland private.
        impholdasrt: bool,
        /// Message circular, kernel private.
        circular: bool,
    } = .{ .impholdasrt = false },
    /// Importance raised due to msg. Not "allowed" userland->kernel.
    raise_imp: bool = false,
    unused5: u1 = 0,
    complex: bool,
};

pub const mach_msg_header_t = extern struct {
    msgh_bits: mach_msg_bits_t,
    msgh_size: mach_msg_size_t,
    msgh_remote_port: Port,
    msgh_local_port: Port,
    msgh_voucher_port: Port,
    msgh_id: std.c.mach_msg_id_t,
};

pub const mach_msg_body_t = extern struct {
    msgh_descriptor_count: mach_msg_size_t,
};

/// Documented [here](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/osfmk/mach/mach_port.defs#L327-L341).
pub const MachPortExtractRightType = enum(std.c.mach_msg_type_name_t) {
    move_receive = @intFromEnum(MachMsgTypeName.MOVE_RECEIVE),
    copy_send = @intFromEnum(MachMsgTypeName.COPY_SEND),
    make_send = @intFromEnum(MachMsgTypeName.MAKE_SEND),
    move_send = @intFromEnum(MachMsgTypeName.MOVE_SEND),
    make_send_once = @intFromEnum(MachMsgTypeName.MAKE_SEND_ONCE),
    move_send_once = @intFromEnum(MachMsgTypeName.MOVE_SEND_ONCE),
};

extern var mach_task_self_: ipc_space_t;
pub inline fn mach_task_self() ipc_space_t {
    return mach_task_self_;
}

pub extern "C" fn mach_port_allocate(
    task: ipc_space_t,
    right: mach_port_right_t,
    name: *Port,
) kern_return_t;

pub extern "C" fn mach_port_deallocate(
    task: ipc_space_t,
    name: Port,
) kern_return_t;

pub extern "C" fn mach_port_extract_right(
    task: ipc_space_t,
    name: Port,
    message_type: MachPortExtractRightType,
    out_name: *Port,
    acquired_right: *MachPortType,
) kern_or_mach_msg_return_t;

pub extern "C" fn mach_port_mod_refs(
    task: ipc_space_t,
    name: Port,
    right: mach_port_right_t,
    delta: mach_port_delta_t,
) kern_return_t;

pub extern "C" fn mach_port_move_member(
    task: ipc_space_t,
    name: Port,
    set: Port,
) kern_return_t;

pub extern "C" fn mach_port_request_notification(
    task: ipc_space_t,
    name: Port,
    msgid: mach_msg_id_t,
    sync: mach_port_mscount_t,
    notify: Port,
    notifyPoly: mach_msg_type_name_t,
    previous: *Port,
) kern_return_t;

pub extern "C" fn mach_port_set_attributes(
    task: ipc_space_t,
    name: Port,
    flavor: mach_port_flavor_t,
    port_info: mach_port_info_t,
    port_info_cnt: mach_msg_type_number_t,
) kern_return_t;

pub const task_special_port_t = enum(c_int) {
    /// The full task port for task.
    kernel = 1,
    /// The host (priv) port for task.
    host = 2,
    /// The name port for task.
    name = 3,
    /// Bootstrap environment for task.
    bootstrap = 4,
    /// The inspect port for task.
    inspect = 5,
    /// The read port for task.
    read = 6,
    _,
};

pub extern "C" fn task_get_special_port(
    task: ipc_space_t,
    which_port: task_special_port_t,
    special_port: *Port,
) kern_return_t;

pub extern "C" fn vm_allocate(
    target_task: std.c.vm_map_t,
    address: **anyopaque,
    size: std.c.vm_size_t,
    flags: VmAllocationFlags,
) kern_return_t;

pub extern "C" fn vm_remap(
    target_task: std.c.vm_map_t,
    target_address: **anyopaque,
    size: std.c.vm_size_t,
    mask: std.c.vm_address_t,
    flags: VmAllocationFlags,
    src_task: std.c.vm_map_t,
    src_address: *anyopaque,
    copy: std.c.boolean_t,
    cur_protection: *std.c.vm_prot_t,
    max_protection: *std.c.vm_prot_t,
    inheritance: std.c.vm_inherit_t,
) kern_return_t;

pub const VmAllocationFlags = packed struct(c_int) {
    // VM_FLAGS_NO_PMAP_CHECK
    ///  (for DEBUG kernel config only, ignored for other configs)
    ///  Do not check that there is no stale pmap mapping for the new VM region.
    ///  This is useful for kernel memory allocations at bootstrap when building
    ///  the initial kernel address space while some memory is already in use.
    /// See docs of `anywhere`.
    const fixed: VmAllocationFlags = .{};

    /// Allocate new VM region anywhere it would fit in the address space. If `false`,
    /// allocate new VM region at the specified virtual address, if possible.
    anywhere: bool = false,

    ///  Create a purgable VM object for that new VM region.
    purgable: bool = false,

    ///  The new VM region will be chunked up into 4GB sized pieces.
    @"4gb_chunk": bool = false,

    random_addr: bool = false,

    ///  Pages brought in to this VM region are placed on the speculative
    ///  queue instead of the active queue.  In other words, they are not
    ///  cached so that they will be stolen first if memory runs low.
    no_cache: bool = false,

    resilient_codesign: bool = false,

    resilient_media: bool = false,

    permanent: bool = false,

    _skip1: bool = false,
    _skip2: bool = false,
    _skip3: bool = false,
    _skip4: bool = false,

    tpro: bool = false,

    ///  The new VM region can replace existing VM regions if necessary
    ///  (to be used in combination with VM_FLAGS_FIXED).
    overwrite: bool = false,

    padding: u18 = 0,
};

pub fn vmAllocate(length: usize) error{ OutOfMemory, Unexpected }![]u8 {
    var address: [*]u8 = undefined;
    const rt = vm_allocate(
        mach_task_self(),
        @ptrCast(&address),
        length,
        .{ .anywhere = true },
    );
    return switch (rt) {
        .SUCCESS => address[0..length],
        .NO_SPACE => error.OutOfMemory,
        else => error.Unexpected,
    };
}
