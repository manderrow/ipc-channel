const builtin = @import("builtin");
const std = @import("std");
const socketpair = switch (builtin.os.tag) {
    .linux => std.os.linux.socketpair,
    else => std.c.socketpair,
};

const os = @import("../os.zig");
const BlockingMode = os.BlockingMode;
const IpcMessage = os.IpcMessage;
const SelectionResult = os.SelectionResult;

const MAX_FDS_IN_CMSG = 64;

/// The value Linux returns for SO_SNDBUF
/// is not the size we are actually allowed to use...
/// Empirically, we have to deduct 32 bytes from that.
const RESERVED_SIZE = 32;

const SOCK_FLAGS = switch (builtin.os.tag) {
    .linux, .illumos => std.posix.SOCK.CLOEXEC,
    else => 0,
};

const RECVMSG_FLAGS = switch (builtin.os.tag) {
    .linux, .illumos => std.posix.MSG.CMSG_CLOEXEC,
    else => 0,
};

const IovLen = if (builtin.target.abi.isGnu()) usize else i32;
const MsgControlLen = if (builtin.target.abi.isGnu()) usize else std.posix.socklen_t;

// old return value included sizeof(std.posix.sockaddr.un)
fn new_sockaddr_un(path: []const u8) error{OutOfMemory}!std.posix.sockaddr.un {
    var sockaddr: std.posix.sockaddr.un = .{
        .path = undefined,
    };
    if (path.len > sockaddr.path.len - 1) {
        return error.OutOfMemory;
    }
    @memcpy(sockaddr.path[0..path.len], path);
    sockaddr.path[path.len] = 0;
    return sockaddr;
}

/// Documented minimum value (on Linux) is 2048. For our purposes, `0` is a "null" value.
///
/// Don't access directly. Call `getCachedSystemSendbufSize` instead.
var system_sendbuf_size: std.atomic.Value(usize) = .init(0);

fn getCachedSystemSendbufSize() !usize {
    var size = system_sendbuf_size.load(.monotonic);
    if (size != 0) return size;
    var chan = try channel();
    defer {
        chan.rc.deinit();
        chan.sd.deinit();
    }
    size = try chan.sd.getSystemSendbufSize();
    system_sendbuf_size.store(size, .monotonic);
    return size;
}

/// The pid of the current process which is used to create unique IDs. `0` is a "null" value.
var current_pid: std.atomic.Value(std.posix.pid_t) = .init(0);

fn getPid() std.posix.pid_t {
    var pid = current_pid.load(.monotonic);
    if (pid != 0) return pid;
    pid = std.os.linux.getpid();
    current_pid.store(pid, .monotonic);
    return pid;
}

// A global count used to create unique IDs
var shm_count: std.atomic.Value(usize) = .init(0);

pub fn channel() !struct { sd: Sender, rc: Receiver } {
    var results: [2]i32 = undefined;
    return switch (std.posix.errno(socketpair(std.posix.AF.UNIX, std.posix.SOCK.SEQPACKET | SOCK_FLAGS, 0, &results))) {
        .SUCCESS => .{
            .sd = .{ .fd = results[0] },
            .rc = .{ .fd = results[1] },
        },
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        // invalid `fd` pointer, impossible
        .FAULT => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        // "The specified protocol does not support creation of socket pairs."
        .OPNOTSUPP => |e| std.posix.unexpectedErrno(e),
        // "The specified protocol is not supported on this machine."
        .PROTONOSUPPORT => |e| std.posix.unexpectedErrno(e),
        else => |e| std.posix.unexpectedErrno(e),
    };
}

const PollEntry = struct {
    id: u64,
    fd: std.posix.fd_t,
};

pub const Receiver = struct {
    fd: std.posix.fd_t,

    pub fn deinit(self: @This()) void {
        std.posix.close(self.fd);
    }

    pub fn consume(self: *@This()) Receiver {
        const fd = self.fd;
        self.fd = undefined;
        return .{ .fd = fd };
    }

    pub fn recv(self: @This(), alloc: std.mem.Allocator) !IpcMessage {
        return self.recvOptions(alloc, .blocking);
    }

    pub fn tryRecv(self: @This(), alloc: std.mem.Allocator) !IpcMessage {
        return self.recvOptions(alloc, .nonblocking);
    }

    /// `duration` is measured in milliseconds.
    pub fn tryRecvTimeout(self: @This(), alloc: std.mem.Allocator, duration: u64) !IpcMessage {
        return self.recvOptions(alloc, .{ .timeout = duration });
    }

    fn recvOptions(self: @This(), alloc: std.mem.Allocator, blocking_mode: BlockingMode) !IpcMessage {
        var channels: std.ArrayListUnmanaged(OpaqueChannel) = .empty;
        errdefer channels.deinit(alloc);

        var shared_memory_regions: std.ArrayListUnmanaged(SharedMemory) = .empty;
        errdefer shared_memory_regions.deinit(alloc);

        // First fragments begins with a header recording the total data length.
        //
        // We use this to determine whether we already got the entire message,
        // or need to receive additional fragments -- and if so, how much.
        var total_size: usize = 0;
        var data_buffer = try alloc.alloc(u8, try Sender.getMaxFragmentSize());
        errdefer alloc.free(data_buffer);

        var iovec: [2]std.posix.iovec = .{
            .{
                .base = std.mem.asBytes(&total_size).ptr,
                .len = std.mem.asBytes(&total_size).len,
            },
            .{
                .base = data_buffer.ptr,
                .len = data_buffer.len,
            },
        };
        var cmsg: UnixCmsg = undefined;
        try cmsg.init(&iovec);

        const bytes_read = try cmsg.recv(self.fd, blocking_mode);
        const main_data = data_buffer[0 .. bytes_read - @sizeOf(@TypeOf(total_size))];

        const cmsg_fds: [*]const c_int = @ptrCast(cmsgData(cmsg.cmsgBuffer()));
        const cmsg_length = cmsg.msghdr.controllen;
        // The control header is followed by an array of FDs. The size of the control header is
        // determined by CMSG_SPACE. (On Linux this would the same as CMSG_ALIGN, but that isn't
        // exposed by libc. CMSG_SPACE(0) is the portable version of that.)
        const channel_length = if (cmsg_length == 0) 0 else ((cmsg.cmsgLen() - comptime cmsgSpace(0)) / @sizeOf(c_int));
        for (cmsg_fds[0..channel_length]) |fd| {
            if (isSocket(fd)) {
                try channels.append(alloc, .{ .fd = fd });
            } else {
                try shared_memory_regions.append(alloc, try SharedMemory.fromFd(fd));
            }
        }

        if (total_size == main_data.len) {
            // Fast path: no fragments.
            data_buffer = try alloc.realloc(data_buffer, main_data.len);
            return .{
                .data = data_buffer,
                .channels = try channels.toOwnedSlice(alloc),
                .shared_memory_regions = try shared_memory_regions.toOwnedSlice(alloc),
            };
        }

        // Reassemble fragments.
        //
        // The initial fragment carries the receive end of a dedicated channel
        // through which all the remaining fragments will be coming in.
        const dedicated_rx = try (channels.pop() orelse return error.InvalidMessage).asReceiver();

        // Extend the buffer to hold the entire message, without initialising the memory.
        data_buffer = try alloc.realloc(data_buffer, total_size);

        //     // Receive followup fragments directly into the main buffer.
        var len = main_data.len;
        while (len < total_size) {
            const end_pos = @min(
                len + Sender.fragment_size(try getCachedSystemSendbufSize()),
                total_size,
            );
            const max_chunk_len = end_pos - len;

            // Note: we always use blocking mode for followup fragments,
            // to make sure that once we start receiving a multi-fragment message,
            // we don't abort in the middle of it...
            const result = try std.posix.recv(
                dedicated_rx.fd,
                data_buffer[len..end_pos],
                0,
            );
            std.debug.assert(result <= max_chunk_len);
            len += result;

            if (result == 0) {
                return error.ChannelClosed;
            }
        }

        return .{
            .data = data_buffer,
            .channels = try channels.toOwnedSlice(alloc),
            .shared_memory_regions = try shared_memory_regions.toOwnedSlice(alloc),
        };
    }
};

const SCM = enum(c_int) {
    RIGHTS = 0x01,
    CREDENTIALS = 0x02,
};

pub const Sender = struct {
    fd: std.posix.fd_t,

    pub fn deinit(self: @This()) void {
        std.posix.close(self.fd);
    }

    pub fn clone(self: @This()) !Sender {
        return .{ .fd = try std.posix.dup(self.fd) };
    }

    /// Maximum size of the kernel buffer used for transfers over this channel.
    ///
    /// Note: This is *not* the actual maximal packet size we are allowed to use...
    /// Some of it is reserved by the kernel for bookkeeping.
    fn getSystemSendbufSize(self: @This()) !usize {
        var socket_sendbuf_size: c_int = 0;
        var socket_sendbuf_size_len: std.posix.socklen_t = @sizeOf(c_int);
        switch (std.posix.errno(std.posix.system.getsockopt(
            self.fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDBUF,
            std.mem.asBytes(&socket_sendbuf_size).ptr,
            &socket_sendbuf_size_len,
        ))) {
            .SUCCESS => {
                std.debug.assert(socket_sendbuf_size_len == @sizeOf(c_int));
            },
            .BADF => unreachable,
            .NOTSOCK => unreachable,
            .INVAL => unreachable,
            .FAULT => unreachable,
            .NOPROTOOPT => return error.InvalidProtocolOption,
            .NOMEM => return error.SystemResources,
            .NOBUFS => return error.SystemResources,
            .ACCES => return error.AccessDenied,
            else => |err| return std.posix.unexpectedErrno(err),
        }
        return std.math.cast(usize, socket_sendbuf_size) orelse return error.Overflow;
    }

    /// Calculate maximum payload data size per fragment.
    ///
    /// It is the total size of the kernel buffer, minus the part reserved by the kernel.
    ///
    /// The `sendbuf_size` passed in should usually be the maximum kernel buffer size,
    /// i.e. the value of *SYSTEM_SENDBUF_SIZE --
    /// except after getting ENOBUFS, in which case it needs to be reduced.
    fn fragment_size(sendbuf_size: usize) usize {
        return sendbuf_size - RESERVED_SIZE;
    }

    /// Calculate maximum payload data size of first fragment.
    ///
    /// This one is smaller than regular fragments, because it carries the message (size) header.
    fn first_fragment_size(sendbuf_size: usize) usize {
        // Ensure optimal alignment.
        return (fragment_size(sendbuf_size) - @sizeOf(usize)) & (~@as(usize, 8) + 1);
    }

    /// Maximum data size that can be transferred over this channel in a single packet.
    ///
    /// This is the size of the main data chunk only --
    /// it's independent of any auxiliary data (FDs) transferred along with it.
    ///
    /// A send on this channel won't block for transfers up to this size
    /// under normal circumstances.
    /// (It might still block if heavy memory pressure causes ENOBUFS,
    /// forcing us to reduce the packet size.)
    pub fn getMaxFragmentSize() !usize {
        return first_fragment_size(try getCachedSystemSendbufSize());
    }

    /// - *len* is the total length of the message. Its value will be sent as a
    ///   message header before the payload data. Not to be confused with the
    ///   length of the data to send in this packet (i.e. the length of the data
    ///   buffer passed in), which in a fragmented send will be smaller than the
    ///   total message length.
    fn send_first_fragment(
        self: Sender,
        alloc: std.mem.Allocator,
        channels: []const []const Channel,
        shared_memory_regions: []const SharedMemory,
        data_buffer: []const u8,
        len: usize,
    ) !void {
        var n_fds = shared_memory_regions.len;
        for (channels) |l| {
            n_fds += l.len;
        }
        const cmsg_length = @sizeOf(std.posix.fd_t) * n_fds;
        const cmsg_space = if (cmsg_length > 0) cmsgSpace(cmsg_length) else 0;
        const cmsg_buffer = if (cmsg_length > 0) blk: {
            const cmsg_buffer: *cmsghdr = @ptrCast(try alloc.alignedAlloc(u8, .of(cmsghdr), cmsg_space));
            cmsg_buffer.* = .{
                .len = cmsgLen(cmsg_length),
                .level = std.posix.SOL.SOCKET,
                .type = @intFromEnum(SCM.RIGHTS),
            };

            var buf = @as([*]std.posix.fd_t, @ptrCast(cmsgData(cmsg_buffer)))[0..n_fds];
            for (channels) |l| {
                for (l, 0..) |chan, i| {
                    buf[i] = switch (chan) {
                        .receiver => |rc| rc.fd,
                        .sender => |sd| sd.fd,
                    };
                }
                buf = buf[l.len..];
            }
            for (shared_memory_regions, 0..) |smr, i| {
                buf[i] = smr.store.fd;
            }
            buf = buf[shared_memory_regions.len..];
            std.debug.assert(buf.len == 0);
            break :blk cmsg_buffer;
        } else null;
        defer if (cmsg_buffer) |buf| alloc.free(@as([*]align(@alignOf(cmsghdr)) u8, @ptrCast(buf))[0..cmsg_space]);

        var iovec: [2]std.posix.iovec_const = .{
            // First fragment begins with a header recording the total data length.
            //
            // The receiver uses this to determine
            // whether it already got the entire message,
            // or needs to receive additional fragments -- and if so, how much.
            .{
                .base = std.mem.asBytes(&len).ptr,
                .len = std.mem.asBytes(&len).len,
            },
            .{
                .base = data_buffer.ptr,
                .len = data_buffer.len,
            },
        };

        const msghdr: std.posix.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iovec,
            .iovlen = iovec.len,
            .control = cmsg_buffer,
            .controllen = std.math.cast(u32, cmsg_space) orelse return error.Overflow,
            .flags = 0,
        };
        while (true) {
            const rc = std.posix.system.sendmsg(self.fd, &msghdr, 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return,

                .ACCES => return error.AccessDenied,
                .AGAIN => return error.WouldBlock,
                .ALREADY => return error.FastOpenAlreadyInProgress,
                .BADF => unreachable, // always a race condition
                .CONNRESET => return error.ConnectionResetByPeer,
                .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
                .FAULT => unreachable, // An invalid user space address was specified for an argument.
                .INTR => continue,
                .INVAL => unreachable, // Invalid argument passed.
                .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
                .MSGSIZE => return error.MessageTooBig,
                // override the error from SystemResources to SendBufferTooLarge so we can distinguish between them
                .NOBUFS => return error.SendBufferTooLarge,
                .NOMEM => return error.SystemResources,
                .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
                .PIPE => return error.BrokenPipe,
                .AFNOSUPPORT => return error.AddressFamilyNotSupported,
                .LOOP => return error.SymLinkLoop,
                .NAMETOOLONG => return error.NameTooLong,
                .NOENT => return error.FileNotFound,
                .NOTDIR => return error.NotDir,
                .HOSTUNREACH => return error.NetworkUnreachable,
                .NETUNREACH => return error.NetworkUnreachable,
                .NOTCONN => return error.SocketNotConnected,
                .NETDOWN => return error.NetworkSubsystemFailed,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    }

    fn send_followup_fragment(sender_fd: std.posix.fd_t, data_buffer: []const u8) !void {
        _ = try std.posix.send(sender_fd, data_buffer, 0);
    }

    /// Reduce send buffer size after getting ENOBUFS,
    /// i.e. when the kernel failed to allocate a large enough buffer.
    ///
    /// (If the buffer already was significantly smaller
    /// than the memory page size though,
    /// if means something else must have gone wrong;
    /// so there is no point in further downsizing,
    /// and we error out instead.)
    fn downsize(sendbuf_size: *usize, sent_size: usize) bool {
        if (sent_size > 2000) {
            sendbuf_size.* /= 2;
            // Make certain we end up with less than what we tried before...
            if (sendbuf_size.* >= sent_size) {
                sendbuf_size.* = sent_size / 2;
            }
            return true;
        } else {
            return false;
        }
    }

    /// Takes ownership of the elements of `channels` and `shared_memory_regions`.
    pub fn send(
        self: Sender,
        alloc: std.mem.Allocator,
        data: []const u8,
        channels: []Channel,
        shared_memory_regions: []SharedMemory,
    ) !void {
        var sendbuf_size = try getCachedSystemSendbufSize();

        // If the message is small enough, try sending it in a single fragment.
        if (data.len <= try getMaxFragmentSize()) {
            const ok = blk: {
                self.send_first_fragment(alloc, &.{channels}, shared_memory_regions, data, data.len) catch |e| switch (e) {
                    // ENOBUFS means the kernel failed to allocate a buffer large enough
                    // to actually transfer the message,
                    // although the message was small enough to fit the maximum send size --
                    // so we have to proceed with a fragmented send nevertheless,
                    // using a reduced send buffer size.
                    //
                    // Any other errors we might get here are non-recoverable.
                    error.SendBufferTooLarge => {
                        if (!downsize(&sendbuf_size, data.len)) {
                            return e;
                        }
                        break :blk false;
                    },
                    else => return e,
                };
                break :blk true;
            };
            if (ok) return;
        }

        // The packet is too big. Fragmentation time!
        //
        // Create dedicated channel to send all but the first fragment.
        // This way we avoid fragments of different messages interleaving in the receiver.
        //
        // The receiver end of the channel is sent with the first fragment
        // along any other file descriptors that are to be transferred in the message.
        var dedicated = try channel();
        defer dedicated.sd.deinit();
        defer dedicated.rc.deinit(); // is this right?

        // Extract FD handle without consuming the Receiver, so the FD doesn't get closed.

        // Split up the packet into fragments.
        var byte_position: usize = 0;

        while (byte_position < data.len) {
            var end_byte_position: usize = undefined;
            if (byte_position == 0) {
                // First fragment. No offset; but contains message header (total size).
                // The auxiliary data (FDs) is also sent along with this one.

                // This fragment always uses the full allowable buffer size.
                end_byte_position = first_fragment_size(sendbuf_size);
                self.send_first_fragment(alloc, &.{ channels, &.{.{ .receiver = dedicated.rc }} }, shared_memory_regions, data[0..end_byte_position], data.len) catch |e| switch (e) {
                    error.SendBufferTooLarge => {
                        // If the kernel failed to allocate a buffer large enough for the packet,
                        // retry with a smaller size (if possible).
                        if (downsize(&sendbuf_size, data.len)) {
                            continue;
                        }
                        return e;
                    },
                    else => return e,
                };
            } else {
                // Followup fragment. No header; but offset by amount of data already sent.

                end_byte_position = @min(
                    byte_position + fragment_size(sendbuf_size),
                    data.len,
                );
                try send_followup_fragment(dedicated.sd.fd, data[byte_position..end_byte_position]);
            }

            byte_position = end_byte_position;
        }
    }

    pub fn connect(name: []const u8) !Sender {
        const fd = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.SEQPACKET | SOCK_FLAGS, 0);
        const sockaddr = try new_sockaddr_un(name);
        try std.posix.connect(
            fd,
            @ptrCast(&sockaddr),
            @sizeOf(@TypeOf(sockaddr)),
        );
        return .{ .fd = fd };
    }
};

pub const Channel = union(enum) {
    sender: Sender,
    receiver: Receiver,

    pub fn deinit(self: @This()) void {
        switch (self) {
            .sender => |sd| sd.deinit(),
            .receiver => |rc| rc.deinit(),
        }
    }
};

pub const ReceiverId = struct { id: std.posix.fd_t };

pub const ReceiverSet = struct {
    epoll: std.posix.fd_t,
    events: []std.posix.system.epoll_event,
    fds: std.ArrayListUnmanaged(std.posix.fd_t),

    pub fn new() !ReceiverSet {
        return .{
            .epoll = try std.posix.epoll_create1(0),
            .events = &.{},
            .fds = .empty,
        };
    }

    pub fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        for (self.fds.items) |fd| {
            std.posix.close(fd);
        }
        std.posix.close(self.epoll);

        self.fds.deinit(alloc);
        alloc.free(self.events);

        self.* = undefined;
    }

    pub fn add(self: *@This(), alloc: std.mem.Allocator, receiver: Receiver) !ReceiverId {
        const fd = receiver.fd;
        {
            errdefer {
                var slot = receiver;
                slot.deinit();
            }
            var event: std.posix.system.epoll_event = .{
                .data = .{
                    .fd = fd,
                },
                .events = std.posix.system.EPOLL.IN,
            };
            try std.posix.epoll_ctl(self.epoll, std.posix.system.EPOLL.CTL_ADD, fd, &event);
        }
        try self.fds.append(alloc, fd);
        // use an array list to manage the capacity of the events buffer
        var events = std.ArrayListUnmanaged(std.posix.system.epoll_event){
            .capacity = self.events.len,
            .items = self.events,
        };
        try events.ensureTotalCapacity(alloc, self.fds.items.len);
        self.events = events.items;
        self.events.len = events.capacity;
        return .{ .id = fd };
    }

    pub fn select(self: *@This(), alloc: std.mem.Allocator) !SelectionResult {
        // Poll until we receive at least one event.
        const n = std.posix.epoll_wait(self.epoll, self.events, -1);

        for (self.events[0..n]) |event| {
            // We only register this `Poll` for readable events.
            std.debug.assert((event.events & std.posix.system.EPOLL.IN) != 0);

            while (true) {
                const rx: Receiver = .{ .fd = event.data.fd };
                const msg = rx.recvOptions(alloc, .nonblocking) catch |e| switch (e) {
                    error.ChannelClosed => {
                        try std.posix.epoll_ctl(self.epoll, std.posix.system.EPOLL.CTL_DEL, rx.fd, null);
                        // Unwrap here is fine. Kernel shouldn't give us an event for an fd we don't know about.
                        _ = self.fds.swapRemove(std.mem.indexOfScalar(std.posix.fd_t, self.fds.items, rx.fd).?);
                        std.posix.close(rx.fd);
                        return .{
                            .id = .{ .id = rx.fd },
                            .event = .closed,
                        };
                    },
                    error.Empty => {
                        // We tried to read another message from the file descriptor and
                        // it would have blocked, so we have exhausted all of the data
                        // pending to read.
                        break;
                    },
                    else => return e,
                };
                return .{
                    .id = .{ .id = rx.fd },
                    .event = .{ .received = msg },
                };
            }
        }

        return error.Empty;
    }

    pub fn selectMany(self: *@This(), alloc: std.mem.Allocator) ![]SelectionResult {
        var selection_results: std.ArrayListUnmanaged(SelectionResult) = .empty;
        errdefer selection_results.deinit(alloc);

        // Poll until we receive at least one event.
        const n = std.posix.epoll_wait(self.epoll, self.events, -1);

        for (self.events[0..n]) |event| {
            // We only register this `Poll` for readable events.
            std.debug.assert((event.events & std.posix.system.EPOLL.IN) != 0);

            while (true) {
                const rx: Receiver = .{ .fd = event.data.fd };
                const msg = rx.recvOptions(alloc, .nonblocking) catch |e| switch (e) {
                    error.ChannelClosed => {
                        try std.posix.epoll_ctl(self.epoll, std.posix.system.EPOLL.CTL_DEL, rx.fd, null);
                        // Unwrap here is fine. Kernel shouldn't give us an event for an fd we don't know about.
                        _ = self.fds.swapRemove(std.mem.indexOfScalar(std.posix.fd_t, self.fds.items, rx.fd).?);
                        std.posix.close(rx.fd);
                        try selection_results.append(alloc, .{
                            .id = .{ .id = rx.fd },
                            .event = .closed,
                        });
                        break;
                    },
                    error.Empty => {
                        // We tried to read another message from the file descriptor and
                        // it would have blocked, so we have exhausted all of the data
                        // pending to read.
                        break;
                    },
                    else => return e,
                };
                try selection_results.append(alloc, .{
                    .id = .{ .id = rx.fd },
                    .event = .{ .received = msg },
                });
            }
        }

        return selection_results.toOwnedSlice(alloc);
    }
};

pub const OpaqueChannel = struct {
    fd: std.posix.fd_t,

    pub fn deinit(self: @This()) void {
        std.posix.close(self.fd);
    }

    pub fn asSender(self: OpaqueChannel) error{WrongType}!Sender {
        return .{ .fd = self.fd };
    }

    pub fn asReceiver(self: OpaqueChannel) error{WrongType}!Receiver {
        return .{ .fd = self.fd };
    }
};

pub const OneShotServer = struct {
    sock: std.posix.socket_t,
    name: NameBuf,

    const NameBuf = struct {
        buf: std.posix.sockaddr.un,
        len: usize,

        pub const init: @This() = .{ .buf = .{ .path = undefined }, .len = 0 };

        pub fn span(self: *const @This()) [:0]const u8 {
            return self.buf.path[0..self.len :0];
        }
    };

    pub fn new() !OneShotServer {
        const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.SEQPACKET | SOCK_FLAGS, 0);
        errdefer std.posix.close(sock);

        const rand_len = 6;

        const temp_dir = std.posix.getenv("TMPDIR") orelse switch (builtin.target.abi) {
            .android, .androideabi => "/data/local/tmp",
            else => "/tmp",
        };
        var name: NameBuf = .init;
        if (temp_dir.len > name.buf.path.len - 1 - rand_len) {
            return error.NameTooLong;
        }
        @memcpy(name.buf.path[0..temp_dir.len], temp_dir);
        name.buf.path[temp_dir.len] = '/';

        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        var rng = std.Random.DefaultPrng.init(seed);

        const max_attempts = std.math.maxInt(u16);

        for (0..max_attempts) |_| {
            for (0..rand_len) |i| {
                const dict = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                name.buf.path[temp_dir.len + 1 + i] = dict[rng.random().uintAtMost(u8, dict.len)];
            }
            name.len = temp_dir.len + 1 + rand_len;
            name.buf.path[name.len] = 0;
            std.posix.bind(sock, @ptrCast(&name.buf), @sizeOf(@TypeOf(name.buf))) catch |e| switch (e) {
                // try again with different random characters
                error.AddressInUse => continue,
                error.AccessDenied => {
                    std.debug.print("Unable to bind to socket {}\n", .{std.zig.fmtEscapes(name.span())});
                    return e;
                },
                else => return e,
            };

            try std.posix.listen(sock, 10);

            return .{ .sock = sock, .name = name };
        }

        return error.SocketPathsExhausted;
    }

    pub fn deinit(self: @This()) void {
        std.posix.close(self.sock);
    }

    pub fn accept(self: @This(), alloc: std.mem.Allocator) !struct { rc: Receiver, msg: IpcMessage } {
        const client_fd = try std.posix.accept(self.sock, null, null, 0);
        try makeSocketLingering(client_fd);

        const receiver: Receiver = .{ .fd = client_fd };
        const ipc_message = try receiver.recv(alloc);
        return .{ .rc = receiver, .msg = ipc_message };
    }
};

/// Make sure that the kernel doesn't return errors to readers if there's still data left after we
/// close our end.
///
/// See, for example, https://github.com/servo/ipc-channel/issues/29
fn makeSocketLingering(sockfd: c_int) !void {
    const linger = extern struct {
        /// linger active
        l_onoff: c_int,
        ///how many seconds to linger for
        l_linger: c_int,
    };
    const linger_data: linger = .{
        .l_onoff = 1,
        .l_linger = 30,
    };
    // Zig's handling of EINVAL is incorrect here...
    switch (std.posix.errno(std.posix.system.setsockopt(
        sockfd,
        std.posix.SOL.SOCKET,
        std.posix.SO.LINGER,
        std.mem.asBytes(&linger_data),
        @sizeOf(@TypeOf(linger_data)),
    ))) {
        .SUCCESS => {},
        .BADF => unreachable, // always a race condition
        .NOTSOCK => unreachable, // always a race condition
        .INVAL => {
            // If the other side of the connection is already closed, POSIX.1-2024 (and earlier
            // versions) require that setsockopt return EINVAL [1]. This is a bit unfortunate
            // because SO_LINGER for a closed socket is logically a no-op, which is why some OSes
            // like Linux don't follow this part of the spec. But other OSes like illumos do return
            // EINVAL here.
            //
            // SO_LINGER is widely understood and EINVAL should not occur for any other reason, so
            // accept those errors.
            //
            // Another option would be to call make_socket_lingering on the initial socket created
            // by libc::socket, but whether accept inherits a particular option is
            // implementation-defined [2]. This means that special-casing EINVAL is the most
            // portable thing to do.
            //
            // [1] https://pubs.opengroup.org/onlinepubs/9799919799/functions/setsockopt.html:
            //     "[EINVAL] The specified option is invalid at the specified socket level or the
            //     socket has been shut down."
            //
            // [2] https://pubs.opengroup.org/onlinepubs/9799919799/functions/accept.html: "It is
            //     implementation-defined which socket options, if any, on the accepted socket will
            //     have a default value determined by a value previously customized by setsockopt()
            //     on socket, rather than the default value used for other new sockets."
        },
        .FAULT => unreachable,
        .DOM => return error.TimeoutTooBig,
        .ISCONN => return error.AlreadyConnected,
        .NOPROTOOPT => return error.InvalidProtocolOption,
        .NOMEM => return error.SystemResources,
        .NOBUFS => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        .NODEV => return error.NoDevice,
        .OPNOTSUPP => return error.OperationNotSupported,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub const SharedMemory = struct {
    data: []align(std.heap.page_size_min) u8,
    store: BackingStore,

    pub const BackingStore = struct {
        fd: std.posix.fd_t,

        const name_fmt = "/ipc-channel-shared-memory.{}.{}.{}.{}";
        const max_name_len = std.fmt.count(name_fmt, .{ std.math.maxInt(usize), std.math.maxInt(std.posix.pid_t), std.math.maxInt(u128) / std.time.ns_per_s, std.time.ns_per_s - 1 });

        pub fn new(length: usize) !BackingStore {
            const count = shm_count.fetchAdd(1, .monotonic);
            const timestamp = std.math.cast(u128, std.time.nanoTimestamp()) orelse return error.ClockRanBackwards;
            var name_buf: [max_name_len + 1]u8 = undefined;
            const name = std.fmt.bufPrintZ(&name_buf, name_fmt, .{ count, getPid(), timestamp / std.time.ns_per_s, timestamp % std.time.ns_per_s }) catch unreachable;
            const fd = try std.posix.memfd_createZ(name, std.posix.MFD.CLOEXEC);
            try std.posix.ftruncate(fd, length);
            return .{ .fd = fd };
        }

        pub fn deinit(self: @This()) void {
            std.posix.close(self.fd);
        }

        pub fn getLength(self: @This()) !usize {
            return std.math.cast(usize, (try std.posix.fstat(self.fd)).size) orelse return error.Overflow;
        }

        /// If you do not know the length, call `getLength()` to determine it.
        pub fn mapFile(self: @This(), length: usize) ![]align(std.heap.page_size_min) u8 {
            if (length == 0) {
                // This will cause `mmap` to fail, so handle it explicitly.
                return &.{};
            }
            return std.posix.mmap(
                null,
                length,
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                .{ .TYPE = .SHARED },
                self.fd,
                0,
            );
        }
    };

    fn fromFd(fd: std.posix.fd_t) !SharedMemory {
        const store: BackingStore = .{ .fd = fd };
        return .{ .data = try store.mapFile(try store.getLength()), .store = store };
    }

    pub fn fromByte(byte: u8, length: usize) !SharedMemory {
        const store: BackingStore = try .new(length);
        const data = try store.mapFile(length);
        @memset(data, byte);
        return .{ .data = data, .store = store };
    }

    pub fn fromBytes(bytes: []u8) !SharedMemory {
        const store: BackingStore = try .new(bytes.len);
        const data = try store.mapFile(bytes.len);
        @memcpy(data, bytes);
        return .{ .data = data, .store = store };
    }

    pub fn deinit(self: @This()) void {
        self.store.deinit();
        std.posix.munmap(self.data);
    }

    pub fn clone(self: @This()) !SharedMemory {
        const store: BackingStore = .{ .fd = try std.posix.dup(self.store.fd) };
        return .{ .data = try store.mapFile(self.data.len), .store = store };
    }
};

// #[derive(Debug)]
// pub enum UnixError {
//     Empty,
//     ChannelClosed,
//     Io(io::Error),
// }

// impl UnixError {
//     fn last() -> UnixError {
//         UnixError::Io(io::Error::last_os_error())
//     }

//     #[allow(dead_code)]
//     pub fn channel_is_closed(&self) -> bool {
//         matches!(self, UnixError::ChannelClosed)
//     }
// }

// impl fmt::Display for UnixError {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             Self::Empty => write!(fmt, "The socket is empty"),
//             Self::ChannelClosed => write!(fmt, "All senders for this socket closed"),
//             Self::Io(e) => write!(fmt, "{e}"),
//         }
//     }
// }

// impl StdError for UnixError {}

// impl From<UnixError> for io::Error {
//     fn from(unix_error: UnixError) -> io::Error {
//         match unix_error {
//             UnixError::Empty => io::Error::new(io::ErrorKind::WouldBlock, unix_error),
//             UnixError::ChannelClosed => io::Error::new(io::ErrorKind::ConnectionReset, unix_error),
//             UnixError::Io(e) => e,
//         }
//     }
// }

// impl From<io::Error> for UnixError {
//     fn from(e: io::Error) -> UnixError {
//         if e.kind() == io::ErrorKind::ConnectionReset {
//             Self::ChannelClosed
//         } else if e.kind() == io::ErrorKind::WouldBlock
//             || matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::EWOULDBLOCK))
//         {
//             // TODO: remove the second half of that condition if possible
//             Self::Empty
//         } else {
//             Self::Io(e)
//         }
//     }
// }

pub const cmsghdr = switch (builtin.os.tag) {
    .linux => extern struct {
        len: usize,
        level: i32,
        type: i32,
    },
    .solaris => std.c.cmsghdr,
    else => |os_tag| @compileError("Unsupported OS: " ++ @tagName(os_tag)),
};

fn cmsgAlign(len: usize) usize {
    return std.mem.alignForward(usize, len, @alignOf(usize));
}

fn cmsgSpace(length: usize) usize {
    return cmsgAlign(length) + cmsgAlign(@sizeOf(cmsghdr));
}

fn cmsgLen(length: usize) usize {
    return cmsgAlign(@sizeOf(cmsghdr)) + length;
}

fn cmsgData(cmsg: *cmsghdr) [*]align(@alignOf(cmsghdr)) u8 {
    return @ptrCast(@as([*]cmsghdr, @ptrCast(cmsg)) + 1);
}

const UnixCmsg = struct {
    cmsg_buffer: [cmsgSpace(MAX_FDS_IN_CMSG * @sizeOf(std.posix.fd_t))]u8 align(@alignOf(cmsghdr)),
    msghdr: std.posix.msghdr,

    pub fn init(self: *@This(), iovec: *[2]std.posix.iovec) !void {
        self.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = iovec.ptr,
            .iovlen = iovec.len,
            .control = &self.cmsg_buffer,
            .controllen = self.cmsg_buffer.len,
            .flags = 0,
        };
    }

    pub fn cmsgBuffer(self: *@This()) *cmsghdr {
        return @ptrCast(&self.cmsg_buffer);
    }

    fn recv(self: *@This(), fd: std.posix.fd_t, blocking_mode: BlockingMode) !usize {
        switch (blocking_mode) {
            .blocking => {},
            .nonblocking => {
                _ = try std.posix.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
            },
            .timeout => |duration| {
                // missing from Zig's POLL definition
                const POLLRDHUP = 0x2000;
                const events = std.posix.POLL.IN | std.posix.POLL.PRI | POLLRDHUP;
                var fds: [1]std.posix.pollfd = .{.{
                    .fd = fd,
                    .events = events,
                    .revents = 0,
                }};
                const result = try std.posix.poll(
                    &fds,
                    std.math.cast(i32, duration) orelse return error.Overflow,
                );
                if (result == 0) {
                    return error.Empty;
                }
            },
        }
        defer if (blocking_mode == .nonblocking) {
            _ = std.posix.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))) catch {
                // TODO: log a warning
            };
        };

        const rc = std.os.linux.recvmsg(fd, &self.msghdr, RECVMSG_FLAGS);
        return switch (std.posix.errno(rc)) {
            .SUCCESS => if (rc == 0) error.ChannelClosed else rc,
            .AGAIN => error.Empty,
            .BADF => unreachable, // Always a race condition.
            .CONNREFUSED => error.ConnectionRefused,
            .FAULT => unreachable, // Bad buffer pointers. Impossible.
            .INTR => error.Interrupted,
            .INVAL => unreachable,
            .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            else => |e| std.posix.unexpectedErrno(e),
        };
    }

    fn cmsgLen(self: *const @This()) usize {
        return @as(*const cmsghdr, @alignCast(@ptrCast(self.msghdr.control))).len;
    }
};

fn isSocket(fd: c_int) bool {
    const st = std.posix.fstat(fd) catch return false;
    return (st.mode & std.posix.S.IFMT) == std.posix.S.IFSOCK;
}
