const builtin = @import("builtin");
const std = @import("std");

//const signed: isize = @bitCast(rc);
//const int = if (signed > -4096 and signed < 0) -signed else 0;

pub export fn linux_syscall_epoll_create1(flags: u32) usize {
    return std.os.linux.epoll_create1(flags);
}
pub export fn linux_syscall_epoll_wait(
    epfd: std.os.linux.fd_t,
    events: [*]std.os.linux.epoll_event,
    maxevents: u32,
    timeout: i32,
) usize {
    return std.os.linux.epoll_wait(epfd, events, maxevents, timeout);
}
pub export fn linux_syscall_epoll_ctl(epfd: std.os.linux.fd_t, op: u32, fd: std.os.linux.fd_t, event: *std.os.linux.epoll_event) usize {
    return std.os.linux.epoll_ctl(epfd, op, fd, event);
}

pub export fn linux_syscall_mmap(
    addr: ?[*]u8,
    len: usize,
    prot: usize,
    flags: std.os.linux.MAP,
    fd: std.os.linux.fd_t,
    offset: i64,
) usize {
    return std.os.linux.mmap(addr, len, prot, flags, fd, offset);
}
pub export fn linux_syscall_munmap(addr: [*]const u8, len: usize) usize {
    return std.os.linux.munmap(addr, len);
}

pub export fn linux_syscall_memfd_create(name: [*:0]const u8, flags: u32) usize {
    return std.os.linux.memfd_create(name, flags);
}

pub export fn linux_syscall_send(socket: std.os.linux.socket_t, buf: [*]const u8, len: usize, flags: u32) usize {
    return std.os.linux.sendto(socket, buf, len, flags, null, 0);
}
pub export fn linux_syscall_recv(socket: std.os.linux.socket_t, buf: [*]u8, len: usize, flags: u32) usize {
    return std.os.linux.recvfrom(socket, buf, len, flags, null, null);
}

pub export fn linux_syscall_sendmsg(fd: std.os.linux.fd_t, msg: *const std.os.linux.msghdr_const, flags: u32) usize {
    return std.os.linux.sendmsg(fd, msg, flags);
}
pub export fn linux_syscall_recvmsg(fd: std.os.linux.fd_t, msg: *std.os.linux.msghdr, flags: u32) usize {
    return std.os.linux.recvmsg(fd, msg, flags);
}

pub export fn linux_syscall_socketpair(
    domain: u32,
    type_: u32,
    protocol: u32,
    socket_vector: *[2]std.os.linux.socket_t,
) usize {
    return std.os.linux.socketpair(@bitCast(domain), @bitCast(type_), @bitCast(protocol), socket_vector);
}

pub export fn linux_syscall_ftruncate(fd: std.os.linux.fd_t, length: std.os.linux.off_t) usize {
    return std.os.linux.ftruncate(fd, length);
}

pub export fn linux_syscall_fcntl(fd: std.os.linux.fd_t, cmd: i32, arg: usize) usize {
    return std.os.linux.fcntl(fd, cmd, arg);
}

pub export fn linux_syscall_poll(fds: [*]std.os.linux.pollfd, nfds: std.os.linux.nfds_t, timeout: i32) usize {
    return std.os.linux.poll(fds, nfds, timeout);
}

// these one override windows definitions
pub export fn linux_syscall_accept(socket: std.os.linux.socket_t, noalias address: ?*std.os.linux.sockaddr, noalias address_len: ?*std.os.linux.socklen_t) usize {
    return std.os.linux.accept(socket, address, address_len);
}

pub export fn linux_syscall_bind(socket: std.os.linux.socket_t, address: *const std.os.linux.sockaddr, address_len: std.os.linux.socklen_t) usize {
    return std.os.linux.bind(socket, address, address_len);
}

pub export fn linux_syscall_connect(socket: std.os.linux.socket_t, address: *const std.os.linux.sockaddr, len: std.os.linux.socklen_t) usize {
    return std.os.linux.connect(socket, address, len);
}

pub export fn linux_syscall_getsockopt(
    sockfd: std.os.linux.socket_t,
    level: i32,
    optname: u32,
    noalias optval: [*]u8,
    noalias optlen: *std.os.linux.socklen_t,
) usize {
    return std.os.linux.getsockopt(sockfd, level, optname, optval, optlen);
}
pub export fn linux_syscall_setsockopt(
    socket: std.os.linux.socket_t,
    level: i32,
    optname: u32,
    optval: [*]const u8,
    optlen: std.os.linux.socklen_t,
) usize {
    return std.os.linux.setsockopt(socket, level, optname, optval, optlen);
}

pub export fn linux_syscall_listen(socket: std.os.linux.socket_t, backlog: u32) usize {
    return std.os.linux.listen(socket, backlog);
}

pub export fn linux_syscall_socket(domain: u32, ty: u32, protocol: u32) usize {
    return std.os.linux.socket(domain, ty, protocol);
}

pub export fn linux_syscall_fstat(fd: std.os.linux.fd_t, buf: *std.os.linux.Stat) usize {
    return std.os.linux.fstat(fd, buf);
}

pub export fn linux_syscall_close(fd: std.os.linux.fd_t) usize {
    return std.os.linux.close(fd);
}

pub export fn linux_syscall_dup(fd: std.os.linux.fd_t) usize {
    return std.os.linux.dup(fd);
}

pub export fn linux_syscall_unlink(path: [*:0]const u8) usize {
    return std.os.linux.unlink(path);
}

pub export fn linux_syscall_getpid() std.os.linux.pid_t {
    return std.os.linux.getpid();
}

fn errToRc(e: std.os.linux.E) usize {
    return @bitCast(@as(isize, -@as(i32, @intFromEnum(e))));
}

/// On success, returns the length. On failure, returns an error using the same encoding as syscalls.
pub export fn linux_helper_temp_dir(buf_vec: std.posix.iovec) usize {
    const buf = buf_vec.base[0..buf_vec.len];
    switch (builtin.os.tag) {
        .windows => {
            if (std.process.getenvW(std.unicode.utf8ToUtf16LeStringLiteral("TMPDIR"))) |path| {
                const len = std.unicode.calcWtf8Len(path);
                if (len > buf.len) {
                    return errToRc(.NAMETOOLONG);
                }
                return std.unicode.wtf16LeToWtf8(buf[0..len], path);
            }
        },
        else => {
            if (std.posix.getenv("TMPDIR")) |path| {
                if (path.len > buf.len) {
                    return errToRc(.NAMETOOLONG);
                }
                @memcpy(buf[0..path.len], path);
                return path.len;
            }
        },
    }
    const path = if (builtin.abi.isAndroid()) "/data/local/tmp" else "/tmp";
    if (path.len > buf.len) {
        return errToRc(.NAMETOOLONG);
    }
    @memcpy(buf[0..path.len], path);
    return path.len;
}
