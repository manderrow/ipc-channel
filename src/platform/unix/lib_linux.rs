#![allow(non_camel_case_types)]

use std::ffi::{CStr, c_int, c_uchar, c_uint, c_void};
use std::io;
use std::mem::{self, MaybeUninit};
use std::ptr::NonNull;

#[cfg(not(target_os = "windows"))]
pub use std::os::fd::RawFd as fd_t;
#[cfg(target_os = "windows")]
pub type fd_t = std::ffi::c_int;

fn check_error(rc: usize) -> Result<(), io::Error> {
    let signed: isize = rc as isize;
    let int = if signed > -4096 && signed < 0 {
        -signed as i32
    } else {
        0
    };
    if int == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(int))
    }
}

pub type size_t = usize;
pub type ssize_t = isize;

pub type mode_t = u32;
pub type nfds_t = usize;
pub type sa_family_t = u16;
pub type socklen_t = u32;
pub type pid_t = i32;

pub const EPOLLIN: u32 = 0x1;

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;

pub const MAP_FAILED: *mut u8 = !0 as *mut u8;
pub const MAP_SHARED: u32 = 0x0001;

pub const PROT_READ: usize = 1;
pub const PROT_WRITE: usize = 2;

pub const O_NONBLOCK: u32 = 0x800;
pub const O_CLOEXEC: u32 = 0x80000;

pub const MSG_CMSG_CLOEXEC: u32 = 0x40000000;

pub const SOCK_CLOEXEC: u32 = O_CLOEXEC;
pub const SOCK_SEQPACKET: u32 = 5;

pub const SOL_SOCKET: i32 = 1;

pub const AF_UNIX: u32 = 1;

pub const MFD_CLOEXEC: u32 = 0x0001;

pub const S_IFMT: mode_t = 0o17_0000;
pub const S_IFSOCK: mode_t = 0o14_0000;

pub const SO_SNDBUF: u32 = 7;
pub const SO_LINGER: u32 = 13;

pub const SCM_RIGHTS: i32 = 0x01;

pub const F_SETFL: i32 = 4;

pub const POLLIN: i16 = 0x1;
pub const POLLPRI: i16 = 0x2;
pub const POLLRDHUP: i16 = 0x2000;

pub const EAGAIN: i32 = 11;
pub const ENOBUFS: i32 = 105;

#[repr(C, packed(4))]
pub struct epoll_event {
    pub events: u32,
    pub data: u64,
}

#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [u8; 14],
}

#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [u8; 108],
}

pub const fn CMSG_ALIGN(len: usize) -> usize {
    len + mem::size_of::<usize>() - 1 & !(mem::size_of::<usize>() - 1)
}

pub unsafe fn CMSG_DATA(cmsg: *const cmsghdr) -> *mut c_uchar {
    unsafe { cmsg.offset(1) as *mut c_uchar }
}

pub const fn CMSG_SPACE(length: usize) -> usize {
    CMSG_ALIGN(length) + CMSG_ALIGN(mem::size_of::<cmsghdr>())
}

pub const fn CMSG_LEN(length: usize) -> usize {
    CMSG_ALIGN(mem::size_of::<cmsghdr>()) + length
}

#[repr(C)]
pub struct cmsghdr {
    pub len: usize,
    pub level: c_int,
    pub r#type: c_int,
}

#[repr(C)]
pub struct iovec {
    pub base: NonNull<u8>,
    pub len: usize,
}

#[repr(C)]
pub struct linger {
    pub l_onoff: c_int,
    pub l_linger: c_int,
}

#[repr(C)]
pub struct msghdr {
    pub name: *mut c_void,
    pub namelen: socklen_t,
    pub iov: *mut iovec,
    pub iovlen: usize,
    pub control: *mut c_void,
    pub controllen: usize,
    pub flags: i32,
}

#[repr(C)]
pub struct pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

pub type dev_t = u64;
pub type ino_t = u64;
pub type nlink_t = u64;
pub type uid_t = u32;
pub type gid_t = u32;
pub type off_t = i64;
pub type blksize_t = i64;
pub type blkcnt_t = i64;
pub type time_t = i64;

#[repr(C)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: nlink_t,
    pub st_mode: mode_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    __pad0: c_int,
    pub st_rdev: dev_t,
    pub st_size: off_t,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,
    pub st_atime: time_t,
    pub st_atime_nsec: i64,
    pub st_mtime: time_t,
    pub st_mtime_nsec: i64,
    pub st_ctime: time_t,
    pub st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[link(name = "linux", kind = "static")]
unsafe extern "C" {
    pub fn linux_syscall_epoll_create1(flags: u32) -> usize;
    pub fn linux_syscall_epoll_wait(
        epfd: fd_t,
        events: NonNull<MaybeUninit<epoll_event>>,
        maxevents: u32,
        timeout: i32,
    ) -> usize;
    pub fn linux_syscall_epoll_ctl(
        epfd: fd_t,
        op: u32,
        fd: fd_t,
        event: Option<NonNull<epoll_event>>,
    ) -> usize;

    pub fn linux_syscall_mmap(
        addr: Option<NonNull<u8>>,
        len: usize,
        prot: usize,
        flags: u32,
        fd: fd_t,
        offset: i64,
    ) -> usize;
    pub fn linux_syscall_munmap(addr: NonNull<u8>, len: usize) -> usize;

    pub fn linux_syscall_memfd_create(name: *const u8, flags: u32) -> usize;

    pub fn linux_syscall_send(socket: fd_t, buf: *const u8, len: usize, flags: u32) -> usize;
    pub fn linux_syscall_recv(socket: fd_t, buf: *mut u8, len: usize, flags: u32) -> usize;

    pub fn linux_syscall_sendmsg(fd: fd_t, msg: *const msghdr, flags: u32) -> usize;
    pub fn linux_syscall_recvmsg(fd: fd_t, msg: &mut MaybeUninit<msghdr>, flags: u32) -> usize;

    pub fn linux_syscall_socketpair(
        domain: u32,
        type_: u32,
        protocol: u32,
        socket_vector: &mut [fd_t; 2],
    ) -> usize;

    pub fn linux_syscall_ftruncate(fd: fd_t, length: i64) -> usize;

    pub fn linux_syscall_fcntl(fd: fd_t, cmd: i32, arg: usize) -> usize;

    pub fn linux_syscall_poll(fds: NonNull<pollfd>, nfds: nfds_t, timeout: i32) -> usize;

    // these one override windows definitions
    pub fn linux_syscall_accept(
        socket: fd_t,
        address: Option<NonNull<sockaddr>>,
        address_len: Option<NonNull<socklen_t>>,
    ) -> usize;

    pub fn linux_syscall_bind(
        socket: fd_t,
        address: *const sockaddr,
        address_len: socklen_t,
    ) -> usize;

    pub fn linux_syscall_connect(socket: fd_t, address: *const sockaddr, len: socklen_t) -> usize;

    pub fn linux_syscall_getsockopt(
        sockfd: fd_t,
        level: i32,
        optname: u32,
        optval: *mut u8,
        optlen: &mut socklen_t,
    ) -> usize;
    pub fn linux_syscall_setsockopt(
        socket: fd_t,
        level: i32,
        optname: u32,
        optval: *const u8,
        optlen: socklen_t,
    ) -> usize;

    pub fn linux_syscall_listen(socket: fd_t, backlog: u32) -> usize;

    pub fn linux_syscall_socket(domain: u32, ty: u32, protocol: u32) -> usize;

    pub fn linux_syscall_fstat(fd: fd_t, buf: &mut MaybeUninit<stat>) -> usize;

    pub fn linux_syscall_close(fd: fd_t) -> usize;

    pub fn linux_syscall_dup(fd: fd_t) -> usize;

    pub fn linux_syscall_getpid() -> pid_t;

    /// `path` must be non-null.
    pub fn linux_syscall_unlink(path: *const u8) -> usize;

    pub fn linux_helper_temp_dir(buf: iovec) -> usize;
}

#[track_caller]
fn validate_fd(rc: usize, name: &str) -> fd_t {
    match rc.try_into() {
        Ok(fd) => fd,
        Err(_) => panic!(
            "at {}, {} should return a valid fd: {}",
            std::panic::Location::caller(),
            name,
            rc
        ),
    }
}

#[track_caller]
pub fn epoll_create1(flags: u32) -> Result<fd_t, io::Error> {
    let rc = unsafe { linux_syscall_epoll_create1(flags) };
    check_error(rc)?;
    Ok(validate_fd(rc, "epoll_create1"))
}
pub fn epoll_wait(
    epfd: fd_t,
    events: &mut [MaybeUninit<epoll_event>],
    timeout: i32,
) -> Result<usize, io::Error> {
    let len = events.len().try_into().map_err(io::Error::other)?;
    let rc = unsafe { linux_syscall_epoll_wait(epfd, NonNull::from(events).cast(), len, timeout) };
    check_error(rc)?;
    Ok(rc)
}
pub fn epoll_ctl(
    epfd: fd_t,
    op: u32,
    fd: fd_t,
    event: Option<&mut epoll_event>,
) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_epoll_ctl(epfd, op, fd, event.map(NonNull::from)) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub unsafe fn mmap(
    addr: Option<NonNull<u8>>,
    len: usize,
    prot: usize,
    flags: u32,
    fd: fd_t,
    offset: i64,
) -> Result<NonNull<u8>, io::Error> {
    let rc = unsafe { linux_syscall_mmap(addr, len, prot, flags, fd, offset) };
    check_error(rc)?;
    Ok(NonNull::new(rc as *mut u8).unwrap())
}
pub unsafe fn munmap(addr: NonNull<u8>, len: usize) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_munmap(addr, len) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

#[track_caller]
pub fn memfd_create(name: &CStr, flags: u32) -> Result<fd_t, io::Error> {
    let rc = unsafe { linux_syscall_memfd_create(name.as_ptr() as *const u8, flags) };
    check_error(rc)?;
    Ok(validate_fd(rc, "memfd_create"))
}

pub fn send(socket: fd_t, buf: &[u8], flags: u32) -> Result<usize, io::Error> {
    let rc = unsafe { linux_syscall_send(socket, buf.as_ptr(), buf.len(), flags) };
    check_error(rc)?;
    Ok(rc)
}
pub fn recv(socket: fd_t, buf: &mut [MaybeUninit<u8>], flags: u32) -> Result<usize, io::Error> {
    let rc = unsafe { linux_syscall_recv(socket, buf.as_mut_ptr().cast(), buf.len(), flags) };
    check_error(rc)?;
    Ok(rc)
}

pub fn sendmsg(fd: fd_t, msg: &msghdr, flags: u32) -> Result<usize, io::Error> {
    let rc = unsafe { linux_syscall_sendmsg(fd, msg, flags) };
    check_error(rc)?;
    Ok(rc)
}
pub fn recvmsg(fd: fd_t, msg: &mut MaybeUninit<msghdr>, flags: u32) -> Result<usize, io::Error> {
    let rc = unsafe { linux_syscall_recvmsg(fd, msg, flags) };
    check_error(rc)?;
    Ok(rc)
}

pub fn socketpair(domain: u32, type_: u32, protocol: u32) -> Result<[fd_t; 2], io::Error> {
    let mut out: [fd_t; 2] = [0; 2];
    let rc = unsafe { linux_syscall_socketpair(domain, type_, protocol, &mut out) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(out)
}

pub fn ftruncate(fd: fd_t, length: i64) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_ftruncate(fd, length) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn fcntl(fd: fd_t, cmd: i32, arg: usize) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_fcntl(fd, cmd, arg) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn poll(fds: &mut [pollfd], timeout: i32) -> Result<usize, io::Error> {
    let rc = unsafe { linux_syscall_poll(NonNull::from(&mut *fds).cast(), fds.len(), timeout) };
    check_error(rc)?;
    Ok(rc)
}

#[track_caller]
pub unsafe fn accept(
    socket: fd_t,
    address: Option<NonNull<sockaddr>>,
    address_len: Option<NonNull<socklen_t>>,
) -> Result<fd_t, io::Error> {
    let rc = unsafe { linux_syscall_accept(socket, address, address_len) };
    check_error(rc)?;
    Ok(validate_fd(rc, "accept"))
}

pub unsafe fn bind(
    socket: fd_t,
    address: *const sockaddr,
    address_len: socklen_t,
) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_bind(socket, address, address_len) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub unsafe fn connect(
    socket: fd_t,
    address: *const sockaddr,
    len: socklen_t,
) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_connect(socket, address, len) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn getsockopt(
    sockfd: fd_t,
    level: i32,
    optname: u32,
    optval: &mut [u8],
) -> Result<u32, io::Error> {
    let mut len_out = optval.len().try_into().map_err(io::Error::other)?;
    let rc = unsafe {
        linux_syscall_getsockopt(sockfd, level, optname, optval.as_mut_ptr(), &mut len_out)
    };
    check_error(rc)?;
    Ok(len_out)
}

pub fn setsockopt(socket: fd_t, level: i32, optname: u32, optval: &[u8]) -> Result<(), io::Error> {
    let rc = unsafe {
        linux_syscall_setsockopt(
            socket,
            level,
            optname,
            optval.as_ptr(),
            optval.len().try_into().map_err(io::Error::other)?,
        )
    };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn listen(socket: fd_t, backlog: u32) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_listen(socket, backlog) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

#[track_caller]
pub fn socket(domain: u32, ty: u32, protocol: u32) -> Result<fd_t, io::Error> {
    let rc = unsafe { linux_syscall_socket(domain, ty, protocol) };
    check_error(rc)?;
    Ok(validate_fd(rc, "socket"))
}

pub fn fstat(fd: fd_t, buf: &mut MaybeUninit<stat>) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_fstat(fd, buf) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn close(fd: fd_t) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_close(fd) };
    check_error(rc)?;
    assert_eq!(rc, 0);
    Ok(())
}

#[track_caller]
pub fn dup(fd: fd_t) -> Result<fd_t, io::Error> {
    let rc = unsafe { linux_syscall_dup(fd) };
    check_error(rc)?;
    Ok(validate_fd(rc, "dup"))
}

pub fn unlink(path: &CStr) -> Result<(), io::Error> {
    let rc = unsafe { linux_syscall_unlink(path.as_ptr().cast::<u8>()) };
    check_error(rc)?;
    Ok(())
}

pub fn getpid() -> pid_t {
    unsafe { linux_syscall_getpid() }
}

pub fn temp_dir() -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(4096);
    let rc = unsafe {
        linux_helper_temp_dir(iovec {
            base: NonNull::from(buf.spare_capacity_mut()).cast(),
            len: buf.capacity(),
        })
    };
    check_error(rc)?;
    unsafe { buf.set_len(rc) };
    Ok(buf)
}
