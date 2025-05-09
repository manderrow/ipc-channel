// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::Cell;
use std::cmp;
use std::convert::TryInto;
use std::error::Error as StdError;
use std::ffi::{CString, OsStr};
use std::ffi::{c_int, c_void};
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::ops::Deref;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, UNIX_EPOCH};

use rand::Rng;

use crate::ipc::IpcMessage;

// FIXME: need to use libc on non-Linux or unix-on-wine platforms
mod lib_linux;
use lib_linux::{self as libc, cmsghdr, fd_t, iovec, msghdr, sockaddr, sockaddr_un};

const MAX_FDS_IN_CMSG: usize = 64;

// The value Linux returns for SO_SNDBUF
// is not the size we are actually allowed to use...
// Empirically, we have to deduct 32 bytes from that.
const RESERVED_SIZE: usize = 32;

#[cfg(any(
    target_os = "linux",
    target_os = "illumos",
    all(target_os = "windows", feature = "unix-on-wine")
))]
const SOCK_FLAGS: u32 = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
#[cfg(not(any(
    target_os = "linux",
    target_os = "illumos",
    all(target_os = "windows", feature = "unix-on-wine")
)))]
const SOCK_FLAGS: u32 = libc::SOCK_SEQPACKET;

#[cfg(any(
    target_os = "linux",
    target_os = "illumos",
    all(target_os = "windows", feature = "unix-on-wine")
))]
const RECVMSG_FLAGS: u32 = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(any(
    target_os = "linux",
    target_os = "illumos",
    all(target_os = "windows", feature = "unix-on-wine")
)))]
const RECVMSG_FLAGS: u32 = 0;

fn new_sockaddr_un(path: &OsStr) -> (sockaddr_un, libc::socklen_t) {
    let mut sockaddr: sockaddr_un = unsafe { mem::zeroed() };
    let path = path.as_encoded_bytes();
    assert!(
        path.len() < sockaddr.sun_path.len(),
        "must leave room for NUL terminator"
    );
    sockaddr.sun_path[0..path.len()].copy_from_slice(path);
    sockaddr.sun_path[path.len()] = 0;
    sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    (sockaddr, mem::size_of::<sockaddr_un>().try_into().unwrap())
}

/// Maximum size of the kernel buffer used for transfers over this channel.
///
/// Note: This is *not* the actual maximal packet size we are allowed to use...
/// Some of it is reserved by the kernel for bookkeeping.
static SYSTEM_SENDBUF_SIZE: LazyLock<usize> = LazyLock::new(|| {
    let sock = libc::socket(libc::AF_UNIX, SOCK_FLAGS, 0)
        .expect("Failed to obtain a socket for checking maximum send size");
    let mut socket_sendbuf_size: c_int = 0;
    let len = libc::getsockopt(sock, libc::SOL_SOCKET, libc::SO_SNDBUF, unsafe {
        NonNull::from(&mut socket_sendbuf_size)
            .cast::<[u8; size_of::<c_int>()]>()
            .as_mut()
    })
    .expect("Failed to obtain maximum send size for socket");
    libc::close(sock).expect("Failed to close socket");
    assert_eq!(len, size_of::<c_int>() as u32);
    socket_sendbuf_size
        .try_into()
        .expect("getsockopt should \"return\" a non-negative size")
});

// The pid of the current process which is used to create unique IDs
static PID: LazyLock<c_int> = LazyLock::new(libc::getpid);

// A global count used to create unique IDs
static SHM_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver), UnixError> {
    let [sd, rc] = libc::socketpair(libc::AF_UNIX, SOCK_FLAGS, 0)?;
    Ok((OsIpcSender::from_fd(sd), OsIpcReceiver::from_fd(rc)))
}

#[derive(PartialEq, Debug)]
pub struct OsIpcReceiver {
    fd: Cell<c_int>,
}

impl Drop for OsIpcReceiver {
    fn drop(&mut self) {
        let fd = self.fd.get();
        if fd >= 0 {
            libc::close(fd).unwrap();
        }
    }
}

impl OsIpcReceiver {
    fn from_fd(fd: c_int) -> OsIpcReceiver {
        OsIpcReceiver { fd: Cell::new(fd) }
    }

    fn consume_fd(&self) -> c_int {
        self.fd.replace(-1)
    }

    pub fn consume(&self) -> OsIpcReceiver {
        OsIpcReceiver::from_fd(self.consume_fd())
    }

    #[allow(clippy::type_complexity)]
    pub fn recv(&self) -> Result<IpcMessage, UnixError> {
        recv(self.fd.get(), BlockingMode::Blocking)
    }

    #[allow(clippy::type_complexity)]
    pub fn try_recv(&self) -> Result<IpcMessage, UnixError> {
        recv(self.fd.get(), BlockingMode::Nonblocking)
    }

    #[allow(clippy::type_complexity)]
    pub fn try_recv_timeout(&self, duration: Duration) -> Result<IpcMessage, UnixError> {
        recv(self.fd.get(), BlockingMode::Timeout(duration))
    }
}

#[derive(PartialEq, Debug)]
struct SharedFileDescriptor(c_int);

impl Drop for SharedFileDescriptor {
    fn drop(&mut self) {
        libc::close(self.0).unwrap();
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct OsIpcSender {
    fd: Arc<SharedFileDescriptor>,
    // Make sure this is `!Sync`, to match `mpsc::Sender`; and to discourage sharing references.
    //
    // (Rather, senders should just be cloned, as they are shared internally anyway --
    // another layer of sharing only adds unnecessary overhead...)
    nosync_marker: PhantomData<Cell<()>>,
}

impl OsIpcSender {
    fn from_fd(fd: c_int) -> OsIpcSender {
        OsIpcSender {
            fd: Arc::new(SharedFileDescriptor(fd)),
            nosync_marker: PhantomData,
        }
    }

    /// Calculate maximum payload data size per fragment.
    ///
    /// It is the total size of the kernel buffer, minus the part reserved by the kernel.
    ///
    /// The `sendbuf_size` passed in should usually be the maximum kernel buffer size,
    /// i.e. the value of *SYSTEM_SENDBUF_SIZE --
    /// except after getting ENOBUFS, in which case it needs to be reduced.
    fn fragment_size(sendbuf_size: usize) -> usize {
        sendbuf_size - RESERVED_SIZE
    }

    /// Calculate maximum payload data size of first fragment.
    ///
    /// This one is smaller than regular fragments, because it carries the message (size) header.
    fn first_fragment_size(sendbuf_size: usize) -> usize {
        (Self::fragment_size(sendbuf_size) - mem::size_of::<usize>()) & (!8usize + 1)
        // Ensure optimal alignment.
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
    pub fn get_max_fragment_size() -> usize {
        Self::first_fragment_size(*SYSTEM_SENDBUF_SIZE)
    }

    pub fn send(
        &self,
        data: &[u8],
        channels: Vec<OsIpcChannel>,
        shared_memory_regions: Vec<OsIpcSharedMemory>,
    ) -> Result<(), UnixError> {
        let mut fds = Vec::new();
        for channel in channels.iter() {
            debug_assert!(channel.fd() > 0, "Invalid channel fd: {}", channel.fd());
            fds.push(channel.fd());
        }
        for shared_memory_region in shared_memory_regions.iter() {
            debug_assert!(
                shared_memory_region.store.fd() > 0,
                "Invalid shared memory region fd: {}",
                shared_memory_region.store.fd()
            );
            fds.push(shared_memory_region.store.fd());
        }

        // `len` is the total length of the message.
        // Its value will be sent as a message header before the payload data.
        //
        // Not to be confused with the length of the data to send in this packet
        // (i.e. the length of the data buffer passed in),
        // which in a fragmented send will be smaller than the total message length.
        fn send_first_fragment(
            sender_fd: fd_t,
            fds: &[fd_t],
            data_buffer: &[u8],
            len: usize,
        ) -> Result<(), UnixError> {
            let result = unsafe {
                let cmsg_length = mem::size_of_val(fds);
                let unpadded_layout = libc::cmsg_layout_unpadded(cmsg_length)
                    .map_err(|e| UnixError::Io(io::Error::other(e)))?;
                let layout = unpadded_layout.pad_to_align();
                let (cmsg_buffer, cmsg_space) = if cmsg_length > 0 {
                    let Some(cmsg_buffer) =
                        NonNull::new(std::alloc::alloc(layout).cast::<cmsghdr>())
                    else {
                        std::alloc::handle_alloc_error(layout);
                    };
                    cmsg_buffer.write(cmsghdr {
                        len: unpadded_layout.size(),
                        level: libc::SOL_SOCKET,
                        r#type: libc::SCM_RIGHTS,
                    });

                    NonNull::from(fds).cast::<fd_t>().copy_to_nonoverlapping(
                        libc::cmsg_data(cmsg_buffer).cast::<fd_t>(),
                        fds.len(),
                    );
                    (Some(cmsg_buffer), layout.size())
                } else {
                    (None, 0)
                };

                let mut iovec = [
                    // First fragment begins with a header recording the total data length.
                    //
                    // The receiver uses this to determine
                    // whether it already got the entire message,
                    // or needs to receive additional fragments -- and if so, how much.
                    iovec {
                        base: NonNull::from(&len).cast(),
                        len: mem::size_of_val(&len),
                    },
                    iovec {
                        base: NonNull::from(data_buffer).cast(),
                        len: data_buffer.len(),
                    },
                ];

                let msg = new_msghdr(&mut iovec, cmsg_buffer, cmsg_space);
                let result = libc::sendmsg(sender_fd, &msg, 0);
                if let Some(ptr) = cmsg_buffer {
                    std::alloc::dealloc(ptr.cast::<u8>().as_ptr(), layout);
                }
                result
            };

            match result {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Err(UnixError::Io(e)),
                Err(e) => Err(UnixError::from(e)),
            }
        }

        fn send_followup_fragment(sender_fd: c_int, data_buffer: &[u8]) -> Result<(), UnixError> {
            libc::send(sender_fd, data_buffer, 0)?;
            Ok(())
        }

        let mut sendbuf_size = *SYSTEM_SENDBUF_SIZE;

        /// Reduce send buffer size after getting ENOBUFS,
        /// i.e. when the kernel failed to allocate a large enough buffer.
        ///
        /// (If the buffer already was significantly smaller
        /// than the memory page size though,
        /// if means something else must have gone wrong;
        /// so there is no point in further downsizing,
        /// and we error out instead.)
        fn downsize(sendbuf_size: &mut usize, sent_size: usize) -> Result<(), ()> {
            if sent_size > 2000 {
                *sendbuf_size /= 2;
                // Make certain we end up with less than what we tried before...
                if *sendbuf_size >= sent_size {
                    *sendbuf_size = sent_size / 2;
                }
                Ok(())
            } else {
                Err(())
            }
        }

        // If the message is small enough, try sending it in a single fragment.
        if data.len() <= Self::get_max_fragment_size() {
            match send_first_fragment(self.fd.0, &fds[..], data, data.len()) {
                Ok(_) => return Ok(()),
                Err(error) => {
                    // ENOBUFS means the kernel failed to allocate a buffer large enough
                    // to actually transfer the message,
                    // although the message was small enough to fit the maximum send size --
                    // so we have to proceed with a fragmented send nevertheless,
                    // using a reduced send buffer size.
                    //
                    // Any other errors we might get here are non-recoverable.
                    match error {
                        UnixError::Io(e)
                            if e.raw_os_error() == Some(libc::ENOBUFS)
                                && downsize(&mut sendbuf_size, data.len()).is_ok() => {},
                        _ => {
                            return Err(error);
                        },
                    }
                },
            }
        }

        // The packet is too big. Fragmentation time!
        //
        // Create dedicated channel to send all but the first fragment.
        // This way we avoid fragments of different messages interleaving in the receiver.
        //
        // The receiver end of the channel is sent with the first fragment
        // along any other file descriptors that are to be transferred in the message.
        let (dedicated_tx, dedicated_rx) = channel()?;
        // Extract FD handle without consuming the Receiver, so the FD doesn't get closed.
        fds.push(dedicated_rx.fd.get());

        // Split up the packet into fragments.
        let mut byte_position = 0;
        while byte_position < data.len() {
            let end_byte_position;
            let result = if byte_position == 0 {
                // First fragment. No offset; but contains message header (total size).
                // The auxiliary data (FDs) is also sent along with this one.

                // This fragment always uses the full allowable buffer size.
                end_byte_position = Self::first_fragment_size(sendbuf_size);
                send_first_fragment(self.fd.0, &fds[..], &data[..end_byte_position], data.len())
            } else {
                // Followup fragment. No header; but offset by amount of data already sent.

                end_byte_position = cmp::min(
                    byte_position + Self::fragment_size(sendbuf_size),
                    data.len(),
                );
                send_followup_fragment(dedicated_tx.fd.0, &data[byte_position..end_byte_position])
            };

            if let Err(error) = result {
                match error {
                    UnixError::Io(e)
                        if e.raw_os_error() == Some(libc::ENOBUFS)
                            && downsize(&mut sendbuf_size, end_byte_position - byte_position)
                                .is_ok() =>
                    {
                        // If the kernel failed to allocate a buffer large enough for the packet,
                        // retry with a smaller size (if possible).
                        continue;
                    },
                    _ => {
                        return Err(error);
                    },
                }
            }

            byte_position = end_byte_position;
        }

        Ok(())
    }

    pub fn connect(name: &str) -> Result<OsIpcSender, UnixError> {
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, SOCK_FLAGS, 0)?;
            let (sockaddr, len) = new_sockaddr_un(OsStr::new(&name));
            libc::connect(fd, &sockaddr as *const _ as *const sockaddr, len)?;

            Ok(OsIpcSender::from_fd(fd))
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum OsIpcChannel {
    Sender(OsIpcSender),
    Receiver(OsIpcReceiver),
}

impl OsIpcChannel {
    fn fd(&self) -> c_int {
        match *self {
            OsIpcChannel::Sender(ref sender) => sender.fd.0,
            OsIpcChannel::Receiver(ref receiver) => receiver.fd.get(),
        }
    }
}

pub struct OsIpcReceiverSet {
    epoll: fd_t,
    events: Vec<libc::epoll_event>,
    fds: Vec<fd_t>,
}

impl Drop for OsIpcReceiverSet {
    fn drop(&mut self) {
        for &fd in &self.fds {
            libc::close(fd).unwrap();
        }
    }
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet, UnixError> {
        let epoll = libc::epoll_create1(0)?;
        Ok(OsIpcReceiverSet {
            epoll,
            events: Vec::new(),
            fds: Vec::new(),
        })
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<u64, UnixError> {
        let fd = receiver.fd.get();
        libc::epoll_ctl(
            self.epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            Some(&mut libc::epoll_event {
                events: libc::EPOLLIN,
                data: (fd as u32).into(),
            }),
        )?;
        // finally, forget the receiver now that it has been added correctly
        std::mem::forget(receiver);

        self.fds.push(fd);
        assert_eq!(self.events.len(), 0);
        self.events.reserve(self.fds.len());
        Ok((fd as u32).into())
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>, UnixError> {
        let mut selection_results = Vec::<OsIpcSelectionResult>::new();

        // Poll until we receive at least one event.
        assert_eq!(self.events.len(), 0);
        let events = self.events.spare_capacity_mut();
        let n = loop {
            match libc::epoll_wait(self.epoll, events, -1) {
                Ok(0) => {},
                Ok(rc) => break rc,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
                Err(e) => return Err(e.into()),
            }
        };

        let events = &events[0..n];
        for event in events {
            let event = unsafe { event.assume_init_ref() };

            // We only register this `Poll` for readable events.
            assert_ne!(event.events & libc::EPOLLIN, 0);

            fn fd_from_event_data(data: u64) -> Option<fd_t> {
                Some(u32::try_from(data).ok()? as i32)
            }

            loop {
                let data = event.data;
                let fd = fd_from_event_data(data)
                    .expect("Kernel shouldn't give us an event with invalid data");
                let msg = match recv(fd, BlockingMode::Nonblocking) {
                    Ok(msg) => msg,
                    Err(UnixError::ChannelClosed) => {
                        libc::epoll_ctl(self.epoll, libc::EPOLL_CTL_DEL, fd, None)?;
                        self.fds.swap_remove(
                            self.fds.iter().position(|&other_fd| other_fd == fd).expect(
                                "Kernel shouldn't give us an event for an fd we don't know about",
                            ),
                        );
                        std::mem::drop(OsIpcReceiver::from_fd(fd));
                        selection_results
                            .push(OsIpcSelectionResult::ChannelClosed((fd as u32).into()));
                        break;
                    },
                    Err(UnixError::Empty) => {
                        // We tried to read another message from the file descriptor and
                        // it would have blocked, so we have exhausted all of the data
                        // pending to read.
                        break;
                    },
                    Err(e) => return Err(e),
                };
                selection_results.push(OsIpcSelectionResult::DataReceived((fd as u32).into(), msg));
            }
        }

        Ok(selection_results)
    }
}

pub enum OsIpcSelectionResult {
    DataReceived(u64, IpcMessage),
    ChannelClosed(u64),
}

#[must_use]
#[derive(PartialEq, Debug)]
pub struct OsOpaqueIpcChannel {
    fd: c_int,
}

impl Drop for OsOpaqueIpcChannel {
    fn drop(&mut self) {
        // Make sure we don't leak!
        //
        // The `OsOpaqueIpcChannel` objects should always be used,
        // i.e. converted with `to_sender()` or `to_receiver()` --
        // so the value should already be unset before the object gets dropped.
        assert_eq!(self.fd, -1, "OsOpaqueIpcChannel leaked");
    }
}

impl OsOpaqueIpcChannel {
    fn from_fd(fd: c_int) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel { fd }
    }

    pub fn consume(&mut self) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            fd: mem::replace(&mut self.fd, -1),
        }
    }

    pub fn into_sender(self) -> OsIpcSender {
        let this = ManuallyDrop::new(self);
        OsIpcSender::from_fd(this.fd)
    }

    pub fn into_receiver(self) -> OsIpcReceiver {
        let this = ManuallyDrop::new(self);
        OsIpcReceiver::from_fd(this.fd)
    }
}

pub struct OsIpcOneShotServer {
    fd: fd_t,

    name: CString,
}

impl Drop for OsIpcOneShotServer {
    fn drop(&mut self) {
        // close the socket and then delete the leftover socket file
        libc::close(self.fd).unwrap();
        libc::unlink(&self.name).unwrap();
    }
}

impl OsIpcOneShotServer {
    pub fn new() -> Result<(OsIpcOneShotServer, String), UnixError> {
        let fd = libc::socket(libc::AF_UNIX, SOCK_FLAGS, 0)?;
        let mut name = String::from_utf8(libc::temp_dir()?).map_err(|e| {
            UnixError::Io(io::Error::other(format!(
                "Invalid UTF-8 in temp_dir path: {e}"
            )))
        })?;
        // can't use std::path because we may be compiled for Windows.
        if !name.starts_with("/") {
            return Err(UnixError::Io(io::Error::other(format!(
                "temp_dir path is not absolute: {name:?}"
            ))));
        }
        if name.contains('\0') {
            return Err(UnixError::Io(io::Error::other(format!(
                "temp_dir path contains an interior NUL byte: {name:?}"
            ))));
        }
        const PREFIX: &str = "/socket-";
        const RAND_LEN: usize = 6;
        name.reserve(PREFIX.len() + RAND_LEN);
        name.push_str(PREFIX);
        let base_len = name.len();
        for _ in 0..65536 {
            let mut rng = rand::rng();
            for _ in 0..RAND_LEN {
                name.push(rng.sample(rand::distr::Alphanumeric) as char);
            }

            if Path::new(&name).try_exists()? {
                // truncate and try again
                name.truncate(base_len);
            } else {
                break;
            }
        }

        let (sockaddr, len) = new_sockaddr_un(OsStr::new(&name));
        unsafe { libc::bind(fd, &sockaddr as *const _ as *const sockaddr, len)? };

        libc::listen(fd, 10)?;

        Ok((
            OsIpcOneShotServer {
                fd,
                name: CString::new(&*name).expect("We have already checked this"),
            },
            name,
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn accept(self) -> Result<(OsIpcReceiver, IpcMessage), UnixError> {
        unsafe {
            let client_fd = libc::accept(self.fd, None, None)?;
            make_socket_lingering(client_fd)?;

            let receiver = OsIpcReceiver::from_fd(client_fd);
            let ipc_message = receiver.recv()?;
            Ok((receiver, ipc_message))
        }
    }
}

// Make sure that the kernel doesn't return errors to readers if there's still data left after we
// close our end.
//
// See, for example, https://github.com/servo/ipc-channel/issues/29
fn make_socket_lingering(sockfd: c_int) -> Result<(), UnixError> {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 30,
    };
    let r = libc::setsockopt(sockfd, libc::SOL_SOCKET, libc::SO_LINGER, unsafe {
        NonNull::from(&linger)
            .cast::<[u8; mem::size_of::<libc::linger>()]>()
            .as_ref()
    });
    match r {
        Ok(()) => {},
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
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
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

struct BackingStore {
    fd: c_int,
}

impl BackingStore {
    pub fn new(length: usize) -> io::Result<BackingStore> {
        let count = SHM_COUNT.fetch_add(1, Ordering::Relaxed);
        let timestamp = UNIX_EPOCH.elapsed().expect("time should not run backwards");
        let name = CString::new(format!(
            "/ipc-channel-shared-memory.{}.{}.{}.{}",
            count,
            *PID,
            timestamp.as_secs(),
            timestamp.subsec_nanos()
        ))
        .unwrap();
        let fd = create_shmem(name, length)?;
        Ok(Self::from_fd(fd))
    }

    pub fn from_fd(fd: c_int) -> BackingStore {
        BackingStore { fd }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    pub unsafe fn map_file(
        &self,
        length: Option<usize>,
    ) -> Result<(NonNull<u8>, usize), io::Error> {
        let length = match length {
            Some(length) => length,
            None => {
                let mut st = mem::MaybeUninit::uninit();
                libc::fstat(self.fd, &mut st)?;
                unsafe { st.assume_init() }.size as usize
            },
        };
        if length == 0 {
            // This will cause `mmap` to fail, so handle it explicitly.
            return Ok((NonNull::dangling(), length));
        }
        let address = unsafe {
            libc::mmap(
                None,
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd,
                0,
            )
        }?;
        assert_ne!(address.as_ptr(), libc::MAP_FAILED);
        Ok((address, length))
    }
}

impl Drop for BackingStore {
    fn drop(&mut self) {
        libc::close(self.fd).unwrap();
    }
}

pub struct OsIpcSharedMemory {
    ptr: NonNull<u8>,
    length: usize,
    store: BackingStore,
}

unsafe impl Send for OsIpcSharedMemory {}
unsafe impl Sync for OsIpcSharedMemory {}

impl Drop for OsIpcSharedMemory {
    fn drop(&mut self) {
        if self.length != 0 {
            unsafe {
                libc::munmap(self.ptr, self.length).unwrap();
            }
        }
    }
}

impl Clone for OsIpcSharedMemory {
    fn clone(&self) -> OsIpcSharedMemory {
        unsafe {
            let store = BackingStore::from_fd(libc::dup(self.store.fd()).unwrap());
            let (address, _) = store.map_file(Some(self.length)).unwrap();
            OsIpcSharedMemory::from_raw_parts(address, self.length, store)
        }
    }
}

impl PartialEq for OsIpcSharedMemory {
    fn eq(&self, other: &OsIpcSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for OsIpcSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for OsIpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { NonNull::slice_from_raw_parts(self.ptr, self.length).as_ref() }
    }
}

impl OsIpcSharedMemory {
    /// See [`crate::ipc::IpcSharedMemory::deref_mut`].
    #[allow(clippy::missing_safety_doc)]
    #[inline]
    pub unsafe fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { NonNull::slice_from_raw_parts(self.ptr, self.length).as_mut() }
    }
}

impl OsIpcSharedMemory {
    unsafe fn from_raw_parts(
        ptr: NonNull<u8>,
        length: usize,
        store: BackingStore,
    ) -> OsIpcSharedMemory {
        OsIpcSharedMemory { ptr, length, store }
    }

    unsafe fn from_fd(fd: c_int) -> io::Result<OsIpcSharedMemory> {
        let store = BackingStore::from_fd(fd);
        let (ptr, length) = unsafe { store.map_file(None) }?;
        Ok(unsafe { OsIpcSharedMemory::from_raw_parts(ptr, length, store) })
    }

    pub fn from_byte(byte: u8, length: usize) -> OsIpcSharedMemory {
        let store = BackingStore::new(length).unwrap();
        unsafe {
            let (address, _) = store.map_file(Some(length)).unwrap();
            for element in NonNull::slice_from_raw_parts(address, length).as_mut() {
                *element = byte;
            }
            OsIpcSharedMemory::from_raw_parts(address, length, store)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> OsIpcSharedMemory {
        let store = BackingStore::new(bytes.len()).unwrap();
        unsafe {
            let (address, _) = store.map_file(Some(bytes.len())).unwrap();
            address.copy_from_nonoverlapping(NonNull::from(bytes).cast(), bytes.len());
            OsIpcSharedMemory::from_raw_parts(address, bytes.len(), store)
        }
    }
}

#[derive(Debug)]
pub enum UnixError {
    Empty,
    ChannelClosed,
    Io(io::Error),
}

impl UnixError {
    pub fn channel_is_closed(&self) -> bool {
        matches!(self, UnixError::ChannelClosed)
    }
}

impl fmt::Display for UnixError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => write!(fmt, "The socket is empty"),
            Self::ChannelClosed => write!(fmt, "All senders for this socket closed"),
            Self::Io(e) => write!(fmt, "{e}"),
        }
    }
}

impl StdError for UnixError {}

impl From<UnixError> for io::Error {
    fn from(unix_error: UnixError) -> io::Error {
        match unix_error {
            UnixError::Empty => io::Error::new(io::ErrorKind::WouldBlock, unix_error),
            UnixError::ChannelClosed => io::Error::new(io::ErrorKind::ConnectionReset, unix_error),
            UnixError::Io(e) => e,
        }
    }
}

impl From<io::Error> for UnixError {
    fn from(e: io::Error) -> UnixError {
        // FIXME: this case should be only for recv functions, not send functions. See temporary workaround in `send_first_fragment`.
        if e.kind() == io::ErrorKind::ConnectionReset {
            Self::ChannelClosed
        } else if e.kind() == io::ErrorKind::WouldBlock
            || matches!(e.raw_os_error(), Some(libc::EAGAIN))
        {
            // TODO: remove the second half of that condition if possible
            Self::Empty
        } else {
            Self::Io(e)
        }
    }
}

#[derive(Copy, Clone)]
enum BlockingMode {
    Blocking,
    Nonblocking,
    Timeout(Duration),
}

#[allow(clippy::uninit_vec, clippy::type_complexity)]
fn recv(fd: c_int, blocking_mode: BlockingMode) -> Result<IpcMessage, UnixError> {
    let (mut channels, mut shared_memory_regions) = (Vec::new(), Vec::new());

    // First fragments begins with a header recording the total data length.
    //
    // We use this to determine whether we already got the entire message,
    // or need to receive additional fragments -- and if so, how much.
    let mut total_size = 0usize;
    let mut main_data_buffer;
    unsafe {
        // Allocate a buffer without initialising the memory.
        main_data_buffer = Vec::with_capacity(OsIpcSender::get_max_fragment_size());

        let mut iovec = [
            iovec {
                base: NonNull::from(&mut total_size).cast(),
                len: mem::size_of_val(&total_size),
            },
            iovec {
                base: NonNull::from(main_data_buffer.as_mut_slice()).cast(),
                len: main_data_buffer.capacity(),
            },
        ];
        let mut cmsg = MaybeUninit::<UnixCmsg>::uninit();
        let mut msg = new_msghdr(
            &mut iovec,
            Some(NonNull::from(&mut cmsg).cast()),
            size_of::<UnixCmsg>(),
        );

        let bytes_read = recvmsg_wrapped(fd, &mut msg, blocking_mode)?;
        main_data_buffer.set_len(bytes_read - mem::size_of_val(&total_size));

        let cmsg_length = msg.controllen;
        if cmsg_length != 0 {
            let cmsg = cmsg.assume_init_ref();

            // The control header is followed by an array of FDs. The size of the control header is
            // determined by CMSG_SPACE. (On Linux this would the same as CMSG_ALIGN, but that isn't
            // exposed by libc. CMSG_SPACE(0) is the portable version of that.)
            let fd_count = (cmsg.hdr.len - mem::size_of::<cmsghdr>()) / mem::size_of::<fd_t>();

            let cmsg_fds =
                NonNull::slice_from_raw_parts(NonNull::from(&cmsg.body).cast::<fd_t>(), fd_count)
                    .as_ref();
            for &fd in cmsg_fds {
                if is_socket(fd) {
                    channels.push(OsOpaqueIpcChannel::from_fd(fd));
                } else {
                    shared_memory_regions.push(OsIpcSharedMemory::from_fd(fd)?);
                }
            }
        }
    }

    if total_size == main_data_buffer.len() {
        // Fast path: no fragments.
        return Ok(IpcMessage::new(
            main_data_buffer,
            channels,
            shared_memory_regions,
        ));
    }

    // Reassemble fragments.
    //
    // The initial fragment carries the receive end of a dedicated channel
    // through which all the remaining fragments will be coming in.
    let dedicated_rx = channels.pop().unwrap().into_receiver();

    // Extend the buffer to hold the entire message, without initialising the memory.
    let len = main_data_buffer.len();
    main_data_buffer.reserve_exact(total_size - len);

    // Receive followup fragments directly into the main buffer.
    while main_data_buffer.len() < total_size {
        let write_pos = main_data_buffer.len();
        let max_read = cmp::min(
            OsIpcSender::fragment_size(*SYSTEM_SENDBUF_SIZE),
            total_size - write_pos,
        );

        // Note: we always use blocking mode for followup fragments,
        // to make sure that once we start receiving a multi-fragment message,
        // we don't abort in the middle of it...
        let n = libc::recv(
            dedicated_rx.fd.get(),
            &mut main_data_buffer.spare_capacity_mut()[..max_read],
            0,
        )?;
        unsafe { main_data_buffer.set_len(write_pos + n) };

        if n == 0 {
            return Err(UnixError::ChannelClosed);
        }
    }

    Ok(IpcMessage::new(
        main_data_buffer,
        channels,
        shared_memory_regions,
    ))
}

// https://github.com/servo/ipc-channel/issues/192
fn new_msghdr(
    iovec: &mut [iovec],
    cmsg_buffer: Option<NonNull<cmsghdr>>,
    cmsg_space: usize,
) -> msghdr {
    msghdr {
        name: ptr::null_mut(),
        namelen: 0,
        iov: iovec.as_mut_ptr(),
        iovlen: iovec.len(),
        control: cmsg_buffer
            .map(NonNull::as_ptr)
            .unwrap_or(ptr::null_mut())
            .cast::<c_void>(),
        controllen: cmsg_space,
        flags: 0,
    }
}

fn create_shmem(name: CString, length: usize) -> io::Result<c_int> {
    let fd = libc::memfd_create(&name, libc::MFD_CLOEXEC)?;
    libc::ftruncate(fd, length as libc::off_t)?;
    Ok(fd)
}

#[repr(C, align(8))]
struct UnixCmsg {
    hdr: cmsghdr,
    body: [MaybeUninit<u8>; Self::LEN],
}

unsafe impl Send for UnixCmsg {}

impl UnixCmsg {
    const LEN: usize = match libc::cmsg_data_layout(MAX_FDS_IN_CMSG * mem::size_of::<c_int>()) {
        Ok(layout) => layout.pad_to_align().size(),
        Err(_) => panic!(),
    };
}

unsafe fn recvmsg_wrapped(
    fd: c_int,
    msg: &mut msghdr,
    blocking_mode: BlockingMode,
) -> Result<usize, UnixError> {
    match blocking_mode {
        BlockingMode::Nonblocking => {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK.try_into().unwrap())?;
        },
        BlockingMode::Timeout(duration) => {
            let events = libc::POLLIN | libc::POLLPRI | libc::POLLRDHUP;

            let n = libc::poll(
                &mut [libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                }],
                duration.as_millis().try_into().unwrap_or(-1),
            )?;

            if n == 0 {
                return Err(UnixError::Empty);
            }
        },
        BlockingMode::Blocking => {},
    }

    let n = libc::recvmsg(
        fd,
        unsafe { std::mem::transmute::<&mut msghdr, &mut MaybeUninit<msghdr>>(msg) },
        RECVMSG_FLAGS,
    )?;

    if n == 0 {
        return Err(UnixError::ChannelClosed);
    }

    if let BlockingMode::Nonblocking = blocking_mode {
        libc::fcntl(fd, libc::F_SETFL, 0)?;
    }

    Ok(n)
}

fn is_socket(fd: c_int) -> bool {
    unsafe {
        let mut st = mem::MaybeUninit::uninit();
        if libc::fstat(fd, &mut st).is_err() {
            return false;
        }
        (st.assume_init().mode & libc::S_IFMT) == libc::S_IFSOCK
    }
}
