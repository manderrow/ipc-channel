// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::error::{DecodeError, RecvError, SendError, TryRecvError};
use crate::platform::{self, OsIpcChannel, OsIpcReceiver, OsIpcReceiverSet, OsIpcSender};
use crate::platform::{
    OsIpcOneShotServer, OsIpcSelectionResult, OsIpcSharedMemory, OsOpaqueIpcChannel,
};

use rkyv::api::high::HighValidator;
use rkyv::bytecheck::CheckBytes;
use rkyv::de::Pool;
use rkyv::rancor::{Source, Strategy};
use rkyv::{Archive, Deserialize, Portable, Serialize};
use std::cmp::min;
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::ptr::NonNull;
use std::time::Duration;

/// Create a connected [IpcSender] and [IpcReceiver] that
/// transfer messages of a given type provided by type `T`
/// or inferred by the types of messages sent by the sender.
///
/// Messages sent by the sender will be available to the
/// receiver even if the sender or receiver has been moved
/// to a different process. In addition, receivers and senders
/// may be sent over an existing channel.
///
/// # Examples
///
/// ```
/// # use ipc_channel::ipc;
///
/// let payload = "Hello, World!".to_owned();
///
/// // Create a channel
/// let (tx, rx) = ipc::channel().unwrap();
///
/// // Send data
/// tx.send(&payload).unwrap();
///
/// // Receive the data
/// let response = rx.recv().unwrap();
///
/// assert_eq!(response, "Hello, World!".to_owned());
/// ```
///
/// [IpcSender]: struct.IpcSender.html
/// [IpcReceiver]: struct.IpcReceiver.html
pub fn channel<T>() -> Result<(IpcSender<T>, IpcReceiver<T>), io::Error>
where
    T: Decode + Encode,
{
    let (os_sender, os_receiver) = platform::channel()?;
    let ipc_receiver = IpcReceiver {
        os_receiver,
        phantom: PhantomData,
    };
    let ipc_sender = IpcSender {
        os_sender,
        phantom: PhantomData,
    };
    Ok((ipc_sender, ipc_receiver))
}

/// Create a connected [IpcBytesSender] and [IpcBytesReceiver].
///
/// Note: The [IpcBytesSender] transfers messages of the type `[u8]`
/// and the [IpcBytesReceiver] receives a `Vec<u8>`. This sender/receiver
/// type does not serialize/deserialize messages through `serde`, making
/// it more efficient where applicable.
///
/// # Examples
///
/// ```
/// # use ipc_channel::ipc;
///
/// let payload = b"'Tis but a scratch!!";
///
/// // Create a channel
/// let (tx, rx) = ipc::bytes_channel().unwrap();
///
/// // Send data
/// tx.send(payload).unwrap();
///
/// // Receive the data
/// let response = rx.recv().unwrap();
///
/// assert_eq!(response, payload);
/// ```
///
/// [IpcBytesReceiver]: struct.IpcBytesReceiver.html
/// [IpcBytesSender]: struct.IpcBytesSender.html
pub fn bytes_channel() -> Result<(IpcBytesSender, IpcBytesReceiver), io::Error> {
    let (os_sender, os_receiver) = platform::channel()?;
    let ipc_bytes_receiver = IpcBytesReceiver { os_receiver };
    let ipc_bytes_sender = IpcBytesSender { os_sender };
    Ok((ipc_bytes_sender, ipc_bytes_receiver))
}

/// Receiving end of a channel using serialized messages.
///
/// # Examples
///
/// ## Blocking IO
///
/// ```
/// # use ipc_channel::ipc;
/// #
/// # let (tx, rx) = ipc::channel().unwrap();
/// #
/// # let q = "Answer to the ultimate question of life, the universe, and everything";
/// #
/// # tx.send(&q.to_owned()).unwrap();
/// let response = rx.recv().unwrap();
/// println!("Received data...");
/// # assert_eq!(response, q);
/// ```
///
/// ## Non-blocking IO
///
/// ```
/// # use ipc_channel::ipc;
/// #
/// # let (tx, rx) = ipc::channel().unwrap();
/// #
/// # let answer = "42";
/// #
/// # tx.send(&answer.to_owned()).unwrap();
/// loop {
///     match rx.try_recv() {
///         Ok(res) => {
///             // Do something interesting with your result
///             println!("Received data...");
///             break;
///         },
///         Err(_) => {
///             // Do something else useful while we wait
///             println!("Still waiting...");
///         }
///     }
/// }
/// ```
///
/// ## Embedding Receivers
///
/// ```
/// # use ipc_channel::ipc;
/// #
/// let (tx, rx) = ipc::channel().unwrap();
/// let (embedded_tx, embedded_rx) = ipc::channel().unwrap();
/// # let data = [0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x00];
/// // Send the IpcReceiver
/// tx.send(&embedded_rx).unwrap();
/// # embedded_tx.send(&data.to_owned()).unwrap();
/// // Receive the sent IpcReceiver
/// let received_rx = rx.recv().unwrap();
/// // Receive any data sent to the received IpcReceiver
/// let rx_data = received_rx.recv().unwrap();
/// # assert_eq!(rx_data, data);
/// ```
///
/// # Implementation details
///
/// Each [IpcReceiver] is backed by the OS specific implementations of `OsIpcReceiver`.
///
/// [IpcReceiver]: struct.IpcReceiver.html
#[derive(Debug)]
pub struct IpcReceiver<T> {
    os_receiver: OsIpcReceiver,
    phantom: PhantomData<T>,
}

impl<T> IpcReceiver<T>
where
    T: Decode,
{
    /// Blocking receive.
    pub fn recv(&self) -> Result<T, RecvError> {
        self.os_receiver.recv()?.to().map_err(RecvError::from)
    }

    /// Non-blocking receive
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.os_receiver
            .try_recv()?
            .to()
            .map_err(RecvError::from)
            .map_err(TryRecvError::Recv)
    }

    /// Blocks for up to the specified duration attempting to receive a message.
    ///
    /// This may block for longer than the specified duration if the channel is busy. If your timeout
    /// exceeds the duration that your operating system can represent in milliseconds, this may
    /// block forever. At the time of writing, the smallest duration that may trigger this behavior
    /// is over 24 days.
    pub fn try_recv_timeout(&self, duration: Duration) -> Result<T, TryRecvError> {
        self.os_receiver
            .try_recv_timeout(duration)?
            .to()
            .map_err(RecvError::from)
            .map_err(TryRecvError::Recv)
    }
}

impl<T> IpcReceiver<T> {
    /// Erase the type of the channel.
    ///
    /// Useful for adding routes to a `RouterProxy`.
    pub fn to_opaque(self) -> OpaqueIpcReceiver {
        OpaqueIpcReceiver {
            os_receiver: self.os_receiver,
        }
    }
}

/// Sending end of a channel using serialized messages.
///
///
/// ## Embedding Senders
///
/// ```
/// # use ipc_channel::ipc;
/// #
/// # let (tx, rx) = ipc::channel().unwrap();
/// # let (embedded_tx, embedded_rx) = ipc::channel().unwrap();
/// # let data = [0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x00];
/// // Send the IpcSender
/// tx.send(&embedded_tx).unwrap();
/// // Receive the sent IpcSender
/// let received_tx = rx.recv().unwrap();
/// // Send data from the received IpcSender
/// received_tx.send(&data).unwrap();
/// # let rx_data = embedded_rx.recv().unwrap();
/// # assert_eq!(rx_data, data);
/// ```
#[derive(Debug)]
pub struct IpcSender<T> {
    os_sender: OsIpcSender,
    phantom: PhantomData<T>,
}

impl<T> Clone for IpcSender<T> {
    fn clone(&self) -> IpcSender<T> {
        IpcSender {
            os_sender: self.os_sender.clone(),
            phantom: PhantomData,
        }
    }
}

impl<T> IpcSender<T>
where
    T: Encode,
{
    /// Create an [IpcSender] connected to a previously defined [IpcOneShotServer].
    ///
    /// This function should not be called more than once per [IpcOneShotServer],
    /// otherwise the behaviour is unpredictable.
    /// See [issue 378](https://github.com/servo/ipc-channel/issues/378) for details.
    ///
    /// [IpcSender]: struct.IpcSender.html
    /// [IpcOneShotServer]: struct.IpcOneShotServer.html
    pub fn connect(name: String) -> Result<IpcSender<T>, io::Error> {
        Ok(IpcSender {
            os_sender: OsIpcSender::connect(name)?,
            phantom: PhantomData,
        })
    }

    /// Send data across the channel to the receiver.
    ///
    /// Despite taking a reference, note that this function "takes" ownership
    /// of any receivers inside `data`.
    pub fn send(&self, data: &T) -> Result<(), SendError> {
        let (size, channels, shared_memory_regions) = {
            rkyv::util::with_arena(|arena| {
                let mut ser = CountingCustomSerializer {
                    serializer: rkyv::ser::Serializer::new(
                        crate::util::CountingWriter::default(),
                        arena.acquire(),
                        rkyv::ser::sharing::Share::new(),
                    ),
                    channels: 0,
                    shared_memory_regions: 0,
                };
                rkyv::api::serialize_using::<_, rkyv::rancor::BoxedError>(data, &mut ser).unwrap();
                (
                    ser.serializer.into_writer().len,
                    ser.channels,
                    ser.shared_memory_regions,
                )
            })
        };
        rkyv::util::with_arena(|arena| {
            let mut arena = arena.acquire();
            let bytes: &mut [MaybeUninit<u8>] = unsafe {
                let mut ptr = rkyv::ser::Allocator::<rkyv::rancor::BoxedError>::push_alloc(
                    &mut arena,
                    std::alloc::Layout::array::<u8>(size).unwrap(),
                )?;
                NonNull::slice_from_raw_parts(ptr.cast::<MaybeUninit<u8>>(), ptr.as_mut().len())
                    .as_mut()
            };
            let mut buf = rkyv::ser::writer::Buffer::from(bytes);
            let (channels, shared_memory_regions) = {
                let mut ser = CustomSerializer {
                    serializer: rkyv::ser::Serializer::new(
                        &mut buf,
                        arena,
                        rkyv::ser::sharing::Share::new(),
                    ),
                    channels: Vec::with_capacity(
                        channels.try_into().expect("really? that's ridiculous"),
                    ),
                    shared_memory_regions: Vec::with_capacity(
                        shared_memory_regions
                            .try_into()
                            .expect("really? that's ridiculous"),
                    ),
                };
                rkyv::api::serialize_using::<_, rkyv::rancor::BoxedError>(data, &mut ser)?;
                (ser.channels, ser.shared_memory_regions)
            };

            Ok(self
                .os_sender
                .send(&*buf, channels, shared_memory_regions)?)
        })
    }

    pub fn to_opaque(self) -> OpaqueIpcSender {
        OpaqueIpcSender {
            os_sender: self.os_sender,
        }
    }
}

/// Collection of [IpcReceiver]s moved into the set; thus creating a common
/// (and exclusive) endpoint for receiving messages on any of the added
/// channels.
///
/// # Examples
///
/// ```
/// # use ipc_channel::ipc::{self, IpcReceiverSet, IpcSelectionResult};
/// let data = vec![0x52, 0x75, 0x73, 0x74, 0x00];
/// let (tx, rx) = ipc::channel().unwrap();
/// let mut rx_set = IpcReceiverSet::new().unwrap();
///
/// // Add the receiver to the receiver set and send the data
/// // from the sender
/// let rx_id = rx_set.add(rx).unwrap();
/// tx.send(&data).unwrap();
///
/// // Poll the receiver set for any readable events
/// for event in rx_set.select().unwrap() {
///     match event {
///         IpcSelectionResult::MessageReceived(id, message) => {
///             let rx_data: Vec<u8> = message.to().unwrap();
///             assert_eq!(id, rx_id);
///             assert_eq!(data, rx_data);
///             println!("Received: {:?} from {}...", data, id);
///         },
///         IpcSelectionResult::ChannelClosed(id) => {
///             assert_eq!(id, rx_id);
///             println!("No more data from {}...", id);
///         }
///     }
/// }
/// ```
/// [IpcReceiver]: struct.IpcReceiver.html
pub struct IpcReceiverSet {
    os_receiver_set: OsIpcReceiverSet,
}

impl IpcReceiverSet {
    /// Create a new empty [IpcReceiverSet].
    ///
    /// Receivers may then be added to the set with the [add]
    /// method.
    ///
    /// [add]: #method.add
    /// [IpcReceiverSet]: struct.IpcReceiverSet.html
    pub fn new() -> Result<IpcReceiverSet, io::Error> {
        Ok(IpcReceiverSet {
            os_receiver_set: OsIpcReceiverSet::new()?,
        })
    }

    /// Add and consume the [IpcReceiver] to the set of receivers to be polled.
    /// [IpcReceiver]: struct.IpcReceiver.html
    pub fn add<T>(&mut self, receiver: IpcReceiver<T>) -> Result<u64, io::Error> {
        Ok(self.os_receiver_set.add(receiver.os_receiver)?)
    }

    /// Add an [OpaqueIpcReceiver] to the set of receivers to be polled.
    /// [OpaqueIpcReceiver]: struct.OpaqueIpcReceiver.html
    pub fn add_opaque(&mut self, receiver: OpaqueIpcReceiver) -> Result<u64, io::Error> {
        Ok(self.os_receiver_set.add(receiver.os_receiver)?)
    }

    /// Wait for IPC messages received on any of the receivers in the set. The
    /// method will return multiple events. An event may be either a message
    /// received or a channel closed event.
    ///
    /// [IpcReceiver]: struct.IpcReceiver.html
    pub fn select(&mut self) -> Result<Vec<IpcSelectionResult>, io::Error> {
        let results = self.os_receiver_set.select()?;
        Ok(results
            .into_iter()
            .map(|result| match result {
                OsIpcSelectionResult::DataReceived(os_receiver_id, ipc_message) => {
                    IpcSelectionResult::MessageReceived(os_receiver_id, ipc_message)
                },
                OsIpcSelectionResult::ChannelClosed(os_receiver_id) => {
                    IpcSelectionResult::ChannelClosed(os_receiver_id)
                },
            })
            .collect())
    }
}

/// Shared memory descriptor that will be made accessible to the receiver
/// of an IPC message that contains the discriptor.
///
/// # Examples
/// ```
/// # use ipc_channel::ipc::{self, IpcSharedMemory};
/// # let (tx, rx) = ipc::channel().unwrap();
/// # let data = [0x76, 0x69, 0x6d, 0x00];
/// let shmem = IpcSharedMemory::from_bytes(&data);
/// tx.send(&shmem).unwrap();
/// # let rx_shmem = rx.recv().unwrap();
/// # assert_eq!(shmem, rx_shmem);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct IpcSharedMemory {
    /// None represents no data (empty slice)
    os_shared_memory: Option<OsIpcSharedMemory>,
}

impl Deref for IpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        if let Some(os_shared_memory) = &self.os_shared_memory {
            os_shared_memory
        } else {
            &[]
        }
    }
}

impl IpcSharedMemory {
    /// Returns a mutable reference to the deref of this [`IpcSharedMemory`].
    ///
    /// # Safety
    ///
    /// This is safe if there is only one reader/writer on the data.
    /// User can achieve this by not cloning [`IpcSharedMemory`]
    /// and serializing/deserializing only once.
    #[inline]
    pub unsafe fn deref_mut(&mut self) -> &mut [u8] {
        if let Some(os_shared_memory) = &mut self.os_shared_memory {
            unsafe { os_shared_memory.deref_mut() }
        } else {
            &mut []
        }
    }
}

#[derive(rkyv::Portable, bytecheck::CheckBytes)]
#[repr(transparent)]
pub struct IpcSharedMemoryIndex(rkyv::rend::u32_le);

impl rkyv::Archive for IpcSharedMemory {
    type Archived = IpcSharedMemoryIndex;

    type Resolver = IpcSharedMemoryIndex;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        unsafe { out.write_unchecked(resolver) };
    }
}

impl<S: rkyv::rancor::Fallible + CustomSerializerTrait> rkyv::Serialize<S> for IpcSharedMemory {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        if let Some(os_shared_memory) = &self.os_shared_memory {
            Ok(IpcSharedMemoryIndex(
                serializer
                    .serialize_shared_memory_region(os_shared_memory)
                    .into(),
            ))
        } else {
            Ok(IpcSharedMemoryIndex(u32::MAX.into()))
        }
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized + CustomDeserializerTrait> Deserialize<IpcSharedMemory, D>
    for IpcSharedMemoryIndex
where
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IpcSharedMemory, D::Error> {
        if self.0.to_native() == u32::MAX {
            return Ok(IpcSharedMemory::empty());
        }
        let os_shared_memory = deserializer
            .deserialize_shared_memory_region(self.0.to_native())
            .map_err(|e| <D::Error as Source>::new(e))?;
        Ok(IpcSharedMemory {
            os_shared_memory: Some(os_shared_memory),
        })
    }
}

impl IpcSharedMemory {
    const fn empty() -> Self {
        Self {
            os_shared_memory: None,
        }
    }

    /// Create shared memory initialized with the bytes provided.
    pub fn from_bytes(bytes: &[u8]) -> IpcSharedMemory {
        if bytes.is_empty() {
            IpcSharedMemory::empty()
        } else {
            IpcSharedMemory {
                os_shared_memory: Some(OsIpcSharedMemory::from_bytes(bytes)),
            }
        }
    }

    /// Create a chunk of shared memory that is filled with the byte
    /// provided.
    pub fn from_byte(byte: u8, length: usize) -> IpcSharedMemory {
        if length == 0 {
            IpcSharedMemory::empty()
        } else {
            IpcSharedMemory {
                os_shared_memory: Some(OsIpcSharedMemory::from_byte(byte, length)),
            }
        }
    }
}

/// Result for readable events returned from [IpcReceiverSet::select].
///
/// [IpcReceiverSet::select]: struct.IpcReceiverSet.html#method.select
pub enum IpcSelectionResult {
    /// A message received from the [`IpcReceiver`] in the [`IpcMessage`] form,
    /// identified by the `u64` value.
    MessageReceived(u64, IpcMessage),
    /// The channel has been closed for the [IpcReceiver] identified by the `u64` value.
    /// [IpcReceiver]: struct.IpcReceiver.html
    ChannelClosed(u64),
}

/// Structure used to represent a raw message from an [`IpcSender`].
///
/// Use the [to] method to deserialize the raw result into the requested type.
///
/// [to]: #method.to
#[derive(PartialEq)]
pub struct IpcMessage {
    pub(crate) data: Vec<u8>,
    pub(crate) os_ipc_channels: Vec<OsOpaqueIpcChannel>,
    pub(crate) os_ipc_shared_memory_regions: Vec<OsIpcSharedMemory>,
}

impl IpcMessage {
    /// Create a new [`IpcMessage`] with data and without any [`OsOpaqueIpcChannel`]s and
    /// [`OsIpcSharedMemory`] regions.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            data,
            os_ipc_channels: vec![],
            os_ipc_shared_memory_regions: vec![],
        }
    }
}

impl Debug for IpcMessage {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        match String::from_utf8(self.data.clone()) {
            Ok(string) => string.chars().take(256).collect::<String>().fmt(formatter),
            Err(..) => self.data[0..min(self.data.len(), 256)].fmt(formatter),
        }
    }
}

pub struct Context {
    os_ipc_channels: Vec<OsOpaqueIpcChannel>,
    os_ipc_shared_memory_regions: Vec<Option<OsIpcSharedMemory>>,
}

trait Decode: Sized {
    type Archived: Portable
        + for<'a> CheckBytes<HighValidator<'a, rkyv::rancor::BoxedError>>
        + Deserialize<Self, Strategy<CustomDeserializer<Pool>, rkyv::rancor::BoxedError>>;
}

impl<T: Archive> Decode for T
where
    T::Archived: Portable
        + for<'a> CheckBytes<HighValidator<'a, rkyv::rancor::BoxedError>>
        + Deserialize<T, Strategy<CustomDeserializer<Pool>, rkyv::rancor::BoxedError>>,
{
    type Archived = T::Archived;
}

trait Encode
where
    Self: for<'a> rkyv::SerializeUnsized<
            rkyv::rancor::Strategy<
                CountingCustomSerializer<
                    rkyv::ser::Serializer<
                        crate::util::CountingWriter,
                        rkyv::ser::allocator::ArenaHandle<'a>,
                        rkyv::ser::sharing::Share,
                    >,
                >,
                rkyv::rancor::BoxedError,
            >,
        >,
    Self: for<'a, 'b, 'c> rkyv::SerializeUnsized<
            rkyv::rancor::Strategy<
                CustomSerializer<
                    rkyv::ser::Serializer<
                        &'a mut rkyv::ser::writer::Buffer<'b>,
                        rkyv::ser::allocator::ArenaHandle<'c>,
                        rkyv::ser::sharing::Share,
                    >,
                >,
                rkyv::rancor::BoxedError,
            >,
        >,
{
}

impl<T> Encode for T
where
    T: for<'a> rkyv::SerializeUnsized<
            rkyv::rancor::Strategy<
                CountingCustomSerializer<
                    rkyv::ser::Serializer<
                        crate::util::CountingWriter,
                        rkyv::ser::allocator::ArenaHandle<'a>,
                        rkyv::ser::sharing::Share,
                    >,
                >,
                rkyv::rancor::BoxedError,
            >,
        >,
    T: for<'a, 'b, 'c> rkyv::SerializeUnsized<
            rkyv::rancor::Strategy<
                CustomSerializer<
                    rkyv::ser::Serializer<
                        &'a mut rkyv::ser::writer::Buffer<'b>,
                        rkyv::ser::allocator::ArenaHandle<'c>,
                        rkyv::ser::sharing::Share,
                    >,
                >,
                rkyv::rancor::BoxedError,
            >,
        >,
{
}

impl IpcMessage {
    pub(crate) fn new(
        data: Vec<u8>,
        os_ipc_channels: Vec<OsOpaqueIpcChannel>,
        os_ipc_shared_memory_regions: Vec<OsIpcSharedMemory>,
    ) -> IpcMessage {
        IpcMessage {
            data,
            os_ipc_channels,
            os_ipc_shared_memory_regions,
        }
    }

    /// Deserialize the raw data in the contained message into the inferred type.
    pub fn to<T: Decode>(self) -> Result<T, DecodeError> {
        let os_ipc_shared_memory_regions = self
            .os_ipc_shared_memory_regions
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let archived = rkyv::access::<T::Archived, rkyv::rancor::BoxedError>(&self.data[..])?;
        let t = rkyv::api::deserialize_using::<T, _, rkyv::rancor::BoxedError>(
            archived,
            &mut CustomDeserializer {
                deserializer: Pool::new(),
                channels: self.os_ipc_channels,
                shared_memory_regions: os_ipc_shared_memory_regions,
            },
        )?;
        Ok(t)
    }
}

#[derive(Clone, Debug)]
pub struct OpaqueIpcSender {
    os_sender: OsIpcSender,
}

impl OpaqueIpcSender {
    pub fn to<T>(self) -> IpcSender<T> {
        IpcSender {
            os_sender: self.os_sender,
            phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct OpaqueIpcReceiver {
    os_receiver: OsIpcReceiver,
}

impl OpaqueIpcReceiver {
    pub fn to<'de, T>(self) -> IpcReceiver<T> {
        IpcReceiver {
            os_receiver: self.os_receiver,
            phantom: PhantomData,
        }
    }
}

/// A server associated with a given name. The server is "one-shot" because
/// it accepts only one connect request from a client.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```
/// use ipc_channel::ipc::{self, IpcOneShotServer, IpcSender, IpcReceiver};
///
/// let (server, server_name) = IpcOneShotServer::new().unwrap();
/// let tx: IpcSender<Vec<u8>> = IpcSender::connect(server_name).unwrap();
///
/// tx.send(&vec![0x10, 0x11, 0x12, 0x13]).unwrap();
/// let (_, data): (_, Vec<u8>) = server.accept().unwrap();
/// assert_eq!(data, vec![0x10, 0x11, 0x12, 0x13]);
/// ```
///
/// ## Sending an [IpcSender]
/// ```
/// use ipc_channel::ipc::{self, IpcOneShotServer, IpcSender, IpcReceiver};
/// let (server, name) = IpcOneShotServer::new().unwrap();
///
/// let (tx1, rx1): (IpcSender<Vec<u8>>, IpcReceiver<Vec<u8>>) = ipc::channel().unwrap();
/// let tx0 = IpcSender::connect(name).unwrap();
/// tx0.send(&tx1).unwrap();
///
/// let (_, tx1): (_, IpcSender<Vec<u8>>) = server.accept().unwrap();
/// tx1.send(&vec![0x48, 0x65, 0x6b, 0x6b, 0x6f, 0x00]).unwrap();
///
/// let data = rx1.recv().unwrap();
/// assert_eq!(data, vec![0x48, 0x65, 0x6b, 0x6b, 0x6f, 0x00]);
/// ```
/// [IpcSender]: struct.IpcSender.html
pub struct IpcOneShotServer<T> {
    os_server: OsIpcOneShotServer,
    phantom: PhantomData<T>,
}

impl<T> IpcOneShotServer<T>
where
    T: Decode + Encode,
{
    pub fn new() -> Result<(IpcOneShotServer<T>, String), io::Error> {
        let (os_server, name) = OsIpcOneShotServer::new()?;
        Ok((
            IpcOneShotServer {
                os_server,
                phantom: PhantomData,
            },
            name,
        ))
    }

    pub fn accept(self) -> Result<(IpcReceiver<T>, T), RecvError> {
        let (os_receiver, ipc_message) = self.os_server.accept()?;
        Ok((
            IpcReceiver {
                os_receiver,
                phantom: PhantomData,
            },
            ipc_message.to()?,
        ))
    }
}

/// Receiving end of a channel that does not used serialized messages.
#[derive(Debug)]
pub struct IpcBytesReceiver {
    os_receiver: OsIpcReceiver,
}

impl IpcBytesReceiver {
    /// Blocking receive.
    #[inline]
    pub fn recv(&self) -> Result<Vec<u8>, RecvError> {
        match self.os_receiver.recv() {
            Ok(ipc_message) => Ok(ipc_message.data),
            Err(err) => Err(err.into()),
        }
    }

    /// Non-blocking receive
    pub fn try_recv(&self) -> Result<Vec<u8>, TryRecvError> {
        match self.os_receiver.try_recv() {
            Ok(ipc_message) => Ok(ipc_message.data),
            Err(err) => Err(err.into()),
        }
    }
}

/// Sending end of a channel that does not used serialized messages.
#[derive(Debug)]
pub struct IpcBytesSender {
    os_sender: OsIpcSender,
}

impl Clone for IpcBytesSender {
    fn clone(&self) -> IpcBytesSender {
        IpcBytesSender {
            os_sender: self.os_sender.clone(),
        }
    }
}

impl IpcBytesSender {
    #[inline]
    pub fn send(&self, data: &[u8]) -> Result<(), io::Error> {
        self.os_sender
            .send(data, vec![], vec![])
            .map_err(io::Error::from)
    }
}

macro_rules! impl_archive {
	($T:ty, $Index:ident $(, <[$($generics:tt)+]>)?) => {
		#[derive(rkyv::Portable, bytecheck::CheckBytes)]
		#[repr(transparent)]
		pub struct $Index(rkyv::rend::u32_le);

		impl$(<$($generics)+>)? Archive for $T {
		    type Archived = $Index;

		    type Resolver = $Index;

		    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
		        unsafe { out.write_unchecked(resolver) };
		    }
		}
	}
}

macro_rules! impl_deserialize {
    ($T:ident, $Index:ident, $field:ident, $to_direction:ident) => {
        impl<D: rkyv::rancor::Fallible + ?Sized + CustomDeserializerTrait> Deserialize<$T, D>
            for $Index
        where
            D::Error: Source,
        {
            fn deserialize(&self, deserializer: &mut D) -> Result<$T, D::Error> {
                let channel = deserializer
                    .deserialize_channel(self.0.to_native())
                    .map_err(|e| <D::Error as Source>::new(e))?;
                Ok($T {
                    $field: channel.$to_direction(),
                })
            }
        }
    };
}

// real impls

impl_archive!(OsIpcReceiver, OsIpcReceiverIndex);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for OsIpcReceiver {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(OsIpcReceiverIndex(
            serializer.serialize_receiver(self).into(),
        ))
    }
}

impl_archive!(OsIpcSender, OsIpcSenderIndex);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for OsIpcSender {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(OsIpcSenderIndex(serializer.serialize_sender(self).into()))
    }
}

// derived impls

impl_archive!(OpaqueIpcReceiver, OpaqueIpcReceiverIndex);
impl_deserialize!(
    OpaqueIpcReceiver,
    OpaqueIpcReceiverIndex,
    os_receiver,
    into_receiver
);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S>
    for OpaqueIpcReceiver
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_receiver
            .serialize(serializer)
            .map(|i| OpaqueIpcReceiverIndex(i.0))
    }
}

impl_archive!(IpcBytesReceiver, IpcBytesReceiverIndex);
impl_deserialize!(
    IpcBytesReceiver,
    IpcBytesReceiverIndex,
    os_receiver,
    into_receiver
);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for IpcBytesReceiver {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_receiver
            .serialize(serializer)
            .map(|i| IpcBytesReceiverIndex(i.0))
    }
}

impl_archive!(IpcReceiver<T>, IpcReceiverIndex, <[T]>);

impl<T, S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S>
    for IpcReceiver<T>
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_receiver
            .serialize(serializer)
            .map(|i| IpcReceiverIndex(i.0))
    }
}

impl<T, D: rkyv::rancor::Fallible + ?Sized + CustomDeserializerTrait> Deserialize<IpcReceiver<T>, D>
    for IpcReceiverIndex
where
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IpcReceiver<T>, D::Error> {
        let channel = deserializer
            .deserialize_channel(self.0.to_native())
            .map_err(|e| <D::Error as Source>::new(e))?;
        Ok(IpcReceiver {
            os_receiver: channel.into_receiver(),
            phantom: PhantomData,
        })
    }
}

impl_archive!(OpaqueIpcSender, OpaqueIpcSenderIndex);
impl_deserialize!(
    OpaqueIpcSender,
    OpaqueIpcSenderIndex,
    os_sender,
    into_sender
);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for OpaqueIpcSender {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_sender
            .serialize(serializer)
            .map(|i| OpaqueIpcSenderIndex(i.0))
    }
}

impl_archive!(IpcBytesSender, IpcBytesSenderIndex);
impl_deserialize!(IpcBytesSender, IpcBytesSenderIndex, os_sender, into_sender);

impl<S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for IpcBytesSender {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_sender
            .serialize(serializer)
            .map(|i| IpcBytesSenderIndex(i.0))
    }
}

impl_archive!(IpcSender<T>, IpcSenderIndex, <[T]>);

impl<T, S: rkyv::rancor::Fallible + ?Sized + CustomSerializerTrait> Serialize<S> for IpcSender<T> {
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.os_sender
            .serialize(serializer)
            .map(|i| IpcSenderIndex(i.0))
    }
}

impl<T, D: rkyv::rancor::Fallible + ?Sized + CustomDeserializerTrait> Deserialize<IpcSender<T>, D>
    for IpcSenderIndex
where
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<IpcSender<T>, D::Error> {
        let channel = deserializer
            .deserialize_channel(self.0.to_native())
            .map_err(|e| <D::Error as Source>::new(e))?;
        Ok(IpcSender {
            os_sender: channel.into_sender(),
            phantom: PhantomData,
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum DeserializeChannelError {
    #[error("Channel index {index} out of bounds for channel count {len}")]
    IndexOutOfBounds { index: u32, len: usize },
}

#[derive(Debug, thiserror::Error)]
enum DeserializeSharedMemoryRegionError {
    #[error("Shared memory region index {index} out of bounds for region count {len}")]
    IndexOutOfBounds { index: u32, len: usize },
    #[error("Shared memory region at index {index} has already been consumed")]
    AlreadyConsumed { index: u32 },
}

trait CustomDeserializerTrait {
    fn deserialize_channel(
        &mut self,
        index: u32,
    ) -> Result<OsOpaqueIpcChannel, DeserializeChannelError>;

    fn deserialize_shared_memory_region(
        &mut self,
        index: u32,
    ) -> Result<OsIpcSharedMemory, DeserializeSharedMemoryRegionError>;
}

struct CustomDeserializer<D> {
    deserializer: D,
    channels: Vec<OsOpaqueIpcChannel>,
    shared_memory_regions: Vec<Option<OsIpcSharedMemory>>,
}

impl<D: rkyv::de::Pooling<E>, E> rkyv::de::Pooling<E> for CustomDeserializer<D> {
    fn start_pooling(&mut self, address: usize) -> rkyv::de::PoolingState {
        self.deserializer.start_pooling(address)
    }

    unsafe fn finish_pooling(
        &mut self,
        address: usize,
        ptr: rkyv::de::ErasedPtr,
        drop: unsafe fn(rkyv::de::ErasedPtr),
    ) -> Result<(), E> {
        unsafe { self.deserializer.finish_pooling(address, ptr, drop) }
    }
}

impl<D> CustomDeserializerTrait for CustomDeserializer<D> {
    fn deserialize_channel(
        &mut self,
        index: u32,
    ) -> Result<OsOpaqueIpcChannel, DeserializeChannelError> {
        let index_usize: usize =
            index
                .try_into()
                .map_err(|_| DeserializeChannelError::IndexOutOfBounds {
                    index,
                    len: self.channels.len(),
                })?;
        match self.channels.get_mut(index_usize) {
            Some(t) => Ok(t.consume()),
            None => Err(DeserializeChannelError::IndexOutOfBounds {
                index,
                len: self.channels.len(),
            }),
        }
    }

    fn deserialize_shared_memory_region(
        &mut self,
        index: u32,
    ) -> Result<OsIpcSharedMemory, DeserializeSharedMemoryRegionError> {
        assert_ne!(index, u32::MAX);
        let index_usize: usize =
            index
                .try_into()
                .map_err(|_| DeserializeSharedMemoryRegionError::IndexOutOfBounds {
                    index,
                    len: self.channels.len(),
                })?;
        match self.shared_memory_regions.get_mut(index_usize) {
            Some(t) => Ok(t
                .take()
                .ok_or(DeserializeSharedMemoryRegionError::AlreadyConsumed { index })?),
            None => Err(DeserializeSharedMemoryRegionError::IndexOutOfBounds {
                index,
                len: self.channels.len(),
            }),
        }
    }
}

impl<S: CustomDeserializerTrait, E> CustomDeserializerTrait for Strategy<S, E> {
    fn deserialize_channel(
        &mut self,
        index: u32,
    ) -> Result<OsOpaqueIpcChannel, DeserializeChannelError> {
        (**self).deserialize_channel(index)
    }

    fn deserialize_shared_memory_region(
        &mut self,
        index: u32,
    ) -> Result<OsIpcSharedMemory, DeserializeSharedMemoryRegionError> {
        (**self).deserialize_shared_memory_region(index)
    }
}

trait CustomSerializerTrait {
    fn serialize_receiver(&mut self, channel: &OsIpcReceiver) -> u32;
    fn serialize_sender(&mut self, channel: &OsIpcSender) -> u32;

    fn serialize_shared_memory_region(&mut self, shared_memory_region: &OsIpcSharedMemory) -> u32;
}

#[derive(Debug, Default)]
struct CountingCustomSerializer<S> {
    serializer: S,
    channels: u32,
    shared_memory_regions: u32,
}

impl<S> CustomSerializerTrait for CountingCustomSerializer<S> {
    fn serialize_receiver(&mut self, _: &OsIpcReceiver) -> u32 {
        let i = self.channels;
        self.channels += 1;
        i
    }

    fn serialize_sender(&mut self, _: &OsIpcSender) -> u32 {
        let i = self.channels;
        self.channels += 1;
        i
    }

    fn serialize_shared_memory_region(&mut self, _: &OsIpcSharedMemory) -> u32 {
        let i = self.shared_memory_regions;
        self.shared_memory_regions += 1;
        i
    }
}

unsafe impl<S: rkyv::ser::Allocator<E>, E> rkyv::ser::Allocator<E> for CountingCustomSerializer<S> {
    unsafe fn push_alloc(
        &mut self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, E> {
        unsafe { self.serializer.push_alloc(layout) }
    }

    unsafe fn pop_alloc(
        &mut self,
        ptr: std::ptr::NonNull<u8>,
        layout: std::alloc::Layout,
    ) -> Result<(), E> {
        unsafe { self.serializer.pop_alloc(ptr, layout) }
    }
}

impl<S: rkyv::ser::Positional> rkyv::ser::Positional for CountingCustomSerializer<S> {
    fn pos(&self) -> usize {
        self.serializer.pos()
    }
}

impl<S: rkyv::ser::Writer<E>, E> rkyv::ser::Writer<E> for CountingCustomSerializer<S> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), E> {
        self.serializer.write(bytes)
    }
}

impl<S: rkyv::ser::Sharing<E>, E> rkyv::ser::Sharing<E> for CountingCustomSerializer<S> {
    fn start_sharing(&mut self, address: usize) -> rkyv::ser::sharing::SharingState {
        self.serializer.start_sharing(address)
    }

    fn finish_sharing(&mut self, address: usize, pos: usize) -> Result<(), E> {
        self.serializer.finish_sharing(address, pos)
    }
}

#[derive(Default)]
struct CustomSerializer<S> {
    serializer: S,
    channels: Vec<OsIpcChannel>,
    shared_memory_regions: Vec<OsIpcSharedMemory>,
}

impl<S> CustomSerializer<S> {
    pub fn new(serializer: S) -> Self {
        Self {
            serializer,
            // TODO: reuse buffers
            channels: Vec::new(),
            shared_memory_regions: Vec::new(),
        }
    }
}

impl<S> CustomSerializerTrait for CustomSerializer<S> {
    fn serialize_receiver(&mut self, receiver: &OsIpcReceiver) -> u32 {
        let i = self.channels.len();
        assert_ne!(
            self.channels.capacity(),
            self.channels.len(),
            "Invalid call to serialize_channel"
        );
        self.channels
            .push(OsIpcChannel::Receiver(receiver.consume()));
        i.try_into().unwrap()
    }

    fn serialize_sender(&mut self, sender: &OsIpcSender) -> u32 {
        let i = self.channels.len();
        assert_ne!(
            self.channels.capacity(),
            self.channels.len(),
            "Invalid call to serialize_channel"
        );
        self.channels.push(OsIpcChannel::Sender(sender.clone()));
        i.try_into().unwrap()
    }

    fn serialize_shared_memory_region(&mut self, shared_memory_region: &OsIpcSharedMemory) -> u32 {
        let i = self.shared_memory_regions.len();
        assert_ne!(
            self.shared_memory_regions.capacity(),
            self.shared_memory_regions.len(),
            "Invalid call to serialize_shared_memory_region"
        );
        self.shared_memory_regions
            .push(shared_memory_region.clone());
        i.try_into().unwrap()
    }
}

unsafe impl<S: rkyv::ser::Allocator<E>, E> rkyv::ser::Allocator<E> for CustomSerializer<S> {
    unsafe fn push_alloc(
        &mut self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, E> {
        unsafe { self.serializer.push_alloc(layout) }
    }

    unsafe fn pop_alloc(
        &mut self,
        ptr: std::ptr::NonNull<u8>,
        layout: std::alloc::Layout,
    ) -> Result<(), E> {
        unsafe { self.serializer.pop_alloc(ptr, layout) }
    }
}

impl<S: rkyv::ser::Positional> rkyv::ser::Positional for CustomSerializer<S> {
    fn pos(&self) -> usize {
        self.serializer.pos()
    }
}

impl<S: rkyv::ser::Writer<E>, E> rkyv::ser::Writer<E> for CustomSerializer<S> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), E> {
        self.serializer.write(bytes)
    }
}

impl<S: rkyv::ser::Sharing<E>, E> rkyv::ser::Sharing<E> for CustomSerializer<S> {
    fn start_sharing(&mut self, address: usize) -> rkyv::ser::sharing::SharingState {
        self.serializer.start_sharing(address)
    }

    fn finish_sharing(&mut self, address: usize, pos: usize) -> Result<(), E> {
        self.serializer.finish_sharing(address, pos)
    }
}

impl<S: CustomSerializerTrait, E> CustomSerializerTrait for Strategy<S, E> {
    fn serialize_receiver(&mut self, channel: &OsIpcReceiver) -> u32 {
        (**self).serialize_receiver(channel)
    }

    fn serialize_sender(&mut self, channel: &OsIpcSender) -> u32 {
        (**self).serialize_sender(channel)
    }

    fn serialize_shared_memory_region(&mut self, region: &OsIpcSharedMemory) -> u32 {
        (**self).serialize_shared_memory_region(region)
    }
}
