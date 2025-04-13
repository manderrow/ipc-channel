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

use bincode::{BorrowDecode, Decode, Encode};
use std::cell::RefCell;
use std::cmp::min;
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::marker::PhantomData;
use std::ops::Deref;
use std::time::Duration;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

enum SerContext {
    Size {
        channels: usize,
        shared_memory_regions: usize,
    },
    Encode {
        channels: Vec<OsIpcChannel>,
        shared_memory_regions: Vec<OsIpcSharedMemory>,
    },
}

impl SerContext {
    const DEFAULT_SIZE: Self = Self::Size {
        channels: 0,
        shared_memory_regions: 0,
    };

    const DEFAULT_ENCODE: Self = Self::Encode {
        channels: Vec::new(),
        shared_memory_regions: Vec::new(),
    };
}

thread_local! {
    static SER_CONTEXT: RefCell<SerContext> = const { RefCell::new(SerContext::DEFAULT_SIZE) }
}

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
/// tx.send(payload).unwrap();
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
    T: Decode<Context> + Encode,
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
/// # tx.send(q.to_owned()).unwrap();
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
/// # tx.send(answer.to_owned()).unwrap();
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
/// tx.send(embedded_rx).unwrap();
/// # embedded_tx.send(data.to_owned()).unwrap();
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
    T: Decode<Context>,
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

impl<T> Decode<Context> for IpcReceiver<T> {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_receiver = deserialize_os_ipc_receiver(decoder)?;
        Ok(Self {
            os_receiver,
            phantom: PhantomData,
        })
    }
}

impl<'de, T> BorrowDecode<'de, Context> for IpcReceiver<T> {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl<T> Encode for IpcReceiver<T> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_receiver(&self.os_receiver, encoder)
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
/// tx.send(embedded_tx).unwrap();
/// // Receive the sent IpcSender
/// let received_tx = rx.recv().unwrap();
/// // Send data from the received IpcSender
/// received_tx.send(data.clone()).unwrap();
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
    T: bincode::enc::Encode,
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
    pub fn send(&self, data: T) -> Result<(), SendError> {
        SER_CONTEXT.with(|context| {
            let old_context = context.replace(SerContext::DEFAULT_SIZE);
            let size = {
                let mut size_writer = bincode::enc::write::SizeWriter::default();
                bincode::encode_into_writer(&data, &mut size_writer, BINCODE_CONFIG)?;
                size_writer.bytes_written
            };
            _ = context.replace(SerContext::DEFAULT_ENCODE);
            let mut bytes = Vec::with_capacity(size);
            bincode::encode_into_std_write(&data, &mut bytes, BINCODE_CONFIG)?;
            let SerContext::Encode {
                channels,
                shared_memory_regions,
            } = context.replace(old_context)
            else {
                unreachable!()
            };
            Ok(self
                .os_sender
                .send(&bytes[..], channels, shared_memory_regions)?)
        })
    }

    pub fn to_opaque(self) -> OpaqueIpcSender {
        OpaqueIpcSender {
            os_sender: self.os_sender,
        }
    }
}

impl<'de, T> Decode<Context> for IpcSender<T> {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_sender = deserialize_os_ipc_sender(decoder)?;
        Ok(Self {
            os_sender,
            phantom: PhantomData,
        })
    }
}

impl<'de, T> BorrowDecode<'de, Context> for IpcSender<T> {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl<T> Encode for IpcSender<T> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_sender(&self.os_sender, encoder)
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
/// tx.send(data.clone()).unwrap();
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
/// tx.send(shmem.clone()).unwrap();
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

impl<'de> Decode<Context> for IpcSharedMemory {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let index: usize = Decode::decode(decoder)?;
        if index == usize::MAX {
            return Ok(IpcSharedMemory::empty());
        }

        let os_shared_memory = decoder
            .context()
            .os_ipc_shared_memory_regions
            .get_mut(index)
            .ok_or_else(|| {
                bincode::error::DecodeError::Other("OsIpcSharedMemory index out of bounds")
            })?
            .take()
            .ok_or_else(|| {
                bincode::error::DecodeError::Other("OsIpcSharedMemory index already used")
            })?;
        Ok(IpcSharedMemory {
            os_shared_memory: Some(os_shared_memory),
        })
    }
}

impl<'de> BorrowDecode<'de, Context> for IpcSharedMemory {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl Encode for IpcSharedMemory {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        if let Some(os_shared_memory) = &self.os_shared_memory {
            let index = SER_CONTEXT.with(|context| {
                let mut context = context.borrow_mut();
                match &mut *context {
                    SerContext::Size {
                        shared_memory_regions,
                        ..
                    } => {
                        let index = *shared_memory_regions;
                        *shared_memory_regions += 1;
                        index
                    },
                    SerContext::Encode {
                        shared_memory_regions,
                        ..
                    } => {
                        let index = shared_memory_regions.len();
                        shared_memory_regions.push(os_shared_memory.clone());
                        index
                    },
                }
            });
            debug_assert!(index < usize::MAX);
            index
        } else {
            usize::MAX
        }
        .encode(encoder)
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

impl IpcSelectionResult {
    /// Helper method to move the value out of the [IpcSelectionResult] if it
    /// is [MessageReceived].
    ///
    /// # Panics
    ///
    /// If the result is [ChannelClosed] this call will panic.
    ///
    /// [IpcSelectionResult]: enum.IpcSelectionResult.html
    /// [MessageReceived]: enum.IpcSelectionResult.html#variant.MessageReceived
    /// [ChannelClosed]: enum.IpcSelectionResult.html#variant.ChannelClosed
    pub fn unwrap(self) -> (u64, IpcMessage) {
        match self {
            IpcSelectionResult::MessageReceived(id, message) => (id, message),
            IpcSelectionResult::ChannelClosed(id) => {
                panic!("IpcSelectionResult::unwrap(): channel {} closed", id)
            },
        }
    }
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
    pub fn to<T>(self) -> Result<T, DecodeError>
    where
        T: Decode<Context>,
    {
        let os_ipc_shared_memory_regions = self
            .os_ipc_shared_memory_regions
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let result = bincode::decode_from_slice_with_context(
            &self.data[..],
            BINCODE_CONFIG,
            Context {
                os_ipc_channels: self.os_ipc_channels,
                os_ipc_shared_memory_regions: os_ipc_shared_memory_regions,
            },
        );
        /* Error check comes after doing cleanup,
         * since we need the cleanup both in the success and the error cases. */
        let (t, n) = result?;
        if n != self.data.len() {
            return Err(DecodeError::TrailingBytes);
        }
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

impl<'de> Decode<Context> for OpaqueIpcSender {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_sender = deserialize_os_ipc_sender(decoder)?;
        Ok(Self { os_sender })
    }
}

impl<'de> BorrowDecode<'de, Context> for OpaqueIpcSender {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl Encode for OpaqueIpcSender {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_sender(&self.os_sender, encoder)
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

impl<'de> Decode<Context> for OpaqueIpcReceiver {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_receiver = deserialize_os_ipc_receiver(decoder)?;
        Ok(Self { os_receiver })
    }
}

impl<'de> BorrowDecode<'de, Context> for OpaqueIpcReceiver {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl Encode for OpaqueIpcReceiver {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_receiver(&self.os_receiver, encoder)
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
/// tx.send(vec![0x10, 0x11, 0x12, 0x13]).unwrap();
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
/// tx0.send(tx1).unwrap();
///
/// let (_, tx1): (_, IpcSender<Vec<u8>>) = server.accept().unwrap();
/// tx1.send(vec![0x48, 0x65, 0x6b, 0x6b, 0x6f, 0x00]).unwrap();
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
    T: Decode<Context> + Encode,
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

impl<'de> Decode<Context> for IpcBytesReceiver {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_receiver = deserialize_os_ipc_receiver(decoder)?;
        Ok(IpcBytesReceiver { os_receiver })
    }
}

impl<'de> BorrowDecode<'de, Context> for IpcBytesReceiver {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl Encode for IpcBytesReceiver {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_receiver(&self.os_receiver, encoder)
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

impl<'de> Decode<Context> for IpcBytesSender {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let os_sender = deserialize_os_ipc_sender(decoder)?;
        Ok(Self { os_sender })
    }
}

impl<'de> BorrowDecode<'de, Context> for IpcBytesSender {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Self::decode(decoder)
    }
}

impl Encode for IpcBytesSender {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        serialize_os_ipc_sender(&self.os_sender, encoder)
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

fn serialize_os_ipc_sender<S>(
    sender: &OsIpcSender,
    serializer: &mut S,
) -> Result<(), bincode::error::EncodeError>
where
    S: bincode::enc::Encoder,
{
    let index = SER_CONTEXT.with(|context| {
        let mut context = context.borrow_mut();
        match &mut *context {
            SerContext::Size { channels, .. } => {
                let index = *channels;
                *channels += 1;
                index
            },
            SerContext::Encode { channels, .. } => {
                let index = channels.len();
                channels.push(OsIpcChannel::Sender(sender.clone()));
                index
            },
        }
    });
    index.encode(serializer)
}

fn deserialize_os_ipc_sender<D>(
    deserializer: &mut D,
) -> Result<OsIpcSender, bincode::error::DecodeError>
where
    D: bincode::de::Decoder<Context = Context>,
{
    let index: usize = Decode::decode(deserializer)?;

    deserializer
        .context()
        .os_ipc_channels
        .get_mut(index)
        .ok_or_else(|| bincode::error::DecodeError::Other("OsIpcSender index out of bounds"))
        .map(|channel| channel.to_sender())
}

fn serialize_os_ipc_receiver<S>(
    receiver: &OsIpcReceiver,
    serializer: &mut S,
) -> Result<(), bincode::error::EncodeError>
where
    S: bincode::enc::Encoder,
{
    let index = SER_CONTEXT.with(|context| {
        let mut context = context.borrow_mut();
        match &mut *context {
            SerContext::Size { channels, .. } => {
                let index = *channels;
                *channels += 1;
                index
            },
            SerContext::Encode { channels, .. } => {
                let index = channels.len();
                channels.push(OsIpcChannel::Receiver(receiver.consume()));
                index
            },
        }
    });
    index.encode(serializer)
}

fn deserialize_os_ipc_receiver<D>(
    deserializer: &mut D,
) -> Result<OsIpcReceiver, bincode::error::DecodeError>
where
    D: bincode::de::Decoder<Context = Context>,
{
    let index: usize = Decode::decode(deserializer)?;

    deserializer
        .context()
        .os_ipc_channels
        .get_mut(index)
        .ok_or_else(|| bincode::error::DecodeError::Other("OsIpcReceiver index out of bounds"))
        .map(|channel| channel.to_receiver())
}
