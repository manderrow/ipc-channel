use std::error::Error as StdError;
use std::{fmt, io};

pub use crate::platform::OsError;

#[derive(Debug)]
pub enum DecodeError {
    Rkyv(rkyv::rancor::BoxedError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Rkyv(ref err) => write!(fmt, "rkyv error: {err}"),
        }
    }
}

impl StdError for DecodeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Rkyv(ref err) => Some(err),
        }
    }
}

impl From<rkyv::rancor::BoxedError> for DecodeError {
    fn from(value: rkyv::rancor::BoxedError) -> Self {
        Self::Rkyv(value)
    }
}

#[derive(Debug)]
pub enum RecvError {
    Rkyv(rkyv::rancor::BoxedError),
    Io(io::Error),
    Os(OsError),
    Disconnected,
}

impl fmt::Display for RecvError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Rkyv(ref err) => write!(fmt, "rkyv error: {err}"),
            Self::Io(ref err) => write!(fmt, "io error: {err}"),
            Self::Os(ref err) => write!(fmt, "os error: {err}"),
            Self::Disconnected => write!(fmt, "disconnected"),
        }
    }
}

impl StdError for RecvError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Rkyv(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
            Self::Os(ref err) => Some(err),
            Self::Disconnected => None,
        }
    }
}

impl From<rkyv::rancor::BoxedError> for RecvError {
    fn from(value: rkyv::rancor::BoxedError) -> Self {
        Self::Rkyv(value)
    }
}

impl From<DecodeError> for RecvError {
    fn from(value: DecodeError) -> Self {
        match value {
            DecodeError::Rkyv(err) => Self::Rkyv(err),
        }
    }
}

impl From<OsError> for RecvError {
    fn from(value: OsError) -> Self {
        #[cfg(target_os = "macos")]
        {
            if matches!(value, OsError::NotifyNoSenders) {
                return Self::Disconnected;
            }
        }
        #[cfg(any(
            target_os = "linux",
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "illumos",
        ))]
        {
            if matches!(value, OsError::ChannelClosed) {
                return Self::Disconnected;
            }
        }
        #[cfg(windows)]
        {
            if matches!(value, OsError::ChannelClosed) {
                return Self::Disconnected;
            }
        }
        Self::Os(value)
    }
}

#[derive(Debug)]
pub enum TryRecvError {
    Recv(RecvError),
    Empty,
}

impl fmt::Display for TryRecvError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Recv(ref err) => write!(fmt, "ipc error: {err}"),
            Self::Empty => write!(fmt, "empty"),
        }
    }
}

impl StdError for TryRecvError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Recv(ref err) => Some(err),
            Self::Empty => None,
        }
    }
}

impl From<OsError> for TryRecvError {
    fn from(value: OsError) -> Self {
        #[cfg(target_os = "macos")]
        {
            if matches!(value, OsError::RcvTimedOut) {
                return Self::Empty;
            }
        }
        #[cfg(any(
            target_os = "linux",
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "illumos",
            all(windows, feature = "unix-on-wine"),
        ))]
        {
            if matches!(value, OsError::Empty) {
                return Self::Empty;
            }
        }
        #[cfg(all(windows, not(feature = "unix-on-wine")))]
        {
            if matches!(value, OsError::NoData) {
                return Self::Empty;
            }
        }
        Self::Recv(value.into())
    }
}

#[derive(Debug)]
pub enum SendError {
    Rkyv(rkyv::rancor::BoxedError),
    Io(io::Error),
    Os(crate::platform::OsError),
    Disconnected,
}

impl fmt::Display for SendError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Rkyv(ref err) => write!(fmt, "rkyv error: {err}"),
            Self::Io(ref err) => write!(fmt, "io error: {err}"),
            Self::Os(ref err) => write!(fmt, "os error: {err}"),
            Self::Disconnected => write!(fmt, "disconnected"),
        }
    }
}

impl StdError for SendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Rkyv(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
            Self::Os(ref err) => Some(err),
            Self::Disconnected => None,
        }
    }
}

impl From<rkyv::rancor::BoxedError> for SendError {
    fn from(value: rkyv::rancor::BoxedError) -> Self {
        Self::Rkyv(value)
    }
}

impl From<crate::platform::OsError> for SendError {
    fn from(value: crate::platform::OsError) -> Self {
        #[cfg(target_os = "macos")]
        {
            if matches!(value, crate::platform::OsError::NotifyNoSenders) {
                return Self::Disconnected;
            }
        }
        Self::Os(value)
    }
}
