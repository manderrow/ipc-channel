use std::error::Error as StdError;
use std::{fmt, io};

pub use crate::platform::OsError;

#[derive(Debug)]
pub enum DecodeError {
    Bincode(bincode::error::DecodeError),
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Bincode(ref err) => write!(fmt, "bincode error: {}", err),
            Self::TrailingBytes => write!(fmt, "trailing bytes"),
        }
    }
}

impl StdError for DecodeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Bincode(ref err) => Some(err),
            Self::TrailingBytes => None,
        }
    }
}

impl From<bincode::error::DecodeError> for DecodeError {
    fn from(value: bincode::error::DecodeError) -> Self {
        Self::Bincode(value)
    }
}

#[derive(Debug)]
pub enum RecvError {
    Bincode(bincode::error::DecodeError),
    TrailingBytes,
    Io(io::Error),
    Os(OsError),
    Disconnected,
}

impl fmt::Display for RecvError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Bincode(ref err) => write!(fmt, "bincode error: {}", err),
            Self::TrailingBytes => write!(fmt, "trailing bytes"),
            Self::Io(ref err) => write!(fmt, "io error: {}", err),
            Self::Os(ref err) => write!(fmt, "os error: {}", err),
            Self::Disconnected => write!(fmt, "disconnected"),
        }
    }
}

impl StdError for RecvError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Bincode(ref err) => Some(err),
            Self::TrailingBytes => None,
            Self::Io(ref err) => Some(err),
            Self::Os(ref err) => Some(err),
            Self::Disconnected => None,
        }
    }
}

impl From<bincode::error::DecodeError> for RecvError {
    fn from(value: bincode::error::DecodeError) -> Self {
        Self::Bincode(value)
    }
}

impl From<DecodeError> for RecvError {
    fn from(value: DecodeError) -> Self {
        match value {
            DecodeError::Bincode(err) => Self::Bincode(err),
            DecodeError::TrailingBytes => Self::TrailingBytes,
        }
    }
}

impl From<OsError> for RecvError {
    fn from(value: OsError) -> Self {
        #[cfg(not(feature = "force-inprocess"))]
        {
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
            Self::Recv(ref err) => write!(fmt, "ipc error: {}", err),
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
        #[cfg(not(feature = "force-inprocess"))]
        {
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
            ))]
            {
                if matches!(value, OsError::Empty) {
                    return Self::Empty;
                }
            }
            #[cfg(windows)]
            {
                if matches!(value, OsError::NoData) {
                    return Self::Empty;
                }
            }
        }
        Self::Recv(value.into())
    }
}

#[derive(Debug)]
pub enum SendError {
    Bincode(bincode::error::EncodeError),
    Io(io::Error),
    Os(crate::platform::OsError),
    Disconnected,
}

impl fmt::Display for SendError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Bincode(ref err) => write!(fmt, "bincode error: {}", err),
            Self::Io(ref err) => write!(fmt, "io error: {}", err),
            Self::Os(ref err) => write!(fmt, "os error: {}", err),
            Self::Disconnected => write!(fmt, "disconnected"),
        }
    }
}

impl StdError for SendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Self::Bincode(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
            Self::Os(ref err) => Some(err),
            Self::Disconnected => None,
        }
    }
}

impl From<bincode::error::EncodeError> for SendError {
    fn from(value: bincode::error::EncodeError) -> Self {
        Self::Bincode(value)
    }
}

impl From<crate::platform::OsError> for SendError {
    fn from(value: crate::platform::OsError) -> Self {
        #[cfg(not(feature = "force-inprocess"))]
        {
            #[cfg(target_os = "macos")]
            {
                if matches!(value, crate::platform::OsError::NotifyNoSenders) {
                    return Self::Disconnected;
                }
            }
        }
        Self::Os(value)
    }
}
