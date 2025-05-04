// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(
    target_os = "linux",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "illumos",
    all(windows, feature = "unix-on-wine"),
    rust_analyzer
))]
mod unix;
#[cfg(any(
    target_os = "linux",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "illumos",
    all(windows, feature = "unix-on-wine"),
))]
mod os {
    pub use super::unix::*;

    pub use UnixError as OsError;
}

#[cfg(any(target_os = "macos", rust_analyzer))]
mod macos;
#[cfg(target_os = "macos")]
mod os {
    pub use super::macos::*;

    pub use MachError as OsError;
}

#[cfg(any(
    all(target_os = "windows", not(feature = "unix-on-wine")),
    rust_analyzer
))]
mod windows;
#[cfg(all(target_os = "windows", not(feature = "unix-on-wine")))]
mod os {
    pub use super::windows::*;

    pub use WinIpcError as OsError;
}

pub use os::{
    OsError, OsIpcChannel, OsIpcOneShotServer, OsIpcReceiver, OsIpcReceiverSet,
    OsIpcSelectionResult, OsIpcSender, OsIpcSharedMemory, OsOpaqueIpcChannel, channel,
};

#[cfg(test)]
mod test;
