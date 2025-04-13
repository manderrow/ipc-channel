// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(
    all(
        not(feature = "force-inprocess"),
        any(
            target_os = "linux",
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "illumos",
        )
    ),
    rust_analyzer
))]
mod unix;
#[cfg(all(
    not(feature = "force-inprocess"),
    any(
        target_os = "linux",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "illumos",
    )
))]
mod os {
    pub use super::unix::*;

    pub use UnixError as OsError;
}

#[cfg(any(
    all(not(feature = "force-inprocess"), target_os = "macos"),
    rust_analyzer
))]
mod macos;
#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
mod os {
    pub use super::macos::*;

    pub use MachError as OsError;
}

#[cfg(any(
    all(not(feature = "force-inprocess"), target_os = "windows"),
    rust_analyzer
))]
mod windows;
#[cfg(all(not(feature = "force-inprocess"), target_os = "windows"))]
mod os {
    pub use super::windows::*;

    pub use WindowsError as OsError;
}

#[cfg(any(
    feature = "force-inprocess",
    target_os = "android",
    target_os = "ios",
    target_os = "wasi",
    target_os = "unknown"
))]
mod inprocess;
#[cfg(any(
    feature = "force-inprocess",
    target_os = "android",
    target_os = "ios",
    target_os = "wasi",
    target_os = "unknown"
))]
mod os {
    pub use super::inprocess::*;

    pub use super::ChannelError as OsError;
}

pub use self::os::{
    OsError, OsIpcChannel, OsIpcOneShotServer, OsIpcReceiver, OsIpcReceiverSet,
    OsIpcSelectionResult, OsIpcSender, OsIpcSharedMemory, OsOpaqueIpcChannel, channel,
};

#[cfg(test)]
mod test;
