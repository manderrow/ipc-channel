// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::error;
use crate::ipc::IpcReceiver;
use crate::ipc::{self, IpcReceiverSet, IpcSender, IpcSharedMemory};
use bincode::{Decode, Encode};
use std::cell::RefCell;
use std::env;
use std::process::{self, Command, Stdio};
use std::rc::Rc;

#[cfg(not(target_os = "windows"))]
use crate::ipc::IpcOneShotServer;

#[cfg(not(target_os = "windows"))]
use std::io::Error;
use std::time::{Duration, Instant};

#[cfg(not(target_os = "windows"))]
// I'm not actually sure invoking this is indeed unsafe -- but better safe than sorry...
pub unsafe fn fork<F: FnOnce()>(child_func: F) -> rustix::process::Pid {
    unsafe extern "C" {
        // don't pull in the whole libc dependency just for this one function
        fn fork() -> rustix::process::RawPid;
    }

    match unsafe { fork() } {
        ..-1 => unreachable!(),
        -1 => panic!("Fork failed: {}", Error::last_os_error()),
        0 => {
            child_func();
            std::process::exit(0);
        },
        pid => rustix::process::Pid::from_raw(pid).unwrap(),
    }
}

#[cfg(not(target_os = "windows",))]
pub trait Wait {
    fn wait(self);
}

#[cfg(not(target_os = "windows"))]
impl Wait for rustix::process::Pid {
    fn wait(self) {
        rustix::process::waitpid(Some(self), rustix::process::WaitOptions::empty()).unwrap();
    }
}

// Helper to get a channel_name argument passed in; used for the
// cross-process spawn server tests.
pub fn get_channel_name_arg(which: &str) -> Option<String> {
    for arg in env::args() {
        let arg_str = &*format!("channel_name-{}:", which);
        if let Some(arg) = arg.strip_prefix(arg_str) {
            return Some(arg.to_owned());
        }
    }
    None
}

// Helper to get a channel_name argument passed in; used for the
// cross-process spawn server tests.
pub fn spawn_server(test_name: &str, server_args: &[(&str, &str)]) -> process::Child {
    Command::new(env::current_exe().unwrap())
        .arg(test_name)
        .args(
            server_args
                .iter()
                .map(|(name, val)| format!("channel_name-{}:{}", name, val)),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to execute server process")
}

type Person = (String, u32);

#[test]
fn simple() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person.clone()).unwrap();
    let received_person = rx.recv().unwrap();
    assert_eq!(person, received_person);
    drop(tx);
    match rx.recv().unwrap_err() {
        error::RecvError::Disconnected => (),
        e => panic!("expected disconnected error, got {:?}", e),
    }
}

#[test]
fn embedded_senders() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (sub_tx, sub_rx) = ipc::channel().unwrap();
    let person_and_sender = (person.clone(), sub_tx);
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(person_and_sender).unwrap();
    let received_person_and_sender = super_rx.recv().unwrap();
    assert_eq!(received_person_and_sender.0, person);
    received_person_and_sender.1.send(person.clone()).unwrap();
    let received_person = sub_rx.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn embedded_receivers() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (sub_tx, sub_rx) = ipc::channel().unwrap();
    let person_and_receiver = (person.clone(), sub_rx);
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(person_and_receiver).unwrap();
    let received_person_and_receiver = super_rx.recv().unwrap();
    assert_eq!(received_person_and_receiver.0, person);
    sub_tx.send(person.clone()).unwrap();
    let received_person = received_person_and_receiver.1.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn select() {
    let (tx0, rx0) = ipc::channel().unwrap();
    let (tx1, rx1) = ipc::channel().unwrap();
    let mut rx_set = IpcReceiverSet::new().unwrap();
    let rx0_id = rx_set.add(rx0).unwrap();
    let rx1_id = rx_set.add(rx1).unwrap();

    let person = ("Patrick Walton".to_owned(), 29);
    tx0.send(person.clone()).unwrap();
    let (received_id, received_data) = rx_set
        .select()
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .unwrap();
    let received_person: Person = received_data.to().unwrap();
    assert_eq!(received_id, rx0_id);
    assert_eq!(received_person, person);

    tx1.send(person.clone()).unwrap();
    let (received_id, received_data) = rx_set
        .select()
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .unwrap();
    let received_person: Person = received_data.to().unwrap();
    assert_eq!(received_id, rx1_id);
    assert_eq!(received_person, person);

    tx0.send(person.clone()).unwrap();
    tx1.send(person.clone()).unwrap();
    let (mut received0, mut received1) = (false, false);
    while !received0 || !received1 {
        for result in rx_set.select().unwrap().into_iter() {
            let (received_id, received_data) = result.unwrap();
            let received_person: Person = received_data.to().unwrap();
            assert_eq!(received_person, person);
            assert!(received_id == rx0_id || received_id == rx1_id);
            if received_id == rx0_id {
                assert!(!received0);
                received0 = true;
            } else if received_id == rx1_id {
                assert!(!received1);
                received1 = true;
            }
        }
    }
}

#[test]
fn cross_process_embedded_senders_spawn() {
    let person = ("Patrick Walton".to_owned(), 29);

    let server0_name = get_channel_name_arg("server0");
    let server2_name = get_channel_name_arg("server2");
    if let (Some(server0_name), Some(server2_name)) = (server0_name, server2_name) {
        let (tx1, rx1): (IpcSender<Person>, IpcReceiver<Person>) = ipc::channel().unwrap();
        let tx0 = IpcSender::connect(server0_name).unwrap();
        tx0.send(tx1).unwrap();
        rx1.recv().unwrap();
        let tx2: IpcSender<Person> = IpcSender::connect(server2_name).unwrap();
        tx2.send(person.clone()).unwrap();

        std::process::exit(0);
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn cross_process_embedded_senders_fork() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (server0, server0_name) = IpcOneShotServer::new().unwrap();
    let (server2, server2_name) = IpcOneShotServer::new().unwrap();
    let child_pid = unsafe {
        fork(|| {
            let (tx1, rx1): (IpcSender<Person>, IpcReceiver<Person>) = ipc::channel().unwrap();
            let tx0 = IpcSender::connect(server0_name).unwrap();
            tx0.send(tx1).unwrap();
            rx1.recv().unwrap();
            let tx2: IpcSender<Person> = IpcSender::connect(server2_name).unwrap();
            tx2.send(person.clone()).unwrap();
        })
    };
    let (_, tx1): (_, IpcSender<Person>) = server0.accept().unwrap();
    tx1.send(person.clone()).unwrap();
    let (_, received_person): (_, Person) = server2.accept().unwrap();
    child_pid.wait();
    assert_eq!(received_person, person);
}

#[test]
fn shared_memory() {
    let person = ("Patrick Walton".to_owned(), 29);
    let person_and_shared_memory = (person, IpcSharedMemory::from_byte(0xba, 1024 * 1024));
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person_and_shared_memory.clone()).unwrap();
    let received_person_and_shared_memory = rx.recv().unwrap();
    assert_eq!(
        received_person_and_shared_memory.0,
        person_and_shared_memory.0
    );
    assert!(person_and_shared_memory.1.iter().all(|byte| *byte == 0xba));
    assert!(
        received_person_and_shared_memory
            .1
            .iter()
            .all(|byte| *byte == 0xba)
    );
}

#[test]
fn shared_memory_slice() {
    let (tx, rx) = ipc::channel().unwrap();
    // test byte of size 0
    let shared_memory = IpcSharedMemory::from_byte(42, 0);
    tx.send(shared_memory.clone()).unwrap();
    let received_shared_memory = rx.recv().unwrap();
    assert_eq!(*received_shared_memory, *shared_memory);
    // test empty slice
    let shared_memory = IpcSharedMemory::from_bytes(&[]);
    tx.send(shared_memory.clone()).unwrap();
    let received_shared_memory = rx.recv().unwrap();
    assert_eq!(*received_shared_memory, *shared_memory);
    // test non-empty slice
    let shared_memory = IpcSharedMemory::from_bytes(&[4, 2, 42]);
    tx.send(shared_memory.clone()).unwrap();
    let received_shared_memory = rx.recv().unwrap();
    assert_eq!(*received_shared_memory, *shared_memory);
}

#[test]
fn shared_memory_object_equality() {
    let person = ("Patrick Walton".to_owned(), 29);
    let person_and_shared_memory = (person, IpcSharedMemory::from_byte(0xba, 1024 * 1024));
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person_and_shared_memory.clone()).unwrap();
    let received_person_and_shared_memory = rx.recv().unwrap();
    assert_eq!(received_person_and_shared_memory, person_and_shared_memory);
}

#[test]
fn opaque_sender() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (tx, rx) = ipc::channel().unwrap();
    let opaque_tx = tx.to_opaque();
    let tx: IpcSender<Person> = opaque_tx.to();
    tx.send(person.clone()).unwrap();
    let received_person = rx.recv().unwrap();
    assert_eq!(person, received_person);
}

#[test]
fn embedded_opaque_senders() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (sub_tx, sub_rx) = ipc::channel::<Person>().unwrap();
    let person_and_sender = (person.clone(), sub_tx.to_opaque());
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(person_and_sender).unwrap();
    let received_person_and_sender = super_rx.recv().unwrap();
    assert_eq!(received_person_and_sender.0, person);
    received_person_and_sender
        .1
        .to::<Person>()
        .send(person.clone())
        .unwrap();
    let received_person = sub_rx.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn try_recv() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (tx, rx) = ipc::channel().unwrap();
    match rx.try_recv() {
        Err(error::TryRecvError::Empty) => (),
        v => panic!("Expected empty channel err: {:?}", v),
    }
    tx.send(person.clone()).unwrap();
    let received_person = rx.try_recv().unwrap();
    assert_eq!(person, received_person);
    match rx.try_recv() {
        Err(error::TryRecvError::Empty) => (),
        v => panic!("Expected empty channel err: {:?}", v),
    }
    drop(tx);
    match rx.try_recv() {
        Err(error::TryRecvError::Recv(error::RecvError::Disconnected)) => (),
        v => panic!("Expected disconnected err: {:?}", v),
    }
}

#[test]
fn try_recv_timeout() {
    let person = ("Jacob Kiesel".to_owned(), 25);
    let (tx, rx) = ipc::channel().unwrap();
    let timeout = Duration::from_millis(1000);
    let start_recv = Instant::now();
    match rx.try_recv_timeout(timeout) {
        Err(error::TryRecvError::Empty) => {
            assert!(start_recv.elapsed() >= Duration::from_millis(500))
        },
        v => panic!("Expected empty channel err: {:?}", v),
    }
    tx.send(person.clone()).unwrap();
    let start_recv = Instant::now();
    let received_person = rx.try_recv_timeout(timeout).unwrap();
    assert!(start_recv.elapsed() < timeout);
    assert_eq!(person, received_person);
    let start_recv = Instant::now();
    match rx.try_recv_timeout(timeout) {
        Err(error::TryRecvError::Empty) => {
            assert!(start_recv.elapsed() >= Duration::from_millis(500))
        },
        v => panic!("Expected empty channel err: {:?}", v),
    }
    drop(tx);
    match rx.try_recv_timeout(timeout) {
        Err(error::TryRecvError::Recv(error::RecvError::Disconnected)) => (),
        v => panic!("Expected disconnected err: {:?}", v),
    }
}

#[test]
fn multiple_paths_to_a_sender() {
    let person = ("Patrick Walton".to_owned(), 29);
    let (sub_tx, sub_rx) = ipc::channel().unwrap();
    let person_and_sender = Rc::new((person.clone(), sub_tx));
    let send_data = vec![
        person_and_sender.clone(),
        person_and_sender.clone(),
        person_and_sender.clone(),
    ];
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(send_data).unwrap();
    let received_data = super_rx.recv().unwrap();
    assert_eq!(received_data[0].0, person);
    assert_eq!(received_data[1].0, person);
    assert_eq!(received_data[2].0, person);
    received_data[0].1.send(person.clone()).unwrap();
    let received_person = sub_rx.recv().unwrap();
    assert_eq!(received_person, person);
    received_data[1].1.send(person.clone()).unwrap();
    let received_person = sub_rx.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn bytes() {
    // N.B. We're using an odd number of bytes here to expose alignment issues.
    let bytes = [1, 2, 3, 4, 5, 6, 7];
    let (tx, rx) = ipc::bytes_channel().unwrap();
    tx.send(&bytes[..]).unwrap();
    let received_bytes = rx.recv().unwrap();
    assert_eq!(&bytes, &received_bytes[..]);
}

#[test]
fn embedded_bytes_receivers() {
    let (sub_tx, sub_rx) = ipc::bytes_channel().unwrap();
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(sub_tx).unwrap();
    let sub_tx = super_rx.recv().unwrap();
    let bytes = [1, 2, 3, 4, 5, 6, 7];
    sub_tx.send(&bytes[..]).unwrap();
    let received_bytes = sub_rx.recv().unwrap();
    assert_eq!(&bytes, &received_bytes[..]);
}

#[test]
fn test_so_linger() {
    let (sender, receiver) = ipc::channel().unwrap();
    sender.send(42).unwrap();
    drop(sender);
    let val = match receiver.recv() {
        Ok(val) => val,
        Err(e) => {
            panic!("err: `{:?}`", e);
        },
    };
    assert_eq!(val, 42);
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HasWeirdSerializer(Option<String>);

thread_local! { static WEIRD_CHANNEL: RefCell<Option<IpcSender<HasWeirdSerializer>>> = const { RefCell::new(None) } }

impl Encode for HasWeirdSerializer {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        if self.0.is_some() {
            WEIRD_CHANNEL.with(|chan| {
                chan.borrow()
                    .as_ref()
                    .unwrap()
                    .send(HasWeirdSerializer(None))
                    .unwrap();
            });
        }
        self.0.encode(encoder)
    }
}

impl<C> Decode<C> for HasWeirdSerializer {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(HasWeirdSerializer(Decode::decode(decoder)?))
    }
}

#[test]
#[ignore = "I don't want to support this"]
fn test_reentrant() {
    let null = HasWeirdSerializer(None);
    let hello = HasWeirdSerializer(Some(String::from("hello")));
    let (sender, receiver) = ipc::channel().unwrap();
    WEIRD_CHANNEL.with(|chan| {
        *chan.borrow_mut() = Some(sender.clone());
    });
    sender.send(hello.clone()).unwrap();
    assert_eq!(null, receiver.recv().unwrap());
    assert_eq!(hello, receiver.recv().unwrap());
    sender.send(null.clone()).unwrap();
    assert_eq!(null, receiver.recv().unwrap());
}

#[test]
fn clone_sender_after_receiver_dropped() {
    let (tx, rx) = ipc::channel::<u32>().unwrap();
    drop(rx);
    let _tx2 = tx.clone();
}

#[test]
fn transfer_closed_sender() {
    let (main_tx, main_rx) = ipc::channel().unwrap();
    let (transfer_tx, _) = ipc::channel::<()>().unwrap();
    assert!(main_tx.send(transfer_tx).is_ok());
    let _transferred_tx = main_rx.recv().unwrap();
}
