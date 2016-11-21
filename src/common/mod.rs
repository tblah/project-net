//! Code common to both the server and the client
//!

/*  This file is part of project-net.
    project-net is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    project-net is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with project-net.  If not, see http://www.gnu.org/licenses/.*/

pub mod message; 
use std::io;
use std::io::Write;
use std::net::TcpStream;
use std::net::Shutdown;
use proj_crypto::asymmetric::{LongTermKeys, SessionKeys};

/// Errors returned by the client or server
#[derive(Debug)]
pub enum Error {
    Connect(io::Error),
    Bind(io::Error),
    Accept(io::Error),
    DeviceFirst(message::Error),
    ServerFirst(message::Error),
    DeviceSecond(message::Error),
    Sending(message::Error),
    Receiving(message::Error),
    BadMessageN,
}

/// state for both the client and server
pub struct ProtocolState {
    pub stream: TcpStream,
    pub long_keys: LongTermKeys,
    pub next_send_n: u16,
    pub next_recv_n: u16,
    pub session_keys: SessionKeys,
}

impl ProtocolState {
    fn next_message_number(&mut self) -> u16 {
        if self.next_send_n == u16::max_value() {
            let n = self.next_message_number();
            send_error(&mut self.stream, n);
            log("Panicked to prevent the message number from overflowing", LOG_RELEASE);
            panic!("Message number is about to overflow");
        }

        let ret = self.next_send_n;
        self.next_send_n += 1;
        ret
    }

    fn check_recv_number(&mut self, num: u16) -> bool {
        if self.next_recv_n != num {
            let n = self.next_message_number();
            send_error(&mut self.stream, n);
            log("Received an out of order message number", LOG_DEBUG);
            return false;
        }
        
        if self.next_recv_n == u16::max_value() {
            let n = self.next_message_number();
            send_error(&mut self.stream, n);
            log("Failing receive message number check because the counter is about to overflow", LOG_RELEASE);
            return false;
        }

        self.next_recv_n += 1;
        true
    }
}

/// Read for both the server and client
pub fn general_read(state: &mut ProtocolState, buf: &mut Vec<u8>, from_device: bool) -> io::Result<usize> {
    let m = {
        let ref symmetric_state = {
        if from_device {
                &state.session_keys.from_device
            } else {
                &state.session_keys.from_server
            }
        };

        let m = match message::receive::general(&mut state.stream, symmetric_state) {
            Ok(m) => m,
            Err(message_error) => {
                match message_error {
                    message::Error::Read(ioerror) => return Err(ioerror),
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "error receiving the message")),
                }
            }
        };
        m
    }; // some messing with scope so that state is no-longer borrowed by symmetric_state

    if !state.check_recv_number(m.number) {
        return Err(io::Error::new(io::ErrorKind::Other, "received the wrong message number"));
    }

    match m.content {
        message::MessageContent::Message(mut v) => {
            buf.append(&mut v);
            log("Received a message packet", LOG_DEBUG);
            return Ok(v.len());
        },
        _ => {
            log("Received unimplemented message!", LOG_RELEASE);
            return Ok(0);
        },
    }
}

/// Write for both server and client
pub fn general_write(state: &mut ProtocolState, buf: &[u8], from_device: bool) -> io::Result<usize> {
    if buf.len() > (u16::max_value() as usize) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "The buffer was too long for a single message packet. Splitting it is not yet implemented. Please keep to buf.len() <= u16::max_value()"));
    }

    let message_n = state.next_message_number();
    let ref symmetric_state = {
        if from_device {
            &state.session_keys.from_device
        } else {
            &state.session_keys.from_server
        }
    };

    match message::send::message(&mut state.stream, buf, symmetric_state, message_n) {
        None => (),
        Some(error) => {
            match error {
                message::Error::Write(ioerror) => return Err(ioerror),
                _ => return Err(io::Error::new(io::ErrorKind::Other, "error sending the message")),
            }
        }
    }

    log("Message sent successfully", LOG_DEBUG);
    return Ok(buf.len());
}

/// Log level guaranteed to be printed on debug builds
pub const LOG_DEBUG: u8 = 100;

/// Log level guaranteed to be printed on release builds
pub const LOG_RELEASE: u8 = 10;

const MIN_INCLUDED_LOG_LEVEL: u8 = LOG_DEBUG;

/// 0 = highest log level
pub fn log(msg: &str, level: u8) {
    if level <= MIN_INCLUDED_LOG_LEVEL {
        match io::stderr().write(&format!("{}\n",msg).as_bytes()) {
            Err(e) => panic!("Error writing to the log: {}", e),
            Ok(_) => (),
        }
    }
}

/// Send an error message
pub fn send_error(dest: &mut TcpStream, message_number: u16) -> bool {
    let ret = match message::send::error(dest, message_number) {
        Some(e) => {log(&format!("Error encountered when sending an error packet: {:?}", e), LOG_DEBUG); false},
        None => {log("Sent error packet", LOG_DEBUG); true },
    };

    dest.shutdown(Shutdown::Both).unwrap();

    ret
}

/// Check that a message number looks correct
pub fn check_message_n(next_n: &mut u16, m: &message::Message) -> bool {
    if m.number != *next_n {
        log(&format!("Expected message number = {}. Received message number {}. Aborting.", *next_n, m.number), LOG_DEBUG);
        return false;
    }

    if *next_n == u16::max_value() {
        log("next_n is going to overflow!", LOG_RELEASE);
        return false;
    }

    *next_n += 1;

    true
}

