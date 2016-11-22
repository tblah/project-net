//! Server functionality

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

extern crate sodiumoxide;
use std::net;
use proj_crypto::asymmetric::LongTermKeys;
use super::common::*;
use super::common::message::{receive, send, MessageContent};
use std::io;
use std::time::Duration;
use std::net::Shutdown;

/// Encapsulates ProtocolState to allow server to have it's own trait implementations
pub struct Server {
    state: ProtocolState,
    read_buff: Vec<u8>,
}

/// creates a new Server and performs a key exchange
pub fn start(socket_addr: &str, long_keys: LongTermKeys) -> Result<Server ,Error> {
    sodiumoxide::init();
    let listener = match net::TcpListener::bind(socket_addr) {
        Err(e) => {
            log(&format!("Error starting the server: {}", e), LOG_RELEASE);
            return Err(Error::Bind(e)); },
        Ok(s) => {
            log(&format!("Server bound to {}", socket_addr), LOG_DEBUG);
            s },
    };

    // wait for a connection
    let mut stream = match listener.accept() {
        Err(e) => {
            log("Error listening for a connection", LOG_RELEASE);
            return Err(Error::Accept(e)); },
        Ok((s, _)) => s,
    };

    log("Got connection!", LOG_DEBUG);

    // do key exchange
    let mut expected_next_n: u16 = 0;

    let m = match receive::receive_device_first(&mut stream) {
        Err(e) => {
            log(&format!("Error receiving first message: {:?}", e), LOG_RELEASE);
            send_error(&mut stream, 0);
            stream.shutdown(Shutdown::Both).unwrap();
            return Err(Error::DeviceFirst(e)); },
        Ok(m) => m,
    };

    if !check_message_n(&mut expected_next_n, &m) {
        send_error(&mut stream, 0);
        stream.shutdown(Shutdown::Both).unwrap();
        return Err(Error::BadMessageN);
    }

    // was it a DeviceFirst message?
    let device_ephemeral_pk = match m.content {
        MessageContent::DeviceFirst(pk) => pk,
        _ => { send_error(&mut stream, 0);
               stream.shutdown(Shutdown::Both).unwrap();
               return Err(Error::DeviceFirst(message::Error::InvalidOpcode)); },
    };

    log("device_first received successfully", LOG_DEBUG);

    // send response
    let (session_keys, challenge) = match send::server_first(&mut stream, &long_keys, &device_ephemeral_pk) {
        Err(e) => {
            log("Error sending server_first", LOG_RELEASE);
            return Err(Error::ServerFirst(e)); },
        Ok((k, c)) => (k, c)
    };

    log("server_first sent successfully", LOG_DEBUG);

    // receive challenge response
    let device_second = match receive::device_second(&mut stream, &session_keys, &challenge) {
        Err(e) => {
            log("Error validating device response", LOG_RELEASE);
            send_error(&mut stream, 1);
            stream.shutdown(Shutdown::Both).unwrap();
            return Err(Error::DeviceSecond(e)); },
        Ok(m) => m,
    };

    if !check_message_n(&mut expected_next_n, &device_second) {
        send_error(&mut stream, 1);
        stream.shutdown(Shutdown::Both).unwrap();
        return Err(Error::BadMessageN);
    }

    match device_second.content {
        MessageContent::DeviceSecond => (),
        _ => { send_error(&mut stream, 1);
               stream.shutdown(Shutdown::Both).unwrap();
               return Err(Error::DeviceFirst(message::Error::InvalidOpcode)); },
    };

    log("Key exchange completed successfully", LOG_DEBUG);

    stream.set_read_timeout(Some(Duration::from_millis(1))).unwrap(); // 1ms read timeout

    let server = ProtocolState {
        stream: stream,
        long_keys: long_keys,
        next_send_n: 1,
        next_recv_n: expected_next_n,
        session_keys: session_keys,
        send_as_device: false,
    };

    Ok(Server{ state:server, read_buff: Vec::new() }) 
}

/// sending data
impl io::Write for Server {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        general_write(&mut self.state, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.stream.flush()
    }
}

/// receiving data
impl io::Read for Server {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = general_read(&mut self.state, &mut self.read_buff);

        if ret.is_err() {
            return ret;
        }

        let num_elements = {
            if buf.len() > self.read_buff.len() {
                self.read_buff.len()
            } else {
                buf.len()
            }
        };

        for i in 0..num_elements {
            buf[i] = self.read_buff.remove(0);
        }

        Ok(num_elements)
    }
}
                


