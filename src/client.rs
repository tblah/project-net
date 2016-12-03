//! Client functionality

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
use proj_crypto::asymmetric::key_exchange::LongTermKeys;
use super::common::*;
use super::common::message::{receive, send, MessageContent};
use std::io;
use std::time::Duration;
use std::net::Shutdown;

/// Structure containing the state for a running client
pub struct Client {
    state: ProtocolState,
    read_buff: Vec<u8>,
}

/// Creates a new client and performs a key exchange
pub fn start(socket_addr: &str, long_keys: LongTermKeys) -> Result<Client, Error> {
    sodiumoxide::init();
    // attempt connection
    let mut stream = match net::TcpStream::connect(socket_addr) {
        Ok(s) => s,
        Err(e) => {
            log("Failed to connect", LOG_RELEASE);
            return Err(Error::Connect(e)); },
    };

    log("Connected successfully", LOG_DEBUG);
    let mut expected_next_n: u16 = 0;

    // send device first
    let keypair = match send::device_first(&mut stream) {
        Ok(k) => k,
        Err(e) => {
            log("Problem sending device_first", LOG_RELEASE);
            return Err(Error::DeviceFirst(e)); },
    };

    log("Sent device_first successfully", LOG_DEBUG);

    // receive server response
    let server_first = match receive::server_first(&mut stream, &long_keys, &keypair) {
        Ok(m) => m,
        Err(e) => {
            log("Failed to receive server_first", LOG_RELEASE);
            send_error(&mut stream, 1);
            stream.shutdown(Shutdown::Both).unwrap();
            return Err(Error::ServerFirst(e)); },
    };

    if !check_message_n(&mut expected_next_n, &server_first) {
        send_error(&mut stream, 1);
        stream.shutdown(Shutdown::Both).unwrap();
        return Err(Error::BadMessageN);
    }

    let (server_pk, challenge) = match server_first.content {
        MessageContent::ServerFirst(pk, c) => (pk, c),
        _ => return Err(Error::ServerFirst(message::Error::InvalidOpcode)),
    };

    log("received server_first successfully", LOG_DEBUG);    

    // send challenge response
    let session_keys = match send::device_second(&mut stream, &long_keys, &server_pk, &challenge, &keypair) {
        Ok(sk) => sk,
        Err(e) => return Err(Error::DeviceSecond(e)),
    };

    log("Key exchange complete", LOG_DEBUG);

    let client = ProtocolState {
        stream: stream,
        long_keys: long_keys,
        next_send_n: 2,
        next_recv_n: expected_next_n,
        session_keys: session_keys,
        send_as_device: true,
    };

    Ok(Client{ state: client, read_buff: Vec::new() })
}

/// Sending data
impl io::Write for Client{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        general_write(&mut self.state, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.stream.flush()
    }
}

/// Receiving data
impl io::Read for Client {
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

impl Client {
    /// Give up on IO after blocking for a timeout
    pub fn blocking_off(&mut self, milliseconds: u64) {
        self.state.stream.set_read_timeout(Some(Duration::from_millis(milliseconds))).unwrap(); // 1ms read timeout
    }

    /// Block indefinably for IO
    pub fn blocking_on(&mut self) {
        self.state.stream.set_read_timeout(None).unwrap();
    }
}
