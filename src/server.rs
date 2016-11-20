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
use std::io;
use proj_crypto::asymmetric::LongTermKeys;
use proj_crypto::asymmetric::SessionKeys;
use proj_crypto::symmetric;
use super::common::*;
use super::common::message::*;

/// Contains state information for a server
pub struct Server {
    socket: net::TcpStream,
    long_keys: LongTermKeys,
    next_send_n: u16,
    next_recv_n: u16,
    session_keys: SessionKeys,
}

/// Errors returned by the server
#[derive(Debug)]
pub enum Error {
    Bind(io::Error),
    Accept(io::Error),
    DeviceFirst(receive::Error),
    ServerFirst(send::Error),
    DeviceSecond(receive::Error),
    Sending(send::Error),
    Receiving(receive::Error),
    BadMessageN,
}

impl Server {
    /// creates a new Server and performs a key exchange
    pub fn start(socket_addr: &str, long_keys: LongTermKeys) -> Result<Server,Error> {
        sodiumoxide::init();
        let listener = match net::TcpListener::bind(socket_addr) {
            Err(e) => {
                log(&format!("Error starting the server: {}", e), LOG_RELEASE);
                return Err(Error::Bind(e)); },
            Ok(s) => {
                log(&format!("Server binded to {}", socket_addr), LOG_DEBUG);
                s },
        };

        // wait for a connection
        let stream = match listener.accept() {
            Err(e) => {
                log("Error listening for a connection", LOG_RELEASE);
                return Err(Error::Accept(e)); },
            Ok((s, _)) => s,
        };

        log("Got connection!", LOG_DEBUG);

        let mut server = Server {
            socket: stream,
            long_keys: long_keys,
            next_send_n: 0,
            next_recv_n: 0,
            // horrible hacked dummy session keys for until we have a real one. This is bad but deadlines
            // we can't use Option<SessionKeys> because it tries to copy to get the Some(x) out
            session_keys: SessionKeys { 
                from_device: symmetric::State::new(&[0; 32], &[0; 32]),
                from_server: symmetric::State::new(&[0; 32], &[0; 32]), },
        };

        // do key exchange

        let m = match receive::device_first(&mut server.socket) {
            Err(e) => {
                log(&format!("Error receiving first message: {:?}", e), LOG_RELEASE);
                return Err(Error::DeviceFirst(e)); },
            Ok(m) => m,
        };

        if !server.check_message_n(&m) {
            return Err(Error::BadMessageN);
        }

        // was it a DeviceFirst message?
        let device_ephemeral_pk = match m.content {
            MessageContent::DeviceFirst(pk) => pk,
            _ => { return Err(Error::DeviceFirst(receive::Error::InvalidOpcode)); },
        };

        log("device_first received successfully", LOG_DEBUG);
                
        // send response
        let (session_keys, challenge) = match send::server_first(&mut server.socket, &server.long_keys, &device_ephemeral_pk) {
            Err(e) => {
                log("Error sending server_first", LOG_RELEASE);
                return Err(Error::ServerFirst(e)); },
            Ok((k, c)) => (k, c)
        };

        server.session_keys = session_keys;

        log("server_first sent successfully", LOG_DEBUG);
            
        // receive challenge response
        let device_second = match receive::device_second(&mut server.socket, &server.session_keys, &challenge) {
            Err(e) => {
                log("Error validating device response", LOG_RELEASE);
                return Err(Error::DeviceSecond(e)); },
            Ok(m) => m,
        };

        if !server.check_message_n(&device_second) {
            return Err(Error::BadMessageN);
        }

        match device_second.content {
            MessageContent::DeviceSecond => (),
            _ => { return Err(Error::DeviceFirst(receive::Error::InvalidOpcode)); },
        };

        log("Key exchange completed successfully", LOG_DEBUG);
        Ok(server) 
    }

    fn check_message_n(&mut self, m: &Message) -> bool {
        if m.number != self.next_recv_n {
            log(&format!("Expected message number = {}. Received message number {}. Aborting.", self.next_recv_n, m.number), LOG_DEBUG);
            self.send_error();
            return false;
        }

        if self.next_recv_n == u16::max_value() {
            self.send_error();
            log("Aborting. Expected message number is about to overflow.", LOG_RELEASE);
            return false;
        }

        self.next_recv_n += 1;

        true
    }

    fn next_n(&mut self) -> u16 {
        if self.next_send_n == u16::max_value() {
            self.send_error();
            log("Aborting. Message number is about to overflow.", LOG_RELEASE);
            panic!("Message number is about to overflow!");
        }

        let ret = self.next_send_n;
        self.next_send_n += 1;

        ret
    }

    fn send_error(&mut self) {
        let n = self.next_n();
        match send::error(&mut self.socket, n) {
            Some(e) => {
                log("Unable to send an error packet. Aborting.", LOG_RELEASE); },
                //panic!("Error sending error packet: {:?}", e) },
            None => log("Sent error packet", LOG_DEBUG),
        }
    }

}

                    
