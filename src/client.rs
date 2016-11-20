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
use std::io;
use proj_crypto::asymmetric::LongTermKeys;
use proj_crypto::asymmetric::SessionKeys;
use proj_crypto::symmetric;
use super::common::*;
use super::common::message::*;

/// Contains the state information for a client
pub struct Client {
    socket: net::TcpStream,
    long_keys: LongTermKeys,
    next_send_n: u16,
    next_recv_n: u16,
    session_keys: SessionKeys,
}

/// Errors returned by the client
#[derive(Debug)]
pub enum Error {
    Connect(io::Error),
    DeviceFirst(send::Error),
    ServerFirst(receive::Error),
    DeviceSecond(send::Error),
    Sending(send::Error),
    Receiving(receive::Error),
    BadMessageN,
}

impl Client {
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

        // send device first
        let keypair = match send::device_first(&mut stream, &long_keys) {
            Ok(k) => k,
            Err(e) => {
                log("Problem sending device_first", LOG_RELEASE);
                return Err(Error::DeviceFirst(e)); },
        };

        log("Sent device_first successfully", LOG_DEBUG);

        // receive server response
        let server_first = match receive::server_first(&mut stream, &long_keys, &keypair.0, &keypair.1) {
            Ok(m) => m,
            Err(e) => {
                log("Failed to receive server_first", LOG_RELEASE);
                return Err(Error::ServerFirst(e)); },
        };

        //TODO check message_n, error messages

        let (server_pk, challenge) = match server_first.content {
            MessageContent::ServerFirst(pk, c) => (pk, c),
            _ => return Err(Error::ServerFirst(receive::Error::InvalidOpcode)),
        };
        
        log("received server_first successfully", LOG_DEBUG);    

        // send challenge response
        let session_keys = match send::device_second(&mut stream, &long_keys, &server_pk, &challenge, &keypair) {
            Ok(sk) => sk,
            Err(e) => return Err(Error::DeviceSecond(e)),
        };

        log("Key exchange complete", LOG_DEBUG);

        Err(Error::BadMessageN)
    }

}
