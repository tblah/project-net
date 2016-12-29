//! # Proj_Net library crate.
//!
//! This library implements networking around the protocol implemented in proj_crypto.
//! 
//! The cryptography in proj_crypto **has not been reviewed**.
//!
//! For example usage see the server_echo() test in lib.rs and the interactive demo in main.rs.
//!
//! This project is licenced under the terms of the GNU General Public Licence as published by the Free Software Foundation, either version 3 of the licence, or (at your option) any later version.

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

#![crate_name = "proj_net"]
#![crate_type = "lib"]
#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]

extern crate proj_crypto;
extern crate sodiumoxide;

mod common;
pub mod server;
pub mod client;

#[cfg(test)]
mod test {
    use super::server;
    use super::client;
    use std::io::{Read, Write};
    extern crate sodiumoxide;
    extern crate proj_crypto;
    use std::thread;
    use std::time::Duration;

    const MESSAGE_SIZE: usize = 256;

    fn server_echo(server_long_keys: proj_crypto::asymmetric::key_exchange::LongTermKeys) {
        let listener = server::listen("127.0.0.1:1024").unwrap();
        
        let mut server = server::do_key_exchange(listener.incoming().next().unwrap(), server_long_keys).unwrap();
        server.blocking_on(); 

        let mut buf: [u8; MESSAGE_SIZE] = [0; MESSAGE_SIZE];
        loop {
            thread::sleep(Duration::from_millis(10));
            let n = match server.read(&mut buf) {
                Ok(n) => n,
                Err(e) => panic!("{:?}", e), // errors will be detected by the client. This error could well be that the client has send Stop
            };

            if n > 0 {
                server.write(&buf[0..n]).unwrap();
            }
        }
    }
    
    #[test]
    #[ignore] // because we are opening ports on the loop back and it might fail on some configurations
    fn echo() {
        let server_keypair = proj_crypto::asymmetric::key_exchange::gen_keypair();
        let client_keypair = proj_crypto::asymmetric::key_exchange::gen_keypair();

        let server_longkeys = proj_crypto::asymmetric::key_exchange::LongTermKeys {
            my_public_key: server_keypair.0.clone(),
            my_secret_key: server_keypair.1,
            their_public_key: client_keypair.0.clone(),
        };

        let client_longkeys = proj_crypto::asymmetric::key_exchange::LongTermKeys {
            my_public_key: client_keypair.0,
            my_secret_key: client_keypair.1,
            their_public_key: server_keypair.0,
        };

        let _ = thread::spawn(|| { server_echo(server_longkeys) }); // starts listening
        thread::sleep(Duration::from_millis(10));

        let mut client = client::start("127.0.0.1:1024", client_longkeys).unwrap(); // key exchange happens here
        client.blocking_on();

        let client_msg = sodiumoxide::randombytes::randombytes(MESSAGE_SIZE);
        let mut recv_buf = [0 as u8; MESSAGE_SIZE];
        client.write(&client_msg).unwrap();
        thread::sleep(Duration::from_millis(20));
        client.read(&mut recv_buf).unwrap();

        // don't use assert_eq! because we don't want it printing a load of useless entropy
        assert!(&recv_buf[0..MESSAGE_SIZE] == client_msg.as_slice());
    }
}
        
