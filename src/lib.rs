//! # Proj_Net library crate.
//!
//! This library implements networking around the protocol implemented in proj_crypto.
//! 
//! The cryptography in proj_crypto **has not been reviewed**.
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

// not currently working
/*#[cfg(test)]
mod test {
    use super::server;
    use super::client;
    use std::io::{Read, Write};
    extern crate sodiumoxide;
    extern crate proj_crypto;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[ignore] // because we are opening ports on the loop back and it might fail on some configurations
    fn random_read_write() {
        const MESSAGE_SIZE: usize = 256;

        let server_keypair = proj_crypto::asymmetric::gen_keypair();
        let client_keypair = proj_crypto::asymmetric::gen_keypair();

        let server_longkeys = proj_crypto::asymmetric::LongTermKeys {
            my_public_key: server_keypair.0.clone(),
            my_secret_key: server_keypair.1,
            their_public_key: client_keypair.0.clone(),
        };

        let client_longkeys = proj_crypto::asymmetric::LongTermKeys {
            my_public_key: client_keypair.0,
            my_secret_key: client_keypair.1,
            their_public_key: server_keypair.0,
        };

        let server_thread = thread::spawn(|| { server::start("127.0.0.1:1024", server_longkeys).unwrap() }); // starts listening
        thread::sleep(Duration::from_millis(10));

        let mut client = client::start("127.0.0.1:1024", client_longkeys).unwrap(); // key exchange happens here
        let mut server = server_thread.join().unwrap();

        let client_msg = sodiumoxide::randombytes::randombytes(MESSAGE_SIZE);
        let mut server_recv = [0 as u8; MESSAGE_SIZE];
        client.write(&client_msg).unwrap();
        server.read(&mut server_recv).unwrap(); // error here
        assert_eq!(&server_recv[0..MESSAGE_SIZE], client_msg.as_slice());
    }
}*/
        
