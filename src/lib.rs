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
    use std::io;
    use std::net::TcpStream;
    extern crate sodiumoxide;
    extern crate proj_crypto;
    use std::thread;
    use std::time::Duration;
    use std::collections::HashMap;
    use proj_crypto::asymmetric::{key_id, PublicKey};
    use common::*;

    const MESSAGE_SIZE: usize = 256;
    const NUM_CLIENTS: usize = 10;

    fn server_handle_connection(stream: io::Result<TcpStream>, keypair: Keypair, trusted_pks: HashMap<key_id::PublicKeyId, PublicKey>) {
        let mut server = server::do_key_exchange(stream, &keypair, &trusted_pks).unwrap();
        server.blocking_on(); 

        let mut buf: [u8; MESSAGE_SIZE] = [0; MESSAGE_SIZE];
        loop {
            thread::sleep(Duration::from_millis(10));
            let n = match server.read(&mut buf) {
                Ok(n) => n,
                Err(_) => return, // this just occurs when the client sends it's stop packet and we can't fail tests from a panic here anyway (see note at the end of the test function)
            };

            if n > 0 {
                server.write(&buf[0..n]).unwrap();
            }
        }
    }

    fn server_echo(server_long_keypair: Keypair, trusted_pks: HashMap<key_id::PublicKeyId, PublicKey>) {
        let listener = server::listen("127.0.0.1:1024").unwrap();
        let connections = listener.incoming();

        let mut handles = vec!();
        for stream in connections {
            let keypair = server_long_keypair.clone();
            let trusted_pks_clone = trusted_pks.clone();

            handles.push( thread::spawn(|| server_handle_connection(stream, keypair, trusted_pks_clone) ) );
        }
    }
        
    fn client_thread(keypair: Keypair, trusted_pks: HashMap<key_id::PublicKeyId, PublicKey>) {
        let mut client = client::start("127.0.0.1:1024", keypair, &trusted_pks).unwrap();
        client.blocking_on();

        let client_msg = sodiumoxide::randombytes::randombytes(MESSAGE_SIZE);
        let mut recv_buf = [0 as u8; MESSAGE_SIZE];
        client.write(&client_msg).unwrap();
        thread::sleep(Duration::from_millis(20));
        client.read(&mut recv_buf).unwrap();

        // don't use assert_eq! because we don't want it printing a load of useless entropy
        assert!(&recv_buf[0..MESSAGE_SIZE] == client_msg.as_slice());
    }
   
    #[test]
    fn echo() {
        let server_keypair = proj_crypto::asymmetric::key_exchange::gen_keypair();

        let mut trusted_pks = HashMap::new();
        trusted_pks.insert(key_id::id_of_pk(&server_keypair.0), server_keypair.0.clone());
        
        let mut client_keypairs = vec!();
        for _ in 0..NUM_CLIENTS {
            let keypair = proj_crypto::asymmetric::key_exchange::gen_keypair();
            trusted_pks.insert(key_id::id_of_pk(&keypair.0), keypair.0.clone());
            client_keypairs.push( keypair );
        }
            
        let server_trusted_pks = trusted_pks.clone();
        let _ = thread::spawn(|| server_echo(server_keypair, server_trusted_pks) ); // starts listening
        thread::sleep(Duration::from_millis(10));

        let mut client_threads = vec!();
        for keypair in client_keypairs {
            let client_trusted_pks = trusted_pks.clone();
            client_threads.push( thread::spawn(|| client_thread(keypair, client_trusted_pks) ) );
        }

        // make sure this thread panics if any of the children panicked
        for handle in client_threads {
            let _ = handle.join().unwrap();
        }
        // note that we won't notice panics in server threads. This is because we can't join them because the listening thread never stops waiting for more connections. Each client checks that the server responds to connections correctly so I don't think this is too bad.
    }
}

