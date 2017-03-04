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

use proj_crypto::symmetric;
use proj_crypto::asymmetric::*;
use std::fs::OpenOptions;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::collections::HashMap;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::fmt::Display;

mod common;
pub mod server;
pub mod client;

/// Simple tuple of a public key and a secret key
pub type Keypair = (PublicKey, SecretKey);

/// Stores session keys
pub struct SessionKeys {
    /// symmetric state for use with messages to be sent or received from the device
    pub from_device: symmetric::State,
    /// symmetric state for use with message to be sent or received from the server
    pub from_server: symmetric::State,
}
fn to_utf8_hex<'a>(bytes: &[u8]) -> Vec<u8> {
    let strings: Vec<String> = bytes.into_iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let mut ret = Vec::new();
    ret.extend_from_slice(strings.join(" ").as_bytes());
    ret
}

/// Generate a keypair and put it into the specified file
/// This is not memory tidy. It would be difficult to clear the memory properly here and I don't think it matters too much because this doesn't connect to the network
pub fn key_gen_to_file<P: AsRef<Path> + Display + Clone>(file_path: P) where String: std::convert::From<P> {
    // write keypair file
    let option = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(file_path.clone());

    let mut file = match option {
        Ok(f) => f,
        Err(e) => panic!("Opening file '{}' failed with error: {}", file_path, e),
    };

    sodiumoxide::init();
    let (pk, sk) = key_exchange::gen_keypair();

    // unwraps to make sure we panic if something doesn't work
    let _ = file.write(b"PK: ").unwrap();
    let _ = file.write(&to_utf8_hex(&pk[..])).unwrap();
    let _ = file.write(b"\nSK: ").unwrap();
    let _ = file.write(&to_utf8_hex(&sk[..])).unwrap();
    let _ = file.write(b"\n").unwrap(); // just looks a bit nicer if someone curious looks at the file

    // write public key file
    let pub_option = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(String::from(file_path.clone()) + ".pub");

    let mut pub_file = match pub_option {
        Ok(f) => f,
        Err(e) => panic!("Opening file '{}' failed with error: {}", file_path, e),
    };

    let _ = pub_file.write(b"PK: ").unwrap();
    let _ = pub_file.write(&to_utf8_hex(&pk[..])).unwrap();
    let _ = pub_file.write(b"\n").unwrap();
}

fn hex_char_to_num(c: char) -> u8 {
    match c {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'A' => 10,
        'B' => 11,
        'C' => 12,
        'D' => 13,
        'E' => 14,
        'F' => 15,
        _ => panic!("{} is not a hexadecimal digit", c),
    }
}

fn hex_to_byte(hex: Vec<char>) -> u8 {
    assert_eq!(hex.len(), 2);

    hex_char_to_num(hex[1]) | (hex_char_to_num(hex[0]) << 4)
}

/// returns a file so as to give it back to the caller (it was borrowed to get here)
fn get_key_from_file(mut file: fs::File, prefix: &str) -> Option<(fs::File, Vec<u8>)> {
    let prefix_expected = String::from(prefix) + ": ";
    let mut prefix_read_bytes: [u8; 4] = [0; 4]; // e.g. "PK: "

    match file.read(&mut prefix_read_bytes) {
        Ok(_) => (),
        Err(_) => return None,
    };

    if prefix_read_bytes != prefix_expected.as_bytes() {
        if prefix_read_bytes != [10, 0, 0, 0]  { // 10 (denary) is linefeed in ascii
            panic!("The prefix read (as bytes) was {:?}, we expected {:?} ('{}'). Is the file malformed?", prefix_read_bytes, prefix_expected.as_bytes(), prefix_expected);
        } else { // we just got a linefeed so there is nothing to read
            return None;
        }
    }

    let mut key_hex_bytes: [u8; 64+31] = [0; 64+31]; // 64 characters and 31 spaces

    match file.read(&mut key_hex_bytes) {
        Ok(_) => (),
        Err(e) => panic!("Error reading file: {}", e),
    };

    let mut key_hex_vec = Vec::new();
    key_hex_vec.extend_from_slice(&key_hex_bytes);
    
    let key_hex: Vec<char> = String::from_utf8(key_hex_vec).unwrap().chars().collect();

    // split the hex string into pairs of of hex digits (bytes)
    let key: Vec<u8> = key_hex.split(|c| *c == ' ')
        .map(|x| x.to_vec())
        .map(|x| hex_to_byte(x))
        .collect();


    Some((file, key))
}

fn open_or_panic<P: AsRef<Path> + Display + Clone>(path: P) -> fs::File {
    match fs::File::open(path.clone()) {
        Ok(f) => f,
        Err(e) => panic!("Error opening file '{}': {}", path, e),
    }
}

/// Reads keys from a file
pub fn get_keys<P1: AsRef<Path> + Display + Clone, P2: AsRef<Path> + Display + Clone>(my_keypair_path: P1, their_pk_path: P2) -> (HashMap<key_id::PublicKeyId, PublicKey>, Keypair) {
    let my_keypair_file = open_or_panic(my_keypair_path);
    let mut pk_file = open_or_panic(their_pk_path);

    // get my keypair
    let (mut my_keypair_file, pk_bytes) = get_key_from_file(my_keypair_file, "PK").unwrap();

    // seek to the start of SK
    my_keypair_file.seek(SeekFrom::Start(4+64+31+1)).unwrap(); // 4 byte prefix + 64 bytes of hex + 31 spaces + newline
    let (_, sk_bytes) = get_key_from_file(my_keypair_file, "SK").unwrap();

    let my_pk = public_key_from_slice(&pk_bytes).unwrap();
    let my_sk = secret_key_from_slice(&sk_bytes).unwrap();

    // get the trusted public keys
    let mut pks = HashMap::new();
    loop {
        let result = get_key_from_file(pk_file, "PK");

        if result.is_none() {
            break;
        }

        // else
        let (pk_file_tmp, pk_bytes) = result.unwrap();
        pk_file = pk_file_tmp; // got to love the borrow checker
        let pk = public_key_from_slice(&pk_bytes).unwrap();
        let pk_id = key_id::id_of_pk(&pk);
        pks.insert(pk_id, pk);
    }

    (pks, (my_pk, my_sk))
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::io;
    use std::net::TcpStream;
    extern crate sodiumoxide;
    extern crate proj_crypto;
    use std::thread;
    use std::time::Duration;
    use std::collections::HashMap;
    use proj_crypto::asymmetric::{key_id, PublicKey};
    use super::*;

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

