//! For sending messages

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

use super::opcodes;
use super::Error;
use std::io;
use std::vec;
use proj_crypto::asymmetric::key_exchange::*;
use proj_crypto::asymmetric::key_id::*;
use proj_crypto::asymmetric::*;
use proj_crypto::symmetric;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memzero;
use sodiumoxide::randombytes;
use super::super::{SessionKeys, Keypair};

/// The number of bytes in the random challenge
const CHALLENGE_BYES: usize = 32;
/// Differentiates the device encryption key from the server encryption key
const DEVICE_ENC_KEY_CONSTANT: &'static [u8] = b"device";
const SERVER_ENC_KEY_CONSTANT: &'static [u8] = b"server";

pub fn device_first<W: io::Write>(dest: &mut W, long_pk: &PublicKey) -> Result<Keypair, Error> {
    let mut message = construct_header(opcodes::DEVICE_FIRST, 0);
    
    let keypair = gen_keypair();

    let pubkey_bytes = &keypair.0.clone()[..];
    message.extend_from_slice(pubkey_bytes);

    let key_id = id_of_pk(long_pk);
    message.extend_from_slice(&key_id.digest[..]);

    match write_bytes(dest, &message) {
        None => Ok(keypair),
        Some(e) => Err(e),
    }
}

fn hash_two_things(thing1: &[u8], thing2: &[u8]) -> symmetric::Digest {
    let mut thing_to_hash = vec!();
    thing_to_hash.extend_from_slice(thing1);
    thing_to_hash.extend_from_slice(thing2);

    let result = symmetric::Digest{ digest: sha256::hash(&thing_to_hash) };

    memzero(&mut thing_to_hash);

    result
}

/// returns the session keys and the random challenge
pub fn server_first<W: io::Write>(dest: &mut W, long_term_keypair: &Keypair, device_session_pk: &PublicKey, device_long_pk: &PublicKey) -> Result<(SessionKeys, Vec<u8>), Error> {
    let mut message = construct_header(opcodes::SERVER_FIRST, 0);

    // generate the server's ephemeral keypair
    let (pub_key, sec_key) = gen_keypair(); // sec_key implements drop to clear memory

    let challenge = randombytes::randombytes(CHALLENGE_BYES);

    // do key exchange
    let encryption_key_shared = key_exchange(device_session_pk, &sec_key, &pub_key, false);
    let device_enc_key = hash_two_things(&encryption_key_shared.digest[..], DEVICE_ENC_KEY_CONSTANT);
    let server_enc_key = hash_two_things(&encryption_key_shared.digest[..], SERVER_ENC_KEY_CONSTANT);

    let device_auth_key = key_exchange(device_long_pk, &sec_key, &pub_key, false);
    let server_auth_key = key_exchange(device_session_pk, &long_term_keypair.1, &long_term_keypair.0, false);

    let session_keys = SessionKeys {
        from_device: symmetric::State::new(&device_enc_key.as_slice(), &device_auth_key.as_slice()),
        from_server: symmetric::State::new(&server_enc_key.as_slice(), &server_auth_key.as_slice()),
    };

    // message to send to the device
    let mut plaintext = vec!();
    plaintext.extend_from_slice(&pub_key[..]);
    plaintext.extend_from_slice(&challenge);
    let auth_tag = session_keys.from_server.plain_auth_tag(&plaintext, 0); // message number = 0
    
    // construct message
    message.extend_from_slice(&id_of_pk(&long_term_keypair.0).digest[..]);
    message.extend_from_slice(&auth_tag);
    message.append(&mut plaintext); // plaintext is the public key + challenge

    // send message
    match write_bytes(dest, &message) {
        None => Ok((session_keys, challenge)),
        Some(e) => Err(e),
    }
}

pub fn device_second<W: io::Write>(dest: &mut W, server_long_pk: &PublicKey, server_session_pk: &PublicKey, challenge: &[u8], long_keypair: &Keypair, session_keypair: &Keypair) -> Result<SessionKeys, Error> {
    assert_eq!(challenge.len(), CHALLENGE_BYES);
    
    let mut message = construct_header(opcodes::DEVICE_SECOND, 1);

    // re-derive this so that we don't have to copy it everywhere between parsing and sending
    let from_server_auth = &key_exchange(server_long_pk, &session_keypair.1, &session_keypair.0, true).as_slice();

    // the other authentication key
    let from_device_auth = &key_exchange(server_session_pk, &long_keypair.1, &long_keypair.0, true).as_slice();

    // encryption keys
    let encryption_key_shared = key_exchange(&server_session_pk, &session_keypair.1, &session_keypair.0, true);
    let device_enc_key = hash_two_things(&encryption_key_shared.as_slice(), DEVICE_ENC_KEY_CONSTANT);
    let server_enc_key = hash_two_things(&encryption_key_shared.as_slice(), SERVER_ENC_KEY_CONSTANT);

    let session_keys = SessionKeys {
        from_device: symmetric::State::new(&device_enc_key.as_slice(), from_device_auth),
        from_server: symmetric::State::new(&server_enc_key.as_slice(), from_server_auth),
    };

    // encrypt and authenticate the random challenge for sending to the server
    let mut ciphertext = session_keys.from_device.authenticated_encryption(challenge, 1); // message number = 1
    
    message.append(&mut ciphertext);

    // send message
    match write_bytes(dest, &message) {
        None => Ok(session_keys),
        Some(e) => Err(e),
    }
}

pub fn message<W: io::Write>(dest: &mut W, msg: &[u8], session_keys: &symmetric::State, message_number: u16) -> Option<Error> {
    assert!(msg.len() <= u16::max_value() as usize);

    let mut message = construct_header(opcodes::MESSAGE, message_number);

    let length = u16_to_bytes(msg.len() as u16);
    message.extend_from_slice(&length);

    let length_auth_tag = session_keys.plain_auth_tag(&length, message_number);
    message.extend_from_slice(&length_auth_tag);

    let mut ciphertext = session_keys.authenticated_encryption(msg, message_number);
    message.append(&mut ciphertext);

    write_bytes(dest, &message)
}

/*pub fn ack<W: io::Write>(dest: &mut W, ack_num: u16, session_keys: &symmetric::State, message_number: u16) -> Option<Error> {
    const_size_encrypted(dest, opcodes::ACK, &u16_to_bytes(ack_num), session_keys, message_number)
}*/

/*pub fn rekey<W: io::Write>(dest: &mut W, session_keys: &symmetric::State, message_number: u16) -> Option<Error> {
    // too lazy to implement this to be that generalised
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    const_size_encrypted(dest, opcodes::REKEY, &[opcodes::REKEY_CONTENTS], session_keys, message_number)
}*/

pub fn stop<W: io::Write>(dest: &mut W, session_keys: &symmetric::State, message_number: u16) -> Option<Error> {
    // too lazy to implement this to be that generalised
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    const_size_encrypted(dest, opcodes::STOP, &[opcodes::STOP_CONTENTS], session_keys, message_number)
}

pub fn error<W: io::Write>(dest: &mut W, message_number: u16) -> Option<Error> {
    let message = construct_header(opcodes::ERROR, message_number);
    write_bytes(dest, &message)
}

fn const_size_encrypted<W: io::Write>(dest: &mut W, opcode: u8, contents: &[u8], session_keys: &symmetric::State, message_number: u16) -> Option<Error> {
    let mut message = construct_header(opcode, message_number);

    let mut ciphertext = session_keys.authenticated_encryption(contents, message_number);
    message.append(&mut ciphertext);

    write_bytes(dest, &message)
}

fn u16_to_bytes(n: u16) -> [u8; 2] {
    let msb = (n >> 8) as u8;
    let lsb = (n & 0x00FF) as u8;

    [msb, lsb]
}

fn write_bytes <W: io::Write>(dest: &mut W, data: &[u8]) -> Option<Error> {
    match dest.write(data) {
        Err(e) => Some(Error::Write(e)),
        Ok(n) => if n == data.len() {
            None
        } else {
            Some(Error::NotEnoughWritten(n))
        }
    }
}

fn construct_header(opcode: u8, message_number: u16) -> Vec<u8> {
    let message_number_bytes = u16_to_bytes(message_number);

    let mut ret = Vec::with_capacity(3);
    ret.push(opcode);
    ret.extend_from_slice(&message_number_bytes);

    ret
}
