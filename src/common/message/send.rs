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
use std::io;
use proj_crypto::asymmetric;
use proj_crypto::symmetric;

#[derive(Debug)]
pub enum SendError {
    Write(io::Error),
    NotEnoughWritten(usize),
}

pub type Keypair = (asymmetric::PublicKey, asymmetric::SecretKey);

pub fn device_first<W: io::Write>(dest: &mut W, long_term_keys: &asymmetric::LongTermKeys) -> Result<Keypair, SendError> {
    let mut message = construct_header(opcodes::DEVICE_FIRST, 0);
    
    let keypair = long_term_keys.device_first();

    let pubkey_bytes = &keypair.0.clone()[..];

    message.extend_from_slice(pubkey_bytes);

    match write_bytes(dest, &message) {
        None => Ok(keypair),
        Some(e) => Err(e),
    }
}

/// returns the session keys and the random challenge
pub fn server_first<W: io::Write>(dest: &mut W, long_term_keys: &asymmetric::LongTermKeys, device_session_pk: &asymmetric::PublicKey) -> Result<(asymmetric::SessionKeys, Vec<u8>), SendError> {
    let mut message = construct_header(opcodes::SERVER_FIRST, 0);

    let (challenge, session_keys, auth_tag,mut plaintext) = long_term_keys.server_first(device_session_pk, 0);

    message.extend_from_slice(&auth_tag);
    message.append(&mut plaintext); // plaintext is the public key + challenge

    match write_bytes(dest, &message) {
        None => Ok((session_keys, challenge)),
        Some(e) => Err(e),
    }
}

pub fn device_second<W: io::Write>(dest: &mut W, long_term_keys: &asymmetric::LongTermKeys, server_session_pk: &asymmetric::PublicKey, challenge: &[u8], session_keypair: &Keypair) -> Result<asymmetric::SessionKeys, SendError> {
    let mut message = construct_header(opcodes::DEVICE_SECOND, 1);

    let (session_keys, mut ciphertext) = long_term_keys.device_second(server_session_pk, challenge, &session_keypair.0, &session_keypair.1, 1);

    message.append(&mut ciphertext);

    match write_bytes(dest, &message) {
        None => Ok(session_keys),
        Some(e) => Err(e),
    }
}

pub fn message<W: io::Write>(dest: &mut W, msg: &[u8], session_keys: &symmetric::State, message_number: u16) -> Option<SendError> {
    let mut message = construct_header(opcodes::MESSAGE, message_number);

    let length = u16_to_bytes(msg.len() as u16);
    message.extend_from_slice(&length);

    let length_auth_tag = session_keys.plain_auth_tag(&length, message_number);
    message.extend_from_slice(&length_auth_tag);

    let mut ciphertext = session_keys.authenticated_encryption(msg, message_number);
    message.append(&mut ciphertext);

    write_bytes(dest, &message)
}

pub fn ack<W: io::Write>(dest: &mut W, ack_num: u16, session_keys: &symmetric::State, message_number: u16) -> Option<SendError> {
    const_size_encrypted(dest, opcodes::ACK, &u16_to_bytes(ack_num), session_keys, message_number)
}

pub fn rekey<W: io::Write>(dest: &mut W, session_keys: &symmetric::State, message_number: u16) -> Option<SendError> {
    // too lazy to implement this to be that generalised
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    const_size_encrypted(dest, opcodes::REKEY, &[opcodes::REKEY_CONTENTS], session_keys, message_number)
}

pub fn stop<W: io::Write>(dest: &mut W, session_keys: &symmetric::State, message_number: u16) -> Option<SendError> {
    // too lazy to implement this to be that generalised
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    const_size_encrypted(dest, opcodes::STOP, &[opcodes::STOP_CONTENTS], session_keys, message_number)
}

pub fn error<W: io::Write>(dest: &mut W, message_number: u16) -> Option<SendError> {
    let message = construct_header(opcodes::ERROR, message_number);
    write_bytes(dest, &message)
}

fn const_size_encrypted<W: io::Write>(dest: &mut W, opcode: u8, contents: &[u8], session_keys: &symmetric::State, message_number: u16) -> Option<SendError> {
    let mut message = construct_header(opcode, message_number);

    let mut ciphertext = session_keys.authenticated_encryption(contents, message_number);
    message.append(&mut ciphertext);

    write_bytes(dest, &message)
}

// todo: endianness
fn u16_to_bytes(n: u16) -> [u8; 2] {
    let msb = (n >> 8) as u8;
    let lsb = (n & 0x00FF) as u8;

    [msb, lsb]
}

fn write_bytes <W: io::Write>(dest: &mut W, data: &[u8]) -> Option<SendError> {
    match dest.write(data) {
        Err(e) => Some(SendError::Write(e)),
        Ok(n) => if n == data.len() {
            None
        } else {
            Some(SendError::NotEnoughWritten(n))
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
    

    
