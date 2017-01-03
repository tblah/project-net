//! For receiving messages

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

use super::MessageContent;
use super::opcodes;
use super::Error;
use std::io;
use proj_crypto::asymmetric::*;
use proj_crypto::asymmetric::key_exchange::*;
use proj_crypto::asymmetric::key_id::*;
use proj_crypto::symmetric::AUTH_TAG_BYTES;
use proj_crypto::symmetric;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memcmp;
use super::{Message, CHALLENGE_BYTES};
use {SessionKeys, Keypair};
use std::collections::HashMap;

pub fn receive_device_first <R: io::Read> (source: &mut R) -> Result<Message, Error> {
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    parse_clear_message(source, opcode, message_number)
}
 
pub fn server_first <R: io::Read> (source: &mut R, session_keypair: &Keypair, trusted_pks: &HashMap<PublicKeyId, PublicKey>) -> Result<Message, Error> {
    let (ref pk_session, ref sk_session) = *session_keypair;
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    if opcode == opcodes::ERROR {
        Ok(Message { number: message_number, content: MessageContent::Error })
    } else if opcode == opcodes::SERVER_FIRST {
        if message_number != 0 {
            return Err(Error::BadPacket);
        }

        // get the content section of the message
        let buff = match get_n_bytes(source, PUBLIC_KEY_BYTES + CHALLENGE_BYTES + 32 + AUTH_TAG_BYTES) { // the 32 is for the key id
            Err(e) => return Err(e),
            Ok(x) => x,
        };

        // get the key id 
        let (key_id_bytes, authenticated_bit) = buff.split_at(32);
        let key_id = PublicKeyId {
            digest: sha256::Digest::from_slice(key_id_bytes).unwrap(),
        };

        let server_long_pk = match find_public_key(&key_id, trusted_pks) {
            None => return Err(Error::PubKeyId),
            Some(pk) => pk,
        };

        // separate the authentication tag from the message and check that it is correct
        let (auth_tag, the_rest) = authenticated_bit.split_at(AUTH_TAG_BYTES);

        // derive the authentication key
        let from_server_auth = &key_exchange(&server_long_pk, &sk_session, &pk_session, true);
        let server_authenticator = symmetric::State::new(&from_server_auth.as_slice(), &from_server_auth.as_slice()); // we don't use or have encryption keys at this point

        // verify authentication tag
        if !server_authenticator.verify_auth_tag(auth_tag, the_rest, message_number) {
            return Err(Error::Crypto);
        } // else continue...
        
        // parse the message
        let (pub_key_bytes, challenge) = the_rest.split_at(PUBLIC_KEY_BYTES);
        let pub_key = public_key_from_slice(pub_key_bytes).unwrap();

        // the rust compiler is not smart enough to notice that challenge always has length 32 so we are going to have to waste some time
        let mut challenge_sized: [u8; CHALLENGE_BYTES] = [0; CHALLENGE_BYTES];
        for i in 0..CHALLENGE_BYTES {
            challenge_sized[i] = challenge[i];
        }

        Ok(Message{ number: message_number, content: MessageContent::ServerFirst(pub_key, challenge_sized, server_long_pk) })
    } else {
        Err(Error::InvalidOpcode)
    }
}

pub fn device_second <R: io::Read> (source: &mut R, session_keys: &SessionKeys, challenge: &[u8]) -> Result<Message, Error> {
    assert_eq!(challenge.len(), CHALLENGE_BYTES);
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    if opcode == opcodes::ERROR {
        Ok(Message{ number: message_number, content: MessageContent::Error })
    } else if opcode == opcodes::DEVICE_SECOND {
        if message_number != 1 {
            return Err(Error::BadPacket);
        }
        
        let contents = match get_n_bytes(source, CHALLENGE_BYTES + AUTH_TAG_BYTES) {
            Err(e) => return Err(e),
            Ok(x) => x,
        };

        let challenge_recvd = match session_keys.from_device.authenticated_decryption(&contents, message_number) {
            None => return Err(Error::Crypto),
            Some(c) => c,
        };

        if memcmp(&challenge_recvd, challenge) {
            Ok(Message{ number: message_number, content: MessageContent::DeviceSecond })
        } else {
            Err(Error::Crypto)
        }
    } else {
        Err(Error::InvalidOpcode)
    }
}

pub fn general <R: io::Read> (source: &mut R, session_keys: &symmetric::State) -> Result<Message, Error> {
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    // these functions check if the opcode is valid for us
    if opcode <= opcodes::MAX_NOCRYPT {
        parse_clear_message(source, opcode, message_number) 
    } else {
        parse_crypt_message(source, opcode, message_number, session_keys)
    }
}

fn get_n_bytes<R: io::Read> (source: &mut R, n: usize) -> Result<Vec<u8>, Error> {
    let mut buffer: Vec<u8> = Vec::with_capacity(n); // dynamically allocate our buffer

    // if you don't fill the buffer with blanks beforehand, read things the buffer length is 0.
    for _ in 0..n {
        buffer.push(0);
    }
    
    match source.read(&mut buffer) {
        Err(e) => Err(Error::Read(e)),
        Ok(bytes_read) => if bytes_read == n {
            Ok(buffer)
        } else {
            Err(Error::NotEnoughRead(bytes_read))
        }
    }
}

fn two_bytes_to_u16(bytes: &[u8]) -> u16 {
    assert_eq!(bytes.len(), 2);

    bytes[1] as u16 + ((bytes[0] as u16) << 8)
}

fn get_header<R: io::Read> (source: &mut R) -> Result<(u8, u16), Error> {
    let header_buffer = match get_n_bytes(source, 3) { // one byte opcode, 2 byte message number
        Err(e) => return Err(e),
        Ok(buff) => buff
    };

    let (opcode, message_number_bytes) = header_buffer.split_at(1);

    // message_number_bytes is always 2 items long
    let message_number = two_bytes_to_u16(message_number_bytes);

    Ok((opcode[0], message_number))
}
    
// error and device_first are the only two clear messages that we can receive without explicitly expecting them to arrive
fn parse_clear_message <R: io::Read> (source: &mut R, opcode: u8, message_number: u16) -> Result<Message, Error> {
    match opcode {
        opcodes::ERROR => Ok(Message{ number: message_number, content: MessageContent::Error, }),
        opcodes::DEVICE_FIRST => {
            if message_number != 0 {
                return Err(Error::BadPacket);
            }
            
            let pub_key_bytes = match get_n_bytes(source, PUBLIC_KEY_BYTES) {
                Err(e) => return Err(e),
                Ok(x) => x,
            };
            let pub_key = public_key_from_slice(&pub_key_bytes).unwrap();

            let key_id_bytes = match get_n_bytes(source, 32) {
                Err(e) => return Err(e),
                Ok(x) => x,
            };
            let digest = sha256::Digest::from_slice(&key_id_bytes).unwrap();
            let key_id = PublicKeyId {
                digest: digest,
            };
            
            Ok(Message{ number: message_number, content: MessageContent::DeviceFirst(pub_key, key_id )})
        },
        _ => Err(Error::InvalidOpcode),
    } 
}

fn parse_crypt_message <R: io::Read> (source: &mut R, opcode: u8, message_number: u16, session_keys: &symmetric::State) -> Result<Message, Error> {
    match opcode {
        opcodes::ERROR => Ok(Message{ number: message_number, content: MessageContent::Error }),

        opcodes::MESSAGE => {
            // get the fixed fields
            let fixed_fields = match get_n_bytes(source, 2 + AUTH_TAG_BYTES) { // u16 message length + authentication on the length
                Err(e) => return Err(e),
                Ok(x) => x,
            };

            let (length_bytes, auth_tag) = fixed_fields.split_at(2);
            
            // test auth_tag
            if !session_keys.verify_auth_tag(auth_tag, length_bytes, message_number) {
                return Err(Error::Crypto);
            }

            let length = two_bytes_to_u16(length_bytes);

            // now get the ciphertext
            let ciphertext = match get_n_bytes(source, (length as usize) + AUTH_TAG_BYTES) {
                Err(e) => return Err(e),
                Ok(x) => x,
            };

            // decrypt
            match session_keys.authenticated_decryption(&ciphertext, message_number) {
                None => return Err(Error::Crypto),
                Some(plaintext) => Ok(Message{ number: message_number, content: MessageContent::Message(plaintext) })
            }
        }

        /*opcodes::ACK => {
            let ciphertext = match get_n_bytes(source, 2 + AUTH_TAG_BYTES) { // u16 message number + the authentication tag on the message number
                Err(e) => return Err(e),
                Ok(x) => x,
            };

            match session_keys.authenticated_decryption(&ciphertext, message_number) {
                None => return Err(Error::Crypto),
                Some(plaintext) => Ok(Message{ number: message_number, content: MessageContent::Ack(two_bytes_to_u16(&plaintext))})
            }
        }*/
            
        //opcodes::REKEY => parse_constant_contents_message(source, opcode, message_number, session_keys),
           
        opcodes::STOP => parse_constant_contents_message(source, opcode, message_number, session_keys),

        _ => Err(Error::InvalidOpcode),
    }
}

fn parse_constant_contents_message<R: io::Read> (source: &mut R, opcode: u8, message_number: u16, session_keys: &symmetric::State) -> Result<Message, Error> {
    assert!(/*(opcode == opcodes::REKEY ) ||*/ (opcode == opcodes::STOP));
    
    let ciphertext = match get_n_bytes(source, opcodes::CONST_MSG_LEN + AUTH_TAG_BYTES) {
        Err(e) => return Err(e),
        Ok(x) => x,
    };

    let plaintext = match session_keys.authenticated_decryption(&ciphertext, message_number) {
        None => return Err(Error::Crypto),
        Some(p) => p,
    };

    // I was lazy when writing this function. If you change ConstMsg_t this will need improving
    // remember to do constant-time comparison if ConstMsg_t is bigger than a word.
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    if plaintext.len() != opcodes::CONST_MSG_LEN {
        return Err(Error::BadPacket);
    }

    let expected = /*if opcode == opcodes::REKEY {
        opcodes::REKEY_CONTENTS
    } else {*/
        opcodes::STOP_CONTENTS
    /*}*/;

    if plaintext[0] == expected {
    /*    if opcode == opcodes::REKEY {
            Ok(Message{ number: message_number, content: MessageContent::ReKey } )
        } else {*/
            Ok(Message{ number: message_number, content: MessageContent::Stop } )
        //}
    } else {
        Err(Error::Crypto)
    }
}
