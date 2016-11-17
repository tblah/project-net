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
use std::io;
use proj_crypto::asymmetric::*;
use proj_crypto::symmetric::AUTH_TAG_BYTES;
use proj_crypto::symmetric;
use super::Message;

#[derive(Debug)]
pub enum ReceiveError {
    Read(io::Error),
    NotEnoughRead,
    InvalidOpcode,
    Crypto,
    BadPacket
}

pub fn receive_device_first <R: io::Read> (source: &mut R) -> Result<Message, ReceiveError> {
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    parse_clear_message(source, opcode, message_number)
}
        
pub fn receive_server_first <R: io::Read> (source: &mut R, long_term_keys: &LongTermKeys, pk_session: &PublicKey, sk_session: &SecretKey ) -> Result<Message, ReceiveError> {
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    if opcode == opcodes::ERROR {
        Ok(Message { number: message_number, content: MessageContent::Error })
    } else if opcode == opcodes::SERVER_FIRST {
        // get the content section of the message
        let buff = match get_n_bytes(source, PUBLIC_KEY_BYTES + CHALLENGE_BYTES + AUTH_TAG_BYTES) {
            Err(e) => return Err(e),
            Ok(x) => x,
        };

        // separate the authentication tag from the message and check that it is correct
        let (auth_tag, the_rest) = buff.split_at(AUTH_TAG_BYTES);
        if !long_term_keys.device_verify_server_msg(pk_session, sk_session, the_rest, message_number, auth_tag) {
            return Err(ReceiveError::Crypto);
        }

        // parse the message
        let (pub_key_bytes, challenge) = the_rest.split_at(PUBLIC_KEY_BYTES);
        let pub_key = public_key_from_slice(pub_key_bytes).unwrap();

        // the rust compiler is not smart enough to notice that challenge always has length 32 so we are going to have to waste some time
        let mut challenge_sized: [u8; CHALLENGE_BYTES] = [0; CHALLENGE_BYTES];
        for i in 0..CHALLENGE_BYTES {
            challenge_sized[i] = challenge[i];
        }

        Ok(Message{ number: message_number, content: MessageContent::ServerFirst(pub_key, challenge_sized) })
    } else {
        Err(ReceiveError::InvalidOpcode)
    }
}

pub fn receive_device_second <R: io::Read> (source: &mut R, session_keys: &SessionKeys, challenge: &[u8; CHALLENGE_BYTES]) -> Result<Message, ReceiveError> {
    let (opcode, message_number) = match get_header(source) {
        Err(e) => return Err(e),
        Ok(x) => x
    };

    if opcode == opcodes::ERROR {
        Ok(Message{ number: message_number, content: MessageContent::Error })
    } else if opcode == opcodes::DEVICE_SECOND {
        let contents = match get_n_bytes(source, CHALLENGE_BYTES + AUTH_TAG_BYTES) {
            Err(e) => return Err(e),
            Ok(x) => x,
        };

        if server_verify_response(session_keys, &contents, message_number, challenge) {
            Ok(Message{ number: message_number, content: MessageContent::DeviceSecond })
        } else {
            Err(ReceiveError::Crypto)
        }
    } else {
        Err(ReceiveError::InvalidOpcode)
    }
}

pub fn receive <R: io::Read> (source: &mut R, session_keys: &symmetric::State) -> Result<Message, ReceiveError> {
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

fn get_n_bytes<R: io::Read> (source: &mut R, n: usize) -> Result<Vec<u8>, ReceiveError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(n); // dynamically allocate our buffer

    match source.read(&mut buffer) {
        Err(e) => Err(ReceiveError::Read(e)),
        Ok(bytes_read) => if bytes_read == n {
            Ok(buffer)
        } else {
            Err(ReceiveError::NotEnoughRead)
        }
    }
}

// todo endianness!
fn two_bytes_to_u16(bytes: &[u8]) -> u16 {
    assert_eq!(bytes.len(), 2);

    bytes[0] as u16 + ((bytes[1] as u16) << 8)
}

fn get_header<R: io::Read> (source: &mut R) -> Result<(u8, u16), ReceiveError> {
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
fn parse_clear_message <R: io::Read> (source: &mut R, opcode: u8, message_number: u16) -> Result<Message, ReceiveError> {
    match opcode {
        opcodes::ERROR => Ok(Message{ number: message_number, content: MessageContent::Error, }),
        opcodes::DEVICE_FIRST => {
            let pub_key_bytes = match get_n_bytes(source, PUBLIC_KEY_BYTES) {
                Err(e) => return Err(e),
                Ok(x) => x,
            };
                Ok(Message{ number: message_number, content: MessageContent::DeviceFirst(public_key_from_slice(&pub_key_bytes).unwrap())})
        },
        _ => Err(ReceiveError::InvalidOpcode),
    } 
}

fn parse_crypt_message <R: io::Read> (source: &mut R, opcode: u8, message_number: u16, session_keys: &symmetric::State) -> Result<Message, ReceiveError> {
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
                return Err(ReceiveError::Crypto);
            }

            let length = two_bytes_to_u16(length_bytes);

            // now get the ciphertext
            let ciphertext = match get_n_bytes(source, length as usize) {
                Err(e) => return Err(e),
                Ok(x) => x,
            };

            // decrypt
            match session_keys.authenticated_decryption(&ciphertext, message_number) {
                None => return Err(ReceiveError::Crypto),
                Some(plaintext) => Ok(Message{ number: message_number, content: MessageContent::Message(plaintext) })
            }
        }

        opcodes::ACK => {
            let ciphertext = match get_n_bytes(source, 2 + AUTH_TAG_BYTES) { // u16 message number + the authentication tag on the message number
                Err(e) => return Err(e),
                Ok(x) => x,
            };

            match session_keys.authenticated_decryption(&ciphertext, message_number) {
                None => return Err(ReceiveError::Crypto),
                Some(plaintext) => Ok(Message{ number: message_number, content: MessageContent::Ack(two_bytes_to_u16(&plaintext))})
            }
        }
            
        opcodes::REKEY => parse_constant_contents_message(source, opcode, message_number, session_keys),
           
        opcodes::STOP => parse_constant_contents_message(source, opcode, message_number, session_keys),

        _ => Err(ReceiveError::InvalidOpcode),
    }
}

fn parse_constant_contents_message<R: io::Read> (source: &mut R, opcode: u8, message_number: u16, session_keys: &symmetric::State) -> Result<Message, ReceiveError> {
    assert!((opcode == opcodes::REKEY ) || (opcode == opcodes::STOP));
    
    let ciphertext = match get_n_bytes(source, opcodes::CONST_MSG_LEN + AUTH_TAG_BYTES) {
        Err(e) => return Err(e),
        Ok(x) => x,
    };

    let plaintext = match session_keys.authenticated_decryption(&ciphertext, message_number) {
        None => return Err(ReceiveError::Crypto),
        Some(p) => p,
    };

    // I was lazy when writing this function. If you change ConstMsg_t this will need improving
    // remember to do constant-time comparison if ConstMsg_t is bigger than a word.
    assert_eq!(opcodes::CONST_MSG_LEN, 1);

    if plaintext.len() != opcodes::CONST_MSG_LEN {
        return Err(ReceiveError::BadPacket);
    }

    let expected = if opcode == opcodes::REKEY {
        opcodes::REKEY_CONTENTS
    } else {
        opcodes::STOP_CONTENTS
    };

    if plaintext[0] == expected {
        if opcode == opcodes::REKEY {
            Ok(Message{ number: message_number, content: MessageContent::ReKey } )
        } else {
            Ok(Message{ number: message_number, content: MessageContent::Stop } )
        }
    } else {
        Err(ReceiveError::Crypto)
    }
}
    
