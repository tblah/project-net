//! Message structure

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

use proj_crypto::asymmetric;

#[derive(Debug)]
pub struct Message {
    pub number: u16,
    pub content: MessageContent,
}

/// Representation of the information that we care about within a message
#[derive(Debug)]
pub enum MessageContent {
    /// Initiates the key exchange
    DeviceFirst(asymmetric::PublicKey),

    /// Second message in the key exchange
    ServerFirst(asymmetric::PublicKey, [u8; asymmetric::CHALLENGE_BYTES]),

    /// Final message in a successful key exchange
    DeviceSecond,

    /// Destroys the connection and logs an error. Unsigned so that it works before we have keys exchanged.
    /// An active man in the middle attacker could spam this message for DoS but they could also just drop the packets so I don't *think* this is a problem?
    Error,

    /// Actually send data from one party to the other.
    Message(Vec<u8>),

    /// Acknowledge receipt of a message
    Ack(u16),

    /// From server to client requesting a new key exchange. If a device wants to do this (or to respond to this) it closes this session and immediately begins a new session (and key exchange) immediately.
    ReKey,

    /// Tear down the connection without reporting an error. Requires authentication so that a man in the middle can't downgrade an error to a stop to avoid logging.
    Stop,
}

pub mod receive;
pub mod send;
mod opcodes;

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::send;
    use super::receive;
    use super::Message;
    use super::MessageContent;
    extern crate sodiumoxide;
    use sodiumoxide::randombytes;
    use proj_crypto::asymmetric;

    #[test]
    fn error_general() {
        let (server_keys, _) = do_full_exchange();

        // medium over which to send messages
        let mut channel: Vec<u8> = Vec::new();

        send_error(&mut channel, 6000);
        assert!(errorp(receive::general(&mut channel.as_slice(), &server_keys.from_server)));
    }
    
    #[test]
    fn message() {
        let (server_keys, device_keys) = do_full_exchange();

        let message = randombytes::randombytes(300);

        let mut channel: Vec<u8> = Vec::new();

        assert!(send::message(&mut channel, &message, &device_keys.from_device, 1055).is_none());

        let received = receive::general(&mut channel.as_slice(), &server_keys.from_device).unwrap();
        let received_msg = match received.content {
            MessageContent::Message(v) => v,
            _ => panic!("that is not a message!"),
        };

        assert_eq!(received.number, 1055);
        assert_eq!(received_msg, message);
    }

    #[test]
    fn ack() {
        let (server_keys, device_keys) = do_full_exchange();

        let mut channel: Vec<u8> = Vec::new();

        assert!(send::ack(&mut channel, 2003, &server_keys.from_server, 8).is_none());

        let ack = receive::general(&mut channel.as_slice(), &device_keys.from_server).unwrap();
        let ack_num = match ack.content {
            MessageContent::Ack(n) => n,
            _ => panic!("that is not an ack"),
        };

        assert_eq!(ack.number, 8);
        assert_eq!(ack_num, 2003);
    }

    #[test]
    fn rekey() {
        let (server_keys, device_keys) = do_full_exchange();

        let mut channel: Vec<u8> = Vec::new();

        assert!(send::rekey(&mut channel, &device_keys.from_device, 5).is_none());

        let rekey = receive::general(&mut channel.as_slice(), &server_keys.from_device).unwrap();

        match rekey.content {
            MessageContent::ReKey => (),
            _ => panic!("that was not a rekey"),
        };

        assert_eq!(rekey.number, 5);
    }

    #[test]
    fn stop() {
        let (server_keys, device_keys) = do_full_exchange();

        let mut channel: Vec<u8> = Vec::new();

        assert!(send::stop(&mut channel, &server_keys.from_server, 5000).is_none());

        let stop = receive::general(&mut channel.as_slice(), &device_keys.from_server).unwrap();

        match stop.content {
            MessageContent::Stop => (),
            _ => panic!("that was not a rekey"),
        };

        assert_eq!(stop.number, 5000);

    }

    #[test]
    fn full_exchange() {
        let _ = do_full_exchange();
    }

    fn errorp(msg: Result<Message, receive::ReceiveError>) -> bool {
        match msg.unwrap().content {
            MessageContent::Error => true,
            _ => false,
        }
    }

    fn send_error(mut channel: &mut Vec<u8>, message_number: u16) {
        assert!(send::error(&mut channel, message_number).is_none());
    }

    // also tests error packets
    fn do_full_exchange() -> (asymmetric::SessionKeys, asymmetric::SessionKeys) {
        sodiumoxide::init();

        let (pk_device, sk_device) = asymmetric::gen_keypair();
        let (pk_server, sk_server) = asymmetric::gen_keypair();

        let device = asymmetric::LongTermKeys {
            my_public_key: pk_device.clone(),
            my_secret_key: sk_device,
            their_public_key: pk_server.clone(),
        };

        let server = asymmetric::LongTermKeys {
            my_public_key: pk_server.clone(),
            my_secret_key: sk_server,
            their_public_key: pk_device.clone(),
        };

        // medium to send messages across
        let mut channel: Vec<u8> = Vec::new();

        // device_first:

        // send message
        let device_session_keypair = send::device_first(&mut channel, &device).unwrap();

        // receive message
        let device_first = receive::device_first(&mut channel.as_slice()).unwrap();
        let sent_pk = match device_first.content {
            MessageContent::DeviceFirst(p) => p,
            _ => panic!("receive::device_first did not return a device first packet")
        };

        assert_eq!(sent_pk, device_session_keypair.0);
        assert_eq!(device_first.number, 0);

        channel.clear();

        // test sending an error to device_first
        send_error(&mut channel, 133);
        assert!(errorp(receive::device_first(&mut channel.as_slice())));
        channel.clear();
        
        // server_first:

        // send message
        let (server_session_keys, server_challenge)= send::server_first(&mut channel, &server, &device_session_keypair.0).unwrap();

        // receive message
        let server_first = receive::server_first(&mut channel.as_slice(), &device, &device_session_keypair.0, &device_session_keypair.1).unwrap();
        let (server_session_pub_key, challenge) = match server_first.content {
            MessageContent::ServerFirst(x, y) => (x, y),
            _ => panic!("receive::server_first returned the wrong message type!"),
        };

        assert_eq!(server_challenge, challenge);
        assert_eq!(server_first.number, 0);

        channel.clear();

        // test sending an error to server_first
        send_error(&mut channel, 7);
        assert!(errorp(receive::server_first(&mut channel.as_slice(), &device, &device_session_keypair.0, &device_session_keypair.1)));
        channel.clear();
        
        // device_second

        // send message
        let device_session_keys = send::device_second(&mut channel, &device, &server_session_pub_key, &challenge, &device_session_keypair).unwrap();

        // receive message
        let device_second = receive::device_second(&mut channel.as_slice(), &server_session_keys, &server_challenge.as_slice()).unwrap();
        let worked = match device_second.content {
            MessageContent::DeviceSecond => true,
            _ => false,
        };

        assert!(worked);
        assert_eq!(device_second.number, 1);

        channel.clear();

        // test sending an error to device_second
        send_error(&mut channel, 1025);
        assert!(errorp(receive::device_first(&mut channel.as_slice())));

        (server_session_keys, device_session_keys)
    }
}
