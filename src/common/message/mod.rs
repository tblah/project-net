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

pub struct Message {
    number: u16,
    content: MessageContent,
}

/// Representation of the information that we care about within a message
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
mod opcodes;
