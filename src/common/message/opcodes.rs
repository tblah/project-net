/// Opcode numbers

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

// note: these are considered in ranges:
// range 1: stuff that doesn't need crypto
pub const ERROR: u8 = 0;
pub const DEVICE_FIRST: u8 = 1;
pub const SERVER_FIRST: u8 = 2;
pub const MAX_NOCRYPT: u8 = SERVER_FIRST;

// range 2: stuff that does need crypto
pub const DEVICE_SECOND: u8 = 3;
pub const MESSAGE: u8 = 4;
//pub const ACK: u8 = 5;
//pub const REKEY: u8 = 6;
pub const STOP: u8 = 7;

#[allow(dead_code)]
pub const MAX_OPCODE: u8 = STOP;

// contents of constant messages
// don't change the type of these without updating message.rs::parse_constant_contents_message()
pub const CONST_MSG_LEN: usize = 1;
pub const STOP_CONTENTS: u8 = 0;
//pub const REKEY_CONTENTS: u8 = 1;
