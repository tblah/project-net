//! Code common to both the server and the client
//!

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

pub mod message; 
use std::io;
use std::io::Write;

/// Log level guaranteed to be printed on debug builds
pub const LOG_DEBUG: u8 = 100;

/// Log level guaranteed to be printed on release builds
pub const LOG_RELEASE: u8 = 10;

const MIN_INCLUDED_LOG_LEVEL: u8 = LOG_DEBUG;

/// 0 = highest log level
pub fn log(msg: &str, level: u8) {
    if level <= MIN_INCLUDED_LOG_LEVEL {
        match io::stderr().write(&format!("{}\n",msg).as_bytes()) {
            Err(e) => panic!("Error writing to the log: {}", e),
            Ok(_) => (),
        }
    }
}
