//! # Proj_Net library crate.
//!
//! This library implements networking around the protocol implemented in proj_crypto.
//! 
//! The cryptography in proj_crypto **has not been reviewed**.
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
//extern crate sodiumoxide;

mod common;
