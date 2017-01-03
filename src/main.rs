//! Executable for demonstrating client and server functionality

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

extern crate getopts;
extern crate proj_crypto;
extern crate proj_net;
extern crate sodiumoxide;

use getopts::Options;
use std::env;
use std::process;
use std::fs::OpenOptions;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::collections::HashMap;
use proj_crypto::asymmetric::*;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use proj_net::client;
use proj_net::server;
use proj_net::Keypair;

const DEFAULT_SOCKET_ADDR: &'static str = "127.0.0.1:1025";

fn print_usage(executable_name: &str, opts: &Options) -> ! {
    println!("{} is free software licenced under GPLv3+: you are free to change and redistribute it.", executable_name);
    println!("There is NO WAARRANTY, to the extent permitted by law.");
    println!("The cryptography used has not been reviewed by any experts. You should not use it for anything serious.\n");
    
    let brief1 = format!("To generate keys: {} --keygen OUTPUT_FILE\n", executable_name);
    let brief2 = format!("To run a server or client: {} --{{server, client}} MY_KEYPAIR --public-key PUBLIC_KEY_FILE [--socket IPADDR:PORT]", executable_name);

    print!("{}", opts.usage(&(brief1+&brief2)));
    process::exit(1)
}

// handles command line arguments
fn main() {
    let args: Vec<String> = env::args().collect();
    let executable_name = args[0].clone();

    let mut opts = Options::new();

    // prints usage - optional, no argument
    opts.optflag("h", "help", "Print this help menu");

    // key generation mode - optional, takes an argument
    opts.optopt("", "keygen", "Generate a long term keypair into OUTPUTFILE (both keys) and OUTFILE.pub (just the public key)", "OUTPUT_FILE");

    // server mode - optional, takes an argument
    opts.optopt("", "server", "Start a server", "MY_KEYPAIR");

    // client mode - optional, takes an argument
    opts.optopt("", "client", "Start a client", "MY_KEYPAIR");

    // required for client and server mode
    opts.optopt("k", "public-key", "The trusted public keys", "PUBLIC_KEY_FILE");

    // optional for client and server modes
    opts.optopt("s", "socket", &format!("The socket to listen on (server) or to connect to (client). The default is {}.", DEFAULT_SOCKET_ADDR), "IPADDR:PORT");

    // parse options
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => { println!("{}", f.to_string()); print_usage(&executable_name, &opts)},
    };

    if matches.opt_present("help") {
        print_usage(&executable_name, &opts);
    }
    
    // enforce exclusivity between operation modes
    if (matches.opt_present("server") && (matches.opt_present("client") | matches.opt_present("keygen"))) | 
        (matches.opt_present("client") && matches.opt_present("keygen")) {
            println!("Choose either --keygen, --server or --client\n");
            print_usage(&executable_name, &opts);
        }
    

    // server and client modes require the public key of the target to be specified
    if (matches.opt_present("server") | matches.opt_present("client")) & !matches.opt_present("public-key") {
        println!("Server and client modes require a public key to be specified.\n");
        print_usage(&executable_name, &opts);
    }

    // do specified operation
    
    if matches.opt_present("keygen") {
        if matches.opt_present("socket") | matches.opt_present("public-key") {
            println!("No other flags go with keygen\n");
            print_usage(&executable_name, &opts);
        }
        return key_gen(&matches.opt_str("keygen").unwrap());
    }
   
    if matches.opt_present("server") {
        if matches.opt_present("socket") {
            return server(&matches.opt_str("server").unwrap(), &matches.opt_str("public-key").unwrap(), &matches.opt_str("socket").unwrap());
        } else {
            return server(&matches.opt_str("server").unwrap(), &matches.opt_str("public-key").unwrap(), DEFAULT_SOCKET_ADDR);
        }
    }

    if matches.opt_present("client") {
        if matches.opt_present("socket") {
            return client(&matches.opt_str("client").unwrap(), &matches.opt_str("public-key").unwrap(), &matches.opt_str("socket").unwrap());
        } else {
            return client(&matches.opt_str("client").unwrap(), &matches.opt_str("public-key").unwrap(), DEFAULT_SOCKET_ADDR);
        }
    }
}

fn to_utf8_hex<'a>(bytes: &[u8]) -> Vec<u8> {
    let strings: Vec<String> = bytes.into_iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let mut ret = Vec::new();
    ret.extend_from_slice(strings.join(" ").as_bytes());
    ret
}

/// This is not memory tidy. It would be difficult to clear the memory properly here and I don't think it matters too much because this doesn't connect to the network
fn key_gen(file_path: &str) {
    // write keypair file
    let option = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(file_path);

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
        .open(String::from(file_path) + ".pub");

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

fn open_or_panic(path: &str) -> fs::File {
    match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => panic!("Error opening file '{}': {}", path, e),
    }
}

fn get_keys(my_keypair_path: &str, their_pk_path: &str) -> (HashMap<key_id::PublicKeyId, PublicKey>, Keypair) {
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

fn server(my_keypair_path: &str, pk_path: &str, socket: &str) {
    let listener = match server::listen(socket) {
        Err(e) => panic!("Server failed to start with error {:?}", e),
        Ok(l) => l,
    };

    let (pks, keypair) = get_keys(my_keypair_path, pk_path);

    let mut server = server::do_key_exchange(listener.incoming().next().unwrap(), &keypair, &pks).unwrap();

    server.blocking_off(1);

    interactive(&mut server);
}

fn client(my_keypair_path: &str, pk_path: &str, socket: &str) {
    let (pks, keypair) = get_keys(my_keypair_path, pk_path);
    
    let mut client = match client::start(socket, keypair, &pks) {
        Err(e) => panic!("Client failed to start with error {:?}", e),
        Ok(c) => c,
    };
    client.blocking_off(1);

    interactive(&mut client);
}       

fn interactive<T: Read + Write>(channel: &mut T) -> ! {
    let mut recv_buf = [0 as u8; 128];
    loop {
        let mut stdin_buf = String::new();
        print!("Enter your message: ");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_line(&mut stdin_buf);
        stdin_buf = String::from(stdin_buf.trim());
        
        if stdin_buf.len() > 0 {
            channel.write(stdin_buf.as_bytes()).unwrap();
        }

        loop { // try receiving a message
            let read_result = channel.read(&mut recv_buf);
            if read_result.is_ok() {
                let num_read = read_result.unwrap();
                if num_read > 0 {
                    println!("Received: {}", String::from_utf8(Vec::from(&recv_buf[0..num_read])).unwrap());
                    std::io::stdout().flush().unwrap();
                }
            } else {
                break;
            }
        }
    }
}
        
