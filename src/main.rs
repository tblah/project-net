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
use std::io::Write;
use std::io::Read;
use proj_net::*;

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
        return key_gen_to_file(matches.opt_str("keygen").unwrap().as_str());
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
        
