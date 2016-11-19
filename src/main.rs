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
use getopts::Options;
use std::env;
use std::process;

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
    opts.optopt("", "keygen", "Generate a long term keypair", "OUTPUT_FILE");

    // server mode - optional, takes an argument
    opts.optopt("", "server", "Start a server", "MY_KEYPAIR");

    // client mode - optional, takes an argument
    opts.optopt("", "client", "Start a client", "MY_KEYPAIR");

    // required for client and server mode
    opts.optopt("k", "public-key", "The public key of the target", "PUBLIC_KEY_FILE");

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

fn key_gen(file_path: &str) {
    println!("Running key-gen into {}", file_path);
}

fn server(my_keypair: &str, their_pk: &str, socket: &str) {
    println!("Running a server on {}, with keypair from {} and public key from {}", socket, my_keypair, their_pk);
}

fn client(my_keypair: &str, their_pk: &str, socket: &str) {
    println!("Running a client connecting to {}, with keypair from {} and public key from {}", socket, my_keypair, their_pk);
}       
