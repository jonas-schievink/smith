//! I'm using this binary to look at what the real ssh-agent is sending, so this is just for
//! debugging.

extern crate smith;
extern crate env_logger;
extern crate unix_socket;

use smith::protocol::*;

use unix_socket::UnixStream;

use std::fs;
use std::process::Command;

fn main() {
    env_logger::init().unwrap();

    // remove our test socket so the agent can start
    let _ = fs::remove_file("ssh_agent.sock");
    // launch ssh-agent and bind to test socket
    Command::new("ssh-agent").arg("-a").arg("ssh_agent.sock").status().unwrap();
    // add all keys
    Command::new("ssh-add").env("SSH_AUTH_SOCK", "ssh_agent.sock").status().unwrap();

    // do stuff
    let mut stream = UnixStream::connect("ssh_agent.sock").unwrap();
    Request::RequestIdentities.write(&mut stream).unwrap();

    let resp = Response::read(&mut stream).unwrap();
    println!("{:?}", resp);

    if let Response::Identities(idents) = resp {
        let pubblob = idents[0].key_blob.clone();
        Request::SignRequest {
            pubkey_blob: pubblob,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            flags: 0,
        }.write(&mut stream).unwrap();

        let resp = Response::read(&mut stream).unwrap();
        println!("{:?}", resp);
    } else {
        unreachable!();
    }
}
