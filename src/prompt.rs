//! GUI password prompt using pinentry

use std::cmp;
use std::process::{Command, Stdio};
use std::io::prelude::*;
use std::io::BufReader;

pub struct PasswordPrompt {
    key_name: String,
}

impl PasswordPrompt {
    pub fn new(key_name: String) -> Self {
        PasswordPrompt {
            key_name: key_name,
        }
    }

    /// Invokes the password prompt and puts the entered password into `password_buffer`.
    ///
    /// Returns the number of bytes input into the buffer.
    pub fn invoke(&self, password_buffer: &mut [i8]) -> usize {
        let mut pinentry = Command::new("pinentry")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn().unwrap();

        // Configure pinentry
        let mut pincmd = pinentry.stdin.take().unwrap();
        writeln!(pincmd, "SETTITLE Unlock SSH key").unwrap();
        writeln!(pincmd, "SETPROMPT Password:").unwrap();
        writeln!(pincmd, "SETDESC Enter the password for unlocking the SSH key '{}'",
            self.key_name).unwrap();
        writeln!(pincmd, "GETPIN").unwrap();

        // Read until we get an "ERR" or "D" line
        let out = BufReader::new(pinentry.stdout.take().unwrap());
        for line in out.lines() {
            let line = line.unwrap();
            if line.starts_with("ERR ") {
                pinentry.kill().unwrap();
                return 0;   // Abort!
            } else if line.starts_with("D ") {
                let bytes = &line.as_bytes()[2..];
                for (byte, target) in bytes.iter().zip(password_buffer.iter_mut()) {
                    *target = *byte as i8;
                }

                pinentry.kill().unwrap();
                return cmp::min(bytes.len(), password_buffer.len());
            }
        }

        pinentry.kill().unwrap();
        return 0;
    }
}
