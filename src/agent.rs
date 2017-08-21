use prompt::PasswordPrompt;
use protocol::*;
use pubkey::SshKey;

use unix_socket::{UnixListener, UnixStream};

use std::path::Path;
use std::io;
use std::fs;
use std::ffi::OsStr;

/// Implements an SSH agent.
///
/// Communication is done using a `UnixListener`, which must be passed to `Agent::run`.
pub struct Agent {
    /// List of managed keys.
    ///
    /// May contain both locked and unlocked keys. All of these keys are reported to clients
    /// connecting to the agent. This array is usually populated once on initialization, loading all
    /// keys into memory.
    // FIXME We should ensure that no 2 keys with the same pubkey blob are ever loaded
    keys: Vec<SshKey>,
}

impl Agent {
    /// Creates a new agent instance without any managed keys.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
        }
    }

    /// Tries to preload all keys found in the given directory.
    ///
    /// Does not recurse into subdirectories.
    ///
    /// The keys will be presented to clients, and will be unlocked upon use (assuming they are
    /// password protected) by opening a dialog.
    ///
    /// Any errors that occur in this method will be logged, but are not returned to the caller. A
    /// single unreadable SSH key will not prevent other keys from being preloaded, but will emit a
    /// warning (assuming logging is configured correctly).
    pub fn preload_user_keys_from_dir<P: AsRef<Path>>(&mut self, key_dir: P) {
        let key_dir = key_dir.as_ref();
        let key_count_pre = self.keys.len();

        let read_dir = match fs::read_dir(key_dir) {
            Ok(rd) => rd,
            Err(e) => {
                error!("couldn't read key directory {}: {}", key_dir.display(), e);
                return;
            }
        };

        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    error!("couldn't read dir entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();

            // Find all `.pub` files in the directory
            if path.extension() == Some(OsStr::new("pub")) {
                // Only preload if the corresponding non-pub file exists
                let priv_path = path.with_extension("");
                match priv_path.metadata() {
                    Ok(_) => {
                        match SshKey::from_paths(&path, priv_path) {
                            Ok(pkey) => {
                                info!("successfully preloaded public key '{}' from {}",
                                    pkey.comment(), path.display());
                                self.keys.push(pkey);
                            }
                            Err(e) => {
                                error!("couldn't preload {}: {}", path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("{} has no associated private key file ({})", path.display(), e);
                    }
                }
            }
        }

        info!("preloaded {} keys from {}", self.keys.len() - key_count_pre, key_dir.display());
    }

    /// Starts servicing clients
    pub fn run(&mut self, listener: UnixListener) -> ! {
        for res in listener.incoming() {
            if let Err(e) = self.handle_incoming(res) {
                error!("{:?}: {}", e.kind(), e);
            }
        }

        unreachable!();
    }

    /// List available identities (public keys).
    ///
    /// This includes locked keys we want to unlock lazily. When a client attempts to use one of
    /// them, we'll ask the user for a password and block.
    fn list_identities(&self) -> Vec<Identity> {
        self.keys
            .iter()
            .map(|key| Identity {
                key_blob: key.pub_key_blob().to_vec(),
                key_comment: key.comment().to_string(),
            }).collect()
    }

    fn find_key(&mut self, pubkey_blob: &[u8]) -> Option<&mut SshKey> {
        self.keys.iter_mut()
            .find(|key| key.pub_key_blob() == pubkey_blob)
    }

    fn process_request(&mut self, req: &Request) -> Response {
        // FIXME should just make this return a result, maybe with a quick_error context
        match *req {
            Request::RequestIdentities => {
                Response::Identities(self.list_identities())
            }
            Request::SignRequest { ref pubkey_blob, ref data, ref flags } => {
                match self.find_key(pubkey_blob) {
                    Some(key) => {
                        let comment = key.comment().to_string();
                        let signature = {
                            let priv_key = match key.unlock_with(|buf| {
                                Ok(PasswordPrompt::new(comment).invoke(buf))
                            }) {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("failed to unlock key: {}", e);
                                    return Response::Failure;
                                }
                            };

                            match priv_key.sign(data, flags) {
                                Ok(signature) => signature,
                                Err(e) => {
                                    error!("failed to sign data: {}", e);
                                    return Response::Failure;
                                }
                            }
                        };

                        Response::SignResponse {
                            algo_name: signature.algo_name().to_string(),
                            signature: signature.blob().to_vec(),
                        }
                    }
                    None => {
                        error!("no matching key for sign request");
                        Response::Failure
                    }
                }
            }
            Request::Unknown => Response::Failure,
        }
    }

    fn handle_incoming(&mut self, stream_result: io::Result<UnixStream>) -> io::Result<()> {
        let mut stream = stream_result?;

        info!("incoming connection");

        loop {
            let req = Request::read(&mut stream)?;
            debug!("request: {:?}", req);

            let response = self.process_request(&req);
            debug!("response: {:?}", response);
            response.write(&mut stream)?;

            // Close all connections after answering their first `SignRequest`. Otherwise, the
            // connection would stay open for the whole duration of the SSH session, allowing only
            // a single connection to exist.
            // FIXME: The proper way to fix this would be to use non-blocking I/O
            if let Request::SignRequest { .. } = req {
                info!("handled sign request, early exit (FIXME)");
                return Ok(());
            }
        }

        // Apparently the client will just shut the connection down, which is reflected as an `Err`.
        // Maybe we can special-case this one day.
    }
}
