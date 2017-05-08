use config::AgentConfig;
use prompt::PasswordPrompt;
use protocol::*;
use pubkey::Pubkey;

use tempdir::TempDir;
use unix_socket::{UnixListener, UnixStream};
use openssl::rsa::Rsa;
use openssl::hash::{self, Hasher};
use openssl::sign::Signer;
use openssl::pkey::PKey;

use std::env;
use std::path::PathBuf;
use std::io;
use std::io::prelude::*;
use std::fs::{self, File};
use std::ffi::OsStr;

/// Preloads public SSH keys from the user's `.ssh` directory.
fn preload_keys() -> Vec<(Pubkey, PathBuf)> {
    // FIXME this needs to be much more configurable

    if let Some(mut dir) = env::home_dir() {
        dir.push(".ssh");
        let mut keys = Vec::new();

        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                error!("couldn't read key directory {}: {}", dir.display(), e);
                return Vec::new();
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
                if priv_path.metadata().is_ok() {
                    let mut file = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            error!("couldn't open {}, skipping ({})", path.display(), e);
                            continue;
                        }
                    };

                    match Pubkey::from_pub_file(&mut file) {
                        Ok(pkey) => {
                            info!("successfully preloaded public key from {} ({})",
                                path.display(), pkey.comment);
                            keys.push((pkey, priv_path.canonicalize().unwrap()));
                        }
                        Err(e) => {
                            error!("couldn't preload {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        info!("preloaded {} keys from {}", keys.len(), dir.display());
        keys
    } else {
        error!("failed to determine the user's home dir, no keys will be preloaded");
        Vec::new()
    }
}

pub struct Agent {
    conf: AgentConfig,
    /// We hold on to an optional `TempDir` when we create a temporary directory for the socket
    /// outselves. When dropped, it will delete the directory. However, that rarely happens since
    /// destructors don't run when we're killed by a signal, so this is basically useless.
    _tempdir: Option<TempDir>,
    /// The unix domain socket listener. `None` when we're currently listening. This option dance
    /// prevents borrow conflicts.
    listener: Option<UnixListener>,
    sock_path: PathBuf,

    /// Loaded (unlocked) private keys.
    loaded_keys: Vec<(Pubkey, PKey)>,
    /// List of public keys and absolute paths to their private counterparts we want to unlock
    /// lazily.
    lazy_keys: Vec<(Pubkey, PathBuf)>,
}

impl Agent {
    /// Creates a new agent instance from the given configuration.
    pub fn new(conf: AgentConfig) -> io::Result<Self> {
        let mut my_tempdir = None;
        let sock_path = match conf.auth_sock {
            Some(ref sock) => PathBuf::from(sock),
            None => {
                let tempdir = try!(TempDir::new(concat!(env!("CARGO_PKG_NAME"), "-")));
                let mut path = tempdir.path().to_path_buf();
                path.push("agent.sock");
                my_tempdir = Some(tempdir);
                path
            }
        };

        if conf.remove_sock && fs::metadata(&sock_path).is_ok() {
            info!("removing existing socket file {}", sock_path.display());
            try!(fs::remove_file(&sock_path));
        }

        info!("binding to {}", sock_path.display());
        let listener = try!(UnixListener::bind(&sock_path));

        Ok(Agent {
            conf: conf,
            _tempdir: my_tempdir,
            listener: Some(listener),
            sock_path: sock_path,
            loaded_keys: Vec::new(),
            lazy_keys: preload_keys(),
        })
    }

    /// If configured to do so, this will output a shell script to set the SSH environment variables
    /// so that other programs know how to reach the agent.
    pub fn output_env_vars(&self) {
        if let Some(ref shell) = self.conf.shell {
            println!("{}", shell.export_var("SSH_AUTH_SOCK", self.sock_path.to_str().unwrap()));
            println!("{}", shell.export_var("SSH_AGENT_PID", unsafe { ::libc::getpid() }));
        }
    }

    /// List available identities (public keys).
    ///
    /// This includes locked keys we want to unlock lazily. When a client attempts to use one of
    /// them, we'll ask the user for a password and block.
    fn list_identities(&self) -> Vec<Identity> {
        self.lazy_keys
            .iter()
            .map(|&(ref pubkey, _)| pubkey)
            .chain(self.loaded_keys
                .iter()
                .map(|&(ref pubkey, _)| pubkey))
            .map(|pubkey| Identity {
                key_blob: pubkey.data.clone(),
                key_comment: pubkey.comment.clone(),
            }).collect()
    }

    /// Finds the private key belonging to the given public key blob. If the private key is not yet
    /// unlocked, but its pubkey was loaded for lazy unlocking, this will prompt the user to
    /// unlock the key.
    ///
    /// If successful, returns the index in `self.loaded_key` where the private key can be found.
    /// If unlocking fails or the private key wasn't found at all, returns an `Err`.
    fn find_or_unlock_private_key(&mut self, pubkey_blob: &[u8]) -> io::Result<usize> {
        if let Some((index, _)) = self.loaded_keys
                .iter().enumerate().find(|&(_, &(ref pubkey, _))| pubkey.data == pubkey_blob) {
            return Ok(index);
        }

        // FIXME I'm ugly, refactor me <3
        let (priv_index, old_index) = if let Some((index, &(ref pubkey, ref priv_path))) =
                self.lazy_keys
                    .iter().enumerate()
                    .filter(|&(_, &(ref pubkey, _))| pubkey.data == pubkey_blob).next() {
            // Try to unlock private key. If that fails, return `None`, if it succeeds, remove entry
            // from `self.lazy_keys` and put it in `self.loaded_keys`.
            info!("attempting to unlock {} ({})", priv_path.display(), pubkey.comment);

            let mut priv_file = try!(File::open(priv_path));
            let mut pem_data = Vec::new();
            try!(priv_file.read_to_end(&mut pem_data));
            let private_key = try!(Rsa::private_key_from_pem_callback(&pem_data, |buf| {
                Ok(PasswordPrompt::new(pubkey.comment.clone()).invoke(buf))
            }).map_err(|_| io::Error::new(io::ErrorKind::Other, "ssl error :(")));   // FIXME :-(

            let pkey = PKey::from_rsa(private_key).unwrap();

            self.loaded_keys.push(((*pubkey).clone(), pkey));

            (self.loaded_keys.len() - 1, index)
        } else {
            // No matching key found.
            return Err(io::Error::new(io::ErrorKind::NotFound, "no matching private key found"));
        };

        // Success! Remove old entry from `self.lazy_keys`.
        self.lazy_keys.remove(old_index);

        Ok(priv_index)
    }

    fn process_request(&mut self, req: &Request) -> Response {
        match *req {
            Request::RequestIdentities => {
                Response::Identities(self.list_identities())
            }
            Request::SignRequest { ref pubkey_blob, ref data, ref flags } => {
                // FIXME flags are currently ignored
                let _ = flags;
                match self.find_or_unlock_private_key(pubkey_blob) {
                    Ok(priv_index) => {
                        debug!("performing sign request with unlocked private key #{}", priv_index);
                        let (ref pubkey, ref pkey) = self.loaded_keys[priv_index];
                        info!("signing with key {}", pubkey.comment);


                        let mut sha = Hasher::new(hash::MessageDigest::sha1()).unwrap();
                        sha.write_all(&data).unwrap();
                        let digest = sha.finish2().unwrap().to_vec();

                        let mut signer = Signer::new(hash::MessageDigest::sha1(), &pkey).unwrap();
                        signer.update(&digest).unwrap();
                        let signature = signer.finish().unwrap();

                        Response::SignResponse {
                            key_format: pubkey.key_type.clone(),
                            signature: signature,
                        }
                    }
                    Err(e) => {
                        warn!("failed to comply with sign request: {}", e);
                        debug!("failed sign req with pubkey blob {:?}", pubkey_blob);
                        Response::Failure
                    }
                }
            }
            Request::Unknown => Response::Failure,
        }
    }

    fn handle_incoming(&mut self, stream_result: io::Result<UnixStream>) -> io::Result<()> {
        let mut stream = try!(stream_result);

        info!("incoming connection");

        loop {
            let req = try!(Request::read(&mut stream));
            debug!("request: {:?}", req);

            let response = self.process_request(&req);
            debug!("response: {:?}", response);
            try!(response.write(&mut stream));

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

    /// Starts servicing clients
    pub fn run(&mut self) -> ! {
        let listener = self.listener.take().expect("self.listener is None, did someone call \
                                                    Agent::run recursively?");
        for res in listener.incoming() {
            if let Err(e) = self.handle_incoming(res) {
                error!("{:?}: {}", e.kind(), e);
            }
        }

        unreachable!();
    }
}
