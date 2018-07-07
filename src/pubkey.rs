//! Utility for working with `.pub` SSH pubkey files

use protocol::SignFlags;

use base64;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;

use std::io::{self, Read};
use std::fs::File;
use std::path::Path;

// FIXME: Investigate security implications of autoloading possibly unencrypted private keys into memory

quick_error! {
    #[derive(Debug)]
    pub enum KeyError {
        SslError(err: ErrorStack) {
            from()
            description("openssl operation failed")
        }
        IoError(err: io::Error) {
            from()
            description("i/o error")
        }
        // `SignFlags` passed to `PrivateKey::sign` not valid for key type
        IllegalFlags(msg: String) {}
    }
}

/// Represents a fully usable (but possibly locked) SSH key pair.
///
/// We always load public and private key at the same time to ensure consistency.
pub struct SshKey {
    /// The key format identifier. This is the first space-separated part of a `.pub` file.
    ///
    /// Examples: "ssh-dss", "ssh-rsa".
    key_type: String,
    /// Key data as a blob.
    ///
    /// This blob is in the same format that RFC4253 "6.6. Public Key Algorithms" specifies, so the
    /// key type is stored in here as well.
    ///
    /// In the `.pub` file, this is stored in Base 64 encoding.
    pub_blob: Vec<u8>,
    /// Contents of the private key file in PEM format (hopefully).
    priv_file: Vec<u8>,
    /// Comment associated with the key. The last part of a `.pub` file.
    comment: String,
    unlocked_key: Option<PrivateKey>,
}

impl SshKey {
    /// Reads the public and private part of this key from the file system.
    pub fn from_paths<P1, P2>(pub_path: P1, priv_path: P2) -> io::Result<Self>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>
    {
        let (mut pub_file, mut priv_file) = (File::open(pub_path)?, File::open(priv_path)?);

        let mut pub_content = String::new();
        pub_file.read_to_string(&mut pub_content)?;

        let mut priv_blob = Vec::new();
        priv_file.read_to_end(&mut priv_blob)?;

        // Parse public key to extract comment and the actual data that interests us
        // FIXME proper error
        // FIXME we should probably accept all whitespace, but `split_whitespace_n` isn't a thing
        let mut splitn = pub_content.splitn(3, ' ');
        let key_type = splitn.next().unwrap().trim().to_string();
        let data_encoded = splitn.next().ok_or(io::Error::new(io::ErrorKind::InvalidData,
                                                              "no pubkey data blob found"))?;
        let comment = splitn.next().unwrap_or("").trim().to_string();

        Ok(SshKey {
            pub_blob: base64::decode(data_encoded.trim())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
            priv_file: priv_blob,
            unlocked_key: None,
            key_type,
            comment,
        })
    }

    /// Returns the SSH key format identifier (eg. "ssh-rsa").
    pub fn format_identifier(&self) -> &str {
        &self.key_type
    }

    /// Returns the key's comment.
    ///
    /// The comment is supposed to be a human readable string that identifies all SSH keys in use.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns the public key blob.
    ///
    /// This blob is used by the SSH-Agent protocol to identify keys. It is stored as a
    /// base64-encoded string after the key type and before the optional comment.
    pub fn pub_key_blob(&self) -> &[u8] {
        &self.pub_blob
    }

    /// Unlocks the private key (if this didn't already happen) using `password_callback` to provide
    /// the key's password, and returns a reference to the private key.
    ///
    /// The key will stay unlocked when this method returns.
    pub fn unlock_with<F>(&mut self, password_callback: F) -> Result<&PrivateKey, ErrorStack>
    where F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack> {
        // FIXME: This would benefit from the `get_or_insert` methods, which were just recently
        // stabilized
        if let Some(ref pkey) = self.unlocked_key {
            return Ok(pkey);
        }

        let pkey = PKey::private_key_from_pem_callback(&self.priv_file, password_callback)?;
        self.unlocked_key = Some(PrivateKey { pkey });
        Ok(self.unlocked_key.as_ref().unwrap())
    }

    /// Locks the private key if it is unlocked. If not, does nothing.
    pub fn lock(&mut self) {
        self.unlocked_key.take();
    }
}

/// A private SSH key.
pub struct PrivateKey {
    pkey: PKey<Private>,
}

impl PrivateKey {
    /// Signs `data` with this key, according to RFC 4253 "6.6. Public Key Algorithms".
    pub fn sign(&self, data: &[u8], flags: &SignFlags) -> Result<Signature, KeyError> {
        assert!(self.pkey.rsa().is_ok(), "only RSA keys are supported");

        if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_256) && flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_512) {
            return Err(KeyError::IllegalFlags(format!("sign flags contain incompatible bits (flags = 0x{:X})", flags).into()));
        }

        // the digest defaults to sha1 but can be changed using `SignFlags`
        let (algo_name, digest_type) = if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_256) {
            ("rsa-sha2-256", MessageDigest::sha256())
        } else if flags.contains(SignFlags::SSH_AGENT_RSA_SHA2_512) {
            ("rsa-sha2-512", MessageDigest::sha512())
        } else {
            ("ssh-rsa", MessageDigest::sha1())
        };
        debug!("using signature algorithm {}", algo_name);

        let mut signer = Signer::new(digest_type, &self.pkey)?;
        signer.update(data)?;
        let blob = signer.sign_to_vec()?;

        Ok(Signature {
            algo_name,
            blob,
        })
    }
}

/// The result of a private key signing operation.
///
/// We take a shortcut here and assume that all signatures are encoded starting with a `string`
/// denoting their name. This is true for all currently specified signatures.
pub struct Signature {
    algo_name: &'static str,
    blob: Vec<u8>,
}

impl Signature {
    pub fn algo_name(&self) -> &str {
        self.algo_name
    }

    pub fn blob(&self) -> &[u8] {
        &self.blob
    }
}
