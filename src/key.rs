//! Private / public key type abstraction.
//!
//! Currently, we only support RSA keys.

use openssl::rsa::Rsa;

use std::io;
use std::io::prelude::*;

/// Enumeration of supported key types.
pub enum KeyType {
    Rsa,
}

/// A private SSH key.
pub enum PrivateKey {
    Rsa(Rsa),
}

impl PrivateKey {

}

pub enum PublicKey {

}

impl PublicKey {
    /// Encodes this public key as specified in RFC4253 "6.6. Public Key Algorithms" and writes the
    /// result to the given writer.
    pub fn encode_blob<W: Write>(&self, _w: &mut W) -> io::Result<()> {
        unimplemented!();
    }
}
