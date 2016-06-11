//! Utility for working with `.pub` SSH pubkey files

use base64;

use std::io::{self, Read};

/// A public SSH key of arbitrary type.
///
/// Decoded from `.pub` files.
#[derive(Clone)]
pub struct Pubkey {
    /// The type of the key. This is the first space-separated part of a `.pub` file.
    pub key_type: String,
    /// Key data as a blob.
    ///
    /// This blob is in the same format that RFC4253 "6.6. Public Key Algorithms" specifies, so the
    /// key type is stored in here as well.
    ///
    /// In the `.pub` file, this is stored in Base 64 encoding.
    pub data: Vec<u8>,
    /// Comment associated with the key. The last part of a `.pub` file.
    pub comment: String,
}

impl Pubkey {
    /// Decodes the contents of a `.pub` file
    pub fn from_pub_file_contents(pub_file: String) -> io::Result<Self> {
        // FIXME proper error
        // FIXME we should probably accept all whitespace, but `split_whitespace_n` isn't a thing
        let mut splitn = pub_file.splitn(3, ' ');
        let key_type = splitn.next().unwrap().trim();
        let data_encoded = try!(splitn.next().ok_or(io::Error::new(io::ErrorKind::InvalidData,
                                                                   "no pubkey data blob found")));
        let comment = splitn.next().unwrap_or("");

        Ok(Pubkey {
            key_type: key_type.to_string(),
            data: try!(base64::decode(data_encoded.trim())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))),
            comment: comment.trim().to_string(),
        })
    }

    pub fn from_pub_file<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut content = String::new();
        try!(r.read_to_string(&mut content));
        Pubkey::from_pub_file_contents(content)
    }
}
