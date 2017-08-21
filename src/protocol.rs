//! This module provides a more high-level view of the underlying SSH agent protocol.
//!
//! It does not implement the protocol, but it implements (de-)serialization of messages. The actual
//! protocol is implemented by `Agent`.
//!
//! Implements https://tools.ietf.org/html/draft-miller-ssh-agent-00
//!
//! I have carefully chosen to ignore the contained warning stating "It is inappropriate to use
//! Internet-Drafts as reference material".
//!
//! SSH protocol version 1 is not supported. You shouldn't be using it anyways.

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use std::io;
use std::io::prelude::*;

// Requests
const SSH_AGENTC_REQUEST_IDENTITIES                 : u8 = 11;
const SSH_AGENTC_SIGN_REQUEST                       : u8 = 13;
//const SSH_AGENTC_ADD_IDENTITY                       : u8 = 17;
//const SSH_AGENTC_REMOVE_IDENTITY                    : u8 = 18;
//const SSH_AGENTC_REMOVE_ALL_IDENTITIES              : u8 = 19;
//const SSH_AGENTC_ADD_ID_CONSTRAINED                 : u8 = 25;
//const SSH_AGENTC_ADD_SMARTCARD_KEY                  : u8 = 20;
//const SSH_AGENTC_REMOVE_SMARTCARD_KEY               : u8 = 21;
//const SSH_AGENTC_LOCK                               : u8 = 22;
//const SSH_AGENTC_UNLOCK                             : u8 = 23;
//const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED      : u8 = 26;
//const SSH_AGENTC_EXTENSION                          : u8 = 27;

// Agent replies
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
//const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;


bitflags! {
    pub struct SignFlags: u32 {
        const SSH_AGENT_RSA_SHA2_256 = 2;
        const SSH_AGENT_RSA_SHA2_512 = 4;
    }
}

/// Max. length of a received message (for DoS protection).
const MESSAGE_LENGTH_LIMIT: u32 = 4096;

/// Read a `string` field as specified by the protocol. Can include arbitrary bytes, so it's more
/// like a blob, which is why this returns a `Vec<u8>`.
fn read_string<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = r.read_u32::<BigEndian>()?;
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_string<W: Write>(w: &mut W, string: &[u8]) -> io::Result<()> {
    w.write_u32::<BigEndian>(string.len() as u32)?;
    w.write_all(string)
}

/// Helper method for reading a "message" (a client request or a server response), prefixed by a
/// big-endian `u32`.
///
/// The maximum message length is limited by `MESSAGE_LENGTH_LIMIT`.
fn read_message<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let length = r.read_u32::<BigEndian>()?;
    if length > MESSAGE_LENGTH_LIMIT {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  "message length limit exceeded"));
    }

    let mut buf = vec![0; length as usize];
    r.read_exact(&mut buf)?;

    Ok(buf)
}

/// Types of messages that can be received from a connected client.
#[derive(Debug)]
pub enum Request {
    /*
    /// `SSH_AGENTC_REQUEST_RSA_IDENTITIES`
    RequestRsaIdentities,
    /// `SSH_AGENTC_RSA_CHALLENGE`
    RsaChallenge,
    /// `SSH_AGENTC_ADD_RSA_IDENTITY`
    AddRsaIdentity,
    /// `SSH_AGENTC_REMOVE_RSA_IDENTITY`
    RemoveRsaIdentity,
    /// `SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES`
    RemoveAllRsaIdentities,
    /// `SSH_AGENTC_ADD_RSA_ID_CONSTRAINED`
    AddRsaIdConstrained,
    */

    /// `SSH_AGENTC_REQUEST_IDENTITIES`
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST`
    SignRequest {
        /// Blob of the public key, as returned by `RequestIdentities` (encoded as per RFC4253
        /// "6.6. Public Key Algorithms").
        pubkey_blob: Vec<u8>,
        /// The data to sign.
        data: Vec<u8>,
        /// Request flags.
        flags: SignFlags,
    },
    /*/// `SSH2_AGENTC_ADD_IDENTITY`
    AddIdentity,
    /// `SSH2_AGENTC_REMOVE_IDENTITY`
    RemoveIdentity,
    /// `SSH2_AGENTC_REMOVE_ALL_IDENTITIES`
    RemoveAllIdentities,
    /// `SSH2_AGENTC_ADD_ID_CONSTRAINED`
    AddIdConstrained,
    */

    /// Returned for unknown request types. The caller should respond with `Response::Failure`.
    Unknown,
}

impl Request {
    /// Reads a request sent by a client connected to the agent.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let buf = read_message(r)?;
        let mut buf = &buf[..];

        match buf.read_u8()? {
            SSH_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
            SSH_AGENTC_SIGN_REQUEST => {
                Ok(Request::SignRequest {
                    pubkey_blob: read_string(&mut buf)?,
                    data: read_string(&mut buf)?,
                    flags: {
                        // Unknown flag bits are ignored, but will emit a warning
                        let bits = buf.read_u32::<BigEndian>()?;
                        SignFlags::from_bits(bits).unwrap_or_else(|| {
                            warn!("ignoring unknown sign flag bits in 0x{:X}", bits);
                            SignFlags::from_bits_truncate(bits)
                        })
                    },
                })
            }
            unknown => {
                debug!("unknown request type {}", unknown);
                Ok(Request::Unknown)
            }
        }
    }

    /// Encodes this request as specified in the protocol and writes it to the given writer.
    ///
    /// If `self` is `Request::Unknown`, this method will panic.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = Vec::new();

        match *self {
            Request::RequestIdentities => buf.write_u8(SSH_AGENTC_REQUEST_IDENTITIES)?,
            Request::SignRequest { ref pubkey_blob, ref data, ref flags } => {
                buf.write_u8(SSH_AGENTC_SIGN_REQUEST)?;
                write_string(&mut buf, pubkey_blob)?;
                write_string(&mut buf, data)?;
                buf.write_u32::<BigEndian>(flags.bits())?;
            }

            Request::Unknown => panic!("attempted to encode `Unknown` request type"),
        }

        w.write_u32::<BigEndian>(buf.len() as u32)?;
        w.write_all(&buf)?;
        Ok(())
    }
}

// FIXME make more stuff in here 0copy

/// Part of the `SSH2_AGENT_IDENTITIES_ANSWER` response
#[derive(Debug)]
pub struct Identity {
    /// Public key blob encoded according to RFC 4253 section 6.6 "Public Key
    /// Algorithms"
    pub key_blob: Vec<u8>,
    pub key_comment: String,
}

/// A server response sent to the client.
///
/// Note that not all responses are valid for all requests.
#[derive(Debug)]
pub enum Response {
    /// `SSH_AGENT_SUCCESS`
    Success,
    /// `SSH_AGENT_FAILURE`
    Failure,

    /// `SSH2_AGENT_IDENTITIES_ANSWER`
    Identities(Vec<Identity>),

    /// `SSH2_AGENT_SIGN_RESPONSE`
    SignResponse {
        /// Name of the signature algorithm used. This is prepended as a `string`.
        algo_name: String,
        /// Actual signature blob.
        signature: Vec<u8>,
    },
}

impl Response {
    /// Reads and parses a response sent by an SSH agent.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let buf = read_message(r)?;
        let mut buf = &buf[..];

        match buf.read_u8()? {
            SSH_AGENT_IDENTITIES_ANSWER => {
                let mut idents = Vec::new();
                let num = buf.read_u32::<BigEndian>()?;
                for _ in 0..num {
                    let blob = read_string(&mut buf)?;
                    let comment = read_string(&mut buf)?;

                    idents.push(Identity {
                        key_blob: blob,
                        key_comment: String::from_utf8(comment).unwrap(),
                    });
                }

                Ok(Response::Identities(idents))
            },
            SSH_AGENT_SIGN_RESPONSE => {
                // string     signature
                let full_sig = read_string(&mut buf)?;
                let mut full_sig = &full_sig[..];

                // we assume all signature formats start with the name of the signature method
                // (encoded as a string field)
                let algo_name = read_string(&mut full_sig)?;
                let signature = &full_sig[..];   // rest of the "full" signature

                Ok(Response::SignResponse {
                    algo_name: String::from_utf8(algo_name)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                    signature: Vec::from(signature),
                })
            }
            unknown => {
                debug!("unknown response type {}", unknown);
                Err(io::Error::new(io::ErrorKind::Other, "unknown response type"))
            }
        }
    }

    /// Encodes this response as specified in the protocol, and writes it to the given writer.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = Vec::new();

        match *self {
            Response::Success => buf.write_u8(SSH_AGENT_SUCCESS)?,
            Response::Failure => buf.write_u8(SSH_AGENT_FAILURE)?,
            Response::Identities(ref identities) => {
                buf.write_u8(SSH_AGENT_IDENTITIES_ANSWER)?;
                buf.write_u32::<BigEndian>(identities.len() as u32)?;

                for identity in identities {
                    write_string(&mut buf, &identity.key_blob)?;
                    write_string(&mut buf, &identity.key_comment.as_bytes())?;
                }
            }
            Response::SignResponse { ref algo_name, ref signature } => {
                buf.write_u8(SSH_AGENT_SIGN_RESPONSE)?;

                let mut full_sig = Vec::new();
                write_string(&mut full_sig, algo_name.as_bytes())?;
                write_string(&mut full_sig, signature)?;

                write_string(&mut buf, &full_sig)?;
            }
        }

        w.write_u32::<BigEndian>(buf.len() as u32)?;
        w.write_all(&buf)?;
        Ok(())
    }
}
