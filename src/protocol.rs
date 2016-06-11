use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use std::io;
use std::io::prelude::*;

// 3.1 Requests from client to agent for protocol 1 key operations
/*
const SSH_AGENTC_REQUEST_RSA_IDENTITIES: u8 = 1;
const SSH_AGENTC_RSA_CHALLENGE: u8 = 3;
const SSH_AGENTC_ADD_RSA_IDENTITY: u8 = 7;
const SSH_AGENTC_REMOVE_RSA_IDENTITY: u8 = 8;
const SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES: u8 = 9;
const SSH_AGENTC_ADD_RSA_ID_CONSTRAINED: u8 = 24;
*/
// 3.2 Requests from client to agent for protocol 2 key operations

const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
/*const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
const SSH2_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;*/

// 3.3 Key-type independent requests from client to agent

/*const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
const SSH_AGENTC_LOCK: u8 = 22;
const SSH_AGENTC_UNLOCK: u8 = 23;
const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;*/

// 3.4 Generic replies from agent to client

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;

// 3.5 Replies from agent to client for protocol 1 key operations
/*
const SSH_AGENT_RSA_IDENTITIES_ANSWER: u8 = 2;
const SSH_AGENT_RSA_RESPONSE: u8 = 4;
*/
// 3.6 Replies from agent to client for protocol 2 key operations

const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

// 3.7 Key constraint identifiers
/*
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;
*/

/// Max. length of a received message (for DoS protection).
const MESSAGE_LENGTH_LIMIT: u32 = 4096;

/// Read a `string` field as specified by the protocol. Can include arbitrary bytes, so it's more
/// like a blob, which is why this returns a `Vec<u8>`.
fn read_string<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = try!(r.read_u32::<BigEndian>());
    let mut buf = vec![0; len as usize];
    try!(r.read_exact(&mut buf));
    Ok(buf)
}

fn write_string<W: Write>(w: &mut W, string: &[u8]) -> io::Result<()> {
    try!(w.write_u32::<BigEndian>(string.len() as u32));
    w.write_all(string)
}

/// Helper method for reading a "message" (a client request or a server response), prefixed by a
/// big-endian `u32`.
///
/// The maximum message length is limited by `MESSAGE_LENGTH_LIMIT`.
fn read_message<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let length = try!(r.read_u32::<BigEndian>());
    if length > MESSAGE_LENGTH_LIMIT {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  "message length limit exceeded"));
    }

    let mut buf = vec![0; length as usize];
    try!(r.read_exact(&mut buf));

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

    /// `SSH2_AGENTC_REQUEST_IDENTITIES`
    RequestIdentities,
    /// `SSH2_AGENTC_SIGN_REQUEST`
    SignRequest {
        /// Blob of the public key, as returned by `RequestIdentities` (encoded as per RFC4253
        /// "6.6. Public Key Algorithms").
        pubkey_blob: Vec<u8>,
        /// The data to sign.
        data: Vec<u8>,
        /// Request flags, can only contain `SSH_AGENT_OLD_SIGNATURE`.
        flags: u32,
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
        let buf = try!(read_message(r));
        let mut buf = &buf[..];

        match try!(buf.read_u8()) {
            SSH2_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
            SSH2_AGENTC_SIGN_REQUEST => {
                Ok(Request::SignRequest {
                    pubkey_blob: try!(read_string(&mut buf)),
                    data: try!(read_string(&mut buf)),
                    flags: try!(buf.read_u32::<BigEndian>()),
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
            Request::RequestIdentities => try!(buf.write_u8(SSH2_AGENTC_REQUEST_IDENTITIES)),
            Request::SignRequest { ref pubkey_blob, ref data, ref flags } => {
                try!(buf.write_u8(SSH2_AGENTC_SIGN_REQUEST));
                try!(write_string(&mut buf, pubkey_blob));
                try!(write_string(&mut buf, data));
                try!(buf.write_u32::<BigEndian>(*flags));
            }

            Request::Unknown => panic!("attempted to encode `Unknown` request type"),
        }

        try!(w.write_u32::<BigEndian>(buf.len() as u32));
        try!(w.write_all(&buf));
        Ok(())
    }
}

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
        key_format: String,
        signature: Vec<u8>,
    },
}

impl Response {
    /// Reads and parses a response sent by an SSH agent.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let buf = try!(read_message(r));
        let mut buf = &buf[..];

        match try!(buf.read_u8()) {
            SSH2_AGENT_IDENTITIES_ANSWER => {
                let mut idents = Vec::new();
                let num = try!(buf.read_u32::<BigEndian>());
                for _ in 0..num {
                    let blob = try!(read_string(&mut buf));
                    let comment = try!(read_string(&mut buf));

                    idents.push(Identity {
                        key_blob: blob,
                        key_comment: String::from_utf8(comment).unwrap(),
                    });
                }

                Ok(Response::Identities(idents))
            },
            SSH2_AGENT_SIGN_RESPONSE => {
                let full_sig = try!(read_string(&mut buf));
                let mut full_sig = &full_sig[..];
                let key_format = try!(read_string(&mut full_sig));
                let signature = &full_sig[..];   // rest of the "full" signature

                Ok(Response::SignResponse {
                    key_format: try!(String::from_utf8(key_format)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))),
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
            Response::Success => try!(buf.write_all(&[SSH_AGENT_SUCCESS])),
            Response::Failure => try!(buf.write_all(&[SSH_AGENT_FAILURE])),
            Response::Identities(ref identities) => {
                try!(buf.write_all(&[SSH2_AGENT_IDENTITIES_ANSWER]));
                try!(buf.write_u32::<BigEndian>(identities.len() as u32));

                for identity in identities {
                    try!(write_string(&mut buf, &identity.key_blob));
                    try!(write_string(&mut buf, &identity.key_comment.as_bytes()));
                }
            }
            Response::SignResponse { ref key_format, ref signature } => {
                try!(buf.write_all(&[SSH2_AGENT_SIGN_RESPONSE]));

                let mut full_sig = Vec::new();
                try!(write_string(&mut full_sig, key_format.as_bytes()));
                try!(write_string(&mut full_sig, signature));

                try!(write_string(&mut buf, &full_sig));
            }
        }

        try!(w.write_u32::<BigEndian>(buf.len() as u32));
        try!(w.write_all(&buf));
        Ok(())
    }
}
