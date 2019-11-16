use std::cell::RefCell;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;
use sodiumoxide::crypto::auth::{Key, authenticate};
use crate::Result;
use failure::format_err;
use std::fmt;
use std::marker::PhantomData;

// An implementation that represents any binary data. By spec, most fields in a
// macaroon support binary encoded as base64, so ByteString has methods to
// convert to and from base64 strings
#[derive(Debug, Clone)]
pub struct ByteString(pub Vec<u8>);

// TODO: Implement PartialEq for strings
impl ByteString {
    // Takes a base64 encoded string and turns it into a decoded ByteString
    fn new_from_base64(v: &str) -> Result<ByteString> {
        let decoded = base64::decode(v)?;
        Ok(ByteString(decoded))
    }
}

impl From<&str> for ByteString {
    fn from(s: &str) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }
}

impl Default for ByteString {
    fn default() -> ByteString {
        ByteString(Default::default())
    }
}

impl fmt::Display for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct ByteStringVisitor;

impl<'de> Visitor<'de> for ByteStringVisitor {
    type Value = ByteString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("base64 encoded string of bytes")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let raw = match base64::decode(value) {
            Ok(v) => v,
            Err(_) => return Err(E::custom("unable to base64 decode value"))
        };
        Ok(ByteString(raw))
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ByteString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ByteStringVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macaroon {
    // TODO: Name fields in serde
    #[serde(rename = "v")]
    pub version: usize,
    #[serde(rename = "i")]
    pub identifier: ByteString,
    #[serde(rename = "l")]
    pub location: Option<String>,
    #[serde(rename = "s")]
    pub signature: ByteString,
    #[serde(rename = "c")]
    caveats: RefCell<Vec<Caveat>>,
}

impl Default for Macaroon {
    fn default() -> Macaroon {
        Macaroon{
            version: Macaroon::VERSION,
            caveats: RefCell::new(Vec::new()),
            identifier: Default::default(),
            location: None,
            signature: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Caveat {
    #[serde(rename = "i")]
    pub identifier: ByteString,
    #[serde(rename = "l")]
    pub location: Option<String>,
    #[serde(rename = "v")]
    pub verification_id: ByteString,
}

impl Macaroon {
    pub const VERSION: usize = 2;

    // TODO: Maybe just pass through the crypto Key type and have the rest just be a list of bytes
    pub fn new(key: ByteString, identifier: ByteString, location: Option<String>) -> Result<Macaroon> {
        let converted_key = match Key::from_slice(&key.0) {
            Some(k) => k,
            None => return Err(format_err!("Key is not 32 bytes"))
        };
        let sig = authenticate(&identifier.0, &converted_key);
        let mut m = Macaroon::default();
        m.identifier = identifier;
        m.location = location;
        m.signature = ByteString(sig.0.to_vec());
        Ok(m)
    }

    fn sig_to_key(&self) -> Result<Key> {
        let key = Key::from_slice(&self.signature.0).ok_or_else(|| format_err!("key is incorrect length"))?;
        Ok(key)
    }

    pub fn add_first_party_caveat(&mut self, c: Caveat) -> Result<()> {
        if c.verification_id.0.len() != 0 || c.location.is_some() {
            return Err(format_err!("a first party caveat should not contain a verification id or location"))
        }
        let sig = authenticate(&c.identifier.0, &self.sig_to_key()?);
        self.signature = ByteString(sig.0.to_vec());
        self.caveats.borrow_mut().push(c);

        Ok(())
    }
}
