use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;
use sodiumoxide::crypto::auth::{Key, authenticate};
use sodiumoxide::crypto::secretbox;
use crate::Result;
use failure::format_err;
use std::fmt;

// An implementation that represents any binary data. By spec, most fields in a
// macaroon support binary encoded as base64, so ByteString has methods to
// convert to and from base64 strings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteString(pub Vec<u8>);

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

impl From<String> for ByteString {
    fn from(s: String) -> ByteString {
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
        let bs = match ByteString::new_from_base64(value) {
            Ok(v) => v,
            Err(_) => return Err(E::custom("unable to base64 decode value"))
        };
        Ok(bs)
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
    caveats: Vec<Caveat>,
}

impl Default for Macaroon {
    fn default() -> Macaroon {
        Macaroon{
            version: Macaroon::VERSION,
            caveats: Vec::new(),
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

    pub fn new(key: &Key, identifier: ByteString, location: Option<String>) -> Result<Macaroon> {
        let sig = authenticate(&identifier.0, key);
        let mut m = Macaroon::default();
        m.identifier = identifier;
        m.location = location;
        m.signature = ByteString(sig.0.to_vec());
        Ok(m)
    }

    fn sig_to_key(sig: &ByteString) -> Result<Key> {
        let key = Key::from_slice(&sig.0).ok_or_else(|| format_err!("key is incorrect length"))?;
        Ok(key)
    }

    pub fn hash_first_party(sig: &ByteString, identifier: &ByteString) -> Result<ByteString> {
        let sig = authenticate(&identifier.0, &Self::sig_to_key(sig)?);
        Ok(ByteString(sig.0.to_vec()))
    }

    pub fn hash_third_party(sig: &ByteString, identifier: &ByteString, vid: &ByteString) -> Result<ByteString> {
        let key = &Self::sig_to_key(sig)?;
        let mut sig1 = authenticate(&vid.0, key).0.to_vec();
        let sig2 = authenticate(&identifier.0, key).0.to_vec();
        sig1.extend(sig2);
        Ok(ByteString(authenticate(&sig1, key).0.to_vec()))
    }

    // Returns a copy of the current list of caveats
    pub fn get_caveats(&self) -> Vec<Caveat> {
        self.caveats.clone()
    }

    pub fn get_first_party_caveats(&self) -> Vec<Caveat> {
        self.caveats.iter().filter(|c| c.location.is_none()).map(|c| c.clone()).collect()
    }

    // Returns a copy of the current list of third party caveats
    pub fn get_third_party_caveats(&self) -> Vec<Caveat> {
        self.caveats.iter().filter(|c| c.location.is_some()).map(|c| c.clone()).collect()
    }

    pub fn add_first_party_caveat(&mut self, c: Caveat) -> Result<()> {
        if c.verification_id.0.len() != 0 || c.location.is_some() {
            return Err(format_err!("a first party caveat should not contain a verification id or location"))
        }
        self.signature = Self::hash_first_party(&self.signature, &c.identifier)?;
        self.caveats.push(c);
        
        Ok(())
    }

    pub fn add_third_party_caveat(&mut self, caveat_key: &Key, c: Caveat) -> Result<()> {
        if c.location.is_none() {
            return Err(format_err!("a third party caveat must contain a location"))
        }
        if c.verification_id.0.len() != 0 {
            return Err(format_err!("a new third party caveat should not contain a verification id"))
        }
        let mut caveat_copy = c.clone();
        // Here we encrypt the caveat key with the signature using a nonce. The
        // nonce becomes part of the verification ID. So the final message is
        // NONCE+ENCODED_SECRET_DATA
        caveat_copy.verification_id = encrypt(&self.signature, caveat_key)?;
        
        self.signature = Self::hash_third_party(&self.signature, &c.identifier, &caveat_copy.verification_id)?;
        self.caveats.push(caveat_copy);
        
        Ok(())
    }

    // Binds the given mararoon to the request by hashing the two signatures
    // together and returning a new macaroon
    pub fn prepare_for_request(&mut self, discharge_macaroon: &Macaroon) -> Result<Macaroon> {
        let mut d = discharge_macaroon.clone();
        d.signature = Self::hash_third_party(&ByteString(vec![0; sodiumoxide::crypto::auth::KEYBYTES]), &self.signature, &d.signature)?;
        Ok(d)
    }
}

pub fn key_from_str(s: &str) -> Result<Key> {
    let strbytes = s.as_bytes();
    if strbytes.len() > sodiumoxide::crypto::auth::KEYBYTES {
        return Err(format_err!("key is too long"))
    }
    let mut raw: Vec<u8> = vec![0; sodiumoxide::crypto::auth::KEYBYTES];
    raw.splice(raw.len()-strbytes.len().., strbytes.iter().cloned());
    let key = Key::from_slice(&raw).ok_or_else(|| format_err!("key is incorrect length"))?;
    Ok(key)
}

fn encrypt(sig: &ByteString, key: &Key) -> Result<ByteString> {
    // Convert the key to a secretbox key
    let k = match secretbox::Key::from_slice(&sig.0) {
        Some(v) => v,
        None => return Err(format_err!("invalid key length"))
    };
    let nonce = secretbox::gen_nonce();
    let mut msg = nonce.0.to_vec();
    let tmp = secretbox::seal(&key.0, &nonce, &k);
    msg.extend(tmp);

    Ok(ByteString(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn string_key() {
        let test_key = "a test";
        let k = key_from_str(test_key).unwrap();
        let reparsed_key = std::str::from_utf8(&k.0).unwrap();
        assert!(reparsed_key.contains(test_key));

        // Long key should error
        let test_key = "To be, or not to be? That is the question. Whether 'tis nobler in the mind to suffer the slings of fortune...";
        let res = key_from_str(test_key);
        assert!(res.is_err());
    }
}
