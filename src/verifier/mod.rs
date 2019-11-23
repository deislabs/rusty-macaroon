use sodiumoxide::crypto::auth::{Key, authenticate};
use std::collections::BTreeSet;
use std::cell::RefCell;
use std::collections::HashMap;
use sodiumoxide::crypto::secretbox;
use crate::macaroon::*;
use crate::Result;

pub type VerifyFunc = dyn Fn(&Caveat) -> bool;

#[derive(Default)]
pub struct Verifier {
    exact: BTreeSet<ByteString>,
    general: Vec<Box<VerifyFunc>>
}

impl Verifier {
    pub fn verify(&self, m: &Macaroon, key: &Key, discharges: Vec<Macaroon>) -> Result<()> {
        let discharge_set = &RefCell::new(discharges.iter().map(|d| (d.identifier.clone(), d.clone())).into_iter().collect());
        self.verify_with_sig(&m.signature, m, key, discharge_set)?;
        // Now check that all discharges were used
        if !discharge_set.borrow().is_empty() {
            return Err(format_err!("all discharge macaroons were not used"))
        }
        Ok(())
    }

    fn verify_with_sig(&self, root_sig: &ByteString, m: &Macaroon, key: &Key, discharge_set: &RefCell<HashMap<ByteString, Macaroon>>) -> Result<()> {
        let mut sig = ByteString(authenticate(&m.identifier.0, key).0.to_vec());
        for c in m.get_caveats() {
            // This should never fail, but we handle errors in case anything
            // fishy goes on
            sig = match c.location {
                Some(_) => {
                    let caveat_key = decrypt(&sig, &c.verification_id)?;
                    let dm = discharge_set.borrow_mut().remove(&c.identifier).ok_or_else(|| format_err!("no discharge macaroon found (or discharge has already been used) for caveat"))?;
                    self.verify_with_sig(root_sig, &dm, &caveat_key, discharge_set)?;
                    
                    // TODO: When passing the discharges in recursively, generate them from the hash map
                    Macaroon::hash_third_party(&sig, &c.identifier, &c.verification_id)
                },
                None => {
                    if !(self.exact.contains(&c.identifier) || self.verify_general(&c)) {
                        // If both failed, it means we weren't successful at either
                        return Err(format_err!("caveats are not valid"))
                    }
                    Macaroon::hash_first_party(&sig, &c.identifier)
                }
            }?;
        }
        // If the root sig equals the newly generated sig, that means we reached
        // the end of the line and we are ok to return
        if root_sig == &sig {
            return Ok(())
        }
        // Check the bound signature equals the signature of the discharge
        // macaroon
        let bound_sig = Macaroon::hash_third_party(&ByteString(vec![0; sodiumoxide::crypto::auth::KEYBYTES]), root_sig, &sig)?;
        if bound_sig != m.signature {
            return Err(format_err!("signature is not valid"))
        }
        Ok(())
    }

    pub fn satisfy_exact(&mut self, b: ByteString) {
        self.exact.insert(b);
    }

    pub fn satisfy_general(&mut self, f: Box<VerifyFunc>) {
        self.general.push(f)
    }

    fn verify_general(&self, c: &Caveat) -> bool {
        for f in self.general.iter() {
            if f(c) {
                return true
            }
        }
        return false
    }

}

fn decrypt(sig: &ByteString, text: &ByteString) -> Result<Key> {
    // If the message is less than the nonce size plus the number of overhead
    // bytes required for encryption, it it invalid
    if text.0.len() < secretbox::NONCEBYTES+secretbox::MACBYTES {
        return Err(format_err!("cipher text is too short"))
    }
    let mut raw_buffer = text.clone().0;
    // Read the nonce from the text and turn it into a key
    let rawnonce: Vec<u8> = raw_buffer.drain(..secretbox::NONCEBYTES).collect();
    let nonce = secretbox::Nonce::from_slice(&rawnonce).ok_or_else(|| format_err!("unable to reconstruct nonce from data"))?;
    let key = secretbox::Key::from_slice(&sig.0).ok_or_else(|| format_err!("given key is incorrect length"))?;
    let raw = match secretbox::open(&raw_buffer, &nonce, &key) {
        Ok(d) => d,
        Err(_) => return Err(format_err!("unable to decode data"))
    };
    Ok(Key::from_slice(&raw).ok_or_else(|| format_err!("given key is incorrect length"))?)
}
