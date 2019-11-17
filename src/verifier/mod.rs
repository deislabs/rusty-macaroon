use sodiumoxide::crypto::auth::{Key, authenticate};
use std::collections::BTreeSet;
use crate::macaroon::*;
use crate::Result;

pub type VerifyFunc = dyn Fn(&Caveat) -> bool;

#[derive(Default)]
pub struct Verifier {
    exact: BTreeSet<ByteString>,
    general: Vec<Box<VerifyFunc>>
}

impl Verifier {
    pub fn verify(&self, m: &Macaroon, key: &Key) -> Result<()> {
        for c in m.get_caveats() {
            // TODO(taylor): Third party validation
            // If the exact caveat, it is satisfied, so continue to the next one
            if self.exact.contains(&c.identifier) {
                continue
            }
            // If it isn't in the exact list, run it through the general cases
            if self.verify_general(c) {
                continue
            }
            // If we ever get here, it means we weren't successful at either
            return Err(format_err!("caveats are not valid"))
        }
        self.verify_sig(m, key)
    }

    pub fn satisfy_exact(&mut self, b: ByteString) {
        self.exact.insert(b);
    }

    pub fn satisfy_general(&mut self, f: Box<VerifyFunc>) {
        self.general.push(f)
    }

    fn verify_sig(&self, m: &Macaroon, key: &Key) -> Result<()> {
        let mut sig = authenticate(&m.identifier.0, key).0;
        for c in m.get_caveats() {
            // This should never fail, but we handle errors in case anything
            // fishy goes on
            let tmpkey = Key::from_slice(&sig).ok_or_else(|| format_err!("key is incorrect length"))?;
            sig = authenticate(&c.identifier.0, &tmpkey).0
        }
        if ByteString(sig.to_vec()) != m.signature {
            return Err(format_err!("signature is not valid"))
        }
        Ok(())
    }

    fn verify_general(&self, c: Caveat) -> bool {
        for f in self.general.iter() {
            if f(&c) {
                return true
            }
        }
        return false
    }

}
