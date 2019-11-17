extern crate serde_json;
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate base64;
extern crate sodiumoxide;

use failure::Error;

pub type Result<T> = std::result::Result<T, Error>;
pub mod macaroon;
pub mod verifier;
