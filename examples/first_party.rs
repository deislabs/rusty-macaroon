extern crate macaroon;
extern crate serde_json;

use macaroon::macaroon::{Macaroon, ByteString, Caveat};
use sodiumoxide::crypto::auth;

fn main() {
    let key = auth::gen_key();
    let identifier = "a test";
    let mut m = Macaroon::new(ByteString(key.0.to_vec()), identifier.into(), None).unwrap();
    let data = serde_json::to_string(&m).unwrap();
    println!("{}", data);
    m.add_first_party_caveat(Caveat{
        identifier: "foo = bar".into(),
        ..Default::default()
    }).unwrap();

    let data = serde_json::to_string(&m).unwrap();
    println!("{}", data);
    let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
    println!("{:?}", deserialized.signature == m.signature)
}