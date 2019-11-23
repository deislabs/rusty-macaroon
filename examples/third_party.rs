extern crate macaroon;
extern crate serde_json;
extern crate chrono;

use macaroon::macaroon::{Macaroon, Caveat};
use macaroon::verifier::Verifier;
use sodiumoxide::crypto::auth;

fn main() {
    // Construct a macaroon and serialize it
    let key = auth::gen_key();
    let identifier = "a test";
    let mut m = Macaroon::new(&key, identifier.into(), None).unwrap();
    let data = serde_json::to_string(&m).unwrap();
    println!("{}", data);

    // Add some caveats to the macaroon and then serialize the macaroon (and
    // deserialize, for example sake)
    let caveat_key = auth::gen_key();
    m.add_first_party_caveat(Caveat{
        identifier: "foo = bar".into(),
        ..Default::default()
    }).unwrap();
    m.add_third_party_caveat(&caveat_key, Caveat{
        identifier: "foo = bar".into(),
        location: Some("http://my.auth".into()),
        ..Default::default()
    }).unwrap();

    let data = serde_json::to_string(&m).unwrap();
    println!("{}", data);
    let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
    println!("{:?}", deserialized.signature == m.signature);

    // Create discharge macaroon and bind it
    let mut discharge = Macaroon::new(&caveat_key, "foo = bar".into(), Some("http://my.auth".into())).unwrap();
    discharge.add_first_party_caveat(Caveat{
        identifier: "bar = baz".into(),
        ..Default::default()
    }).unwrap();
    let discharge_bound = m.prepare_for_request(&discharge).unwrap();

    // Succeeding verification
    let mut v = Verifier::default();
    v.satisfy_exact("foo = bar".into());
    v.satisfy_exact("bar = baz".into());
    v.verify(&m, &key, vec![discharge_bound]).unwrap();
}
