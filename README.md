# Rusty Macaroon

A Rust implementation of
[Macaroons](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/41892.pdf)
loosely based off of the [C reference
implementation](https://github.com/rescrv/libmacaroons) with a focus on the [v2
spec](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt).

## Examples
There is currently a fully working example in the [examples
directory](./examples). To run it, simply execute:

```shell
$ cargo run --example first_party
```

## Current Status
:rotating_light: :rotating_light: This is _very_ alpha and NOT READY FOR
PRODUCTION :rotating_light: :rotating_light:

With that said, here is what is done and not done.

- [x] Create a new macaroon
- [x] Add first-party caveats
- [x] Add third-party caveats
- [x] Validate macaroon with first-party caveats
- [ ] Validate macaroon with third-party caveats
- [x] Serialize and deserialize macaroons from JSON
- [ ] Serialize and deserialize macaroons using v2 binary format
- [ ] Unit tests

### Other future enhancements
As we continue to work on this, we may create a separate crate that also defines
common caveat validators (such as checking for expiration of a time). But as of
now, we are just trying to get to feature complete

## Contributing
We :heart: any contributions. Most of us are fairly new to Rust, so any fixes to
make things simpler or more idiomatic are also more than welcome. Please open a
pull request if you have something you want to contribute
