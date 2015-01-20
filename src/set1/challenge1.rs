extern crate serialize;

use self::serialize::base64::{self, ToBase64};
use self::serialize::hex::FromHex;

pub fn convert_to_base64(input: &str) -> String {
    input.from_hex().unwrap().as_slice().to_base64(base64::STANDARD)
}

#[test]
fn challenge1() {
    assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
               convert_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
}
