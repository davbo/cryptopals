extern crate core;
extern crate serialize;

use self::serialize::hex::{FromHex, ToHex};


pub fn fixed_xor(left: &str, right: &str) -> String {
    let left_int = match (left.from_hex()) {
        Ok(l) => l,
        Err(_) => vec![]
    };
    let right_int = match (right.from_hex()) {
        Ok(r) => r,
        Err(_) => vec![]
    };

    if (left_int.len() != right_int.len()) {
        return String::new();
    }

    let xored_u8: Vec<u8> = left_int.iter().zip(right_int.iter())
        .map(|(l, r)| *l ^ *r)
        .take(left_int.len())
        .collect();
    xored_u8.to_hex()

}

#[test]
fn challenge2() {
    assert_eq!("746865206b696420646f6e277420706c6179",
               fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
}
