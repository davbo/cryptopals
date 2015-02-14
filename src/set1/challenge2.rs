extern crate core;
extern crate serialize;

use self::serialize::hex::{FromHex, ToHex};


pub fn fixed_xor(left: &str, right: &str) -> String {
    let left_int = left.from_hex().unwrap();
    let right_int = right.from_hex().unwrap();

    assert_eq!(left_int.len(), right_int.len());

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
