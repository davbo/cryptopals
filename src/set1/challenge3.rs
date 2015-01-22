extern crate serialize;

use self::serialize::hex::{FromHex, ToHex};

use set1::challenge1::convert_to_base64;
use set1::challenge2::fixed_xor;

static ENCRYPTED_MESSAGE : &'static str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";


pub fn decrypt_message(test_key: &str) {
    println!("{}", String::from_utf8(fixed_xor(ENCRYPTED_MESSAGE, test_key).from_hex().unwrap()).unwrap().as_slice());
}


#[test]
fn challenge3() {
    for x in 1u8.. 255 {
        let mut vec : Vec<u8> = vec![x];
        vec.resize(ENCRYPTED_MESSAGE.len()/2, x);
        let test_val = vec.to_hex();
        println!("Attempt {} to decrypt with: {}", x, test_val);
        decrypt_message(test_val.as_slice());
    }
}
