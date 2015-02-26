extern crate serialize;
extern crate core;

use self::serialize::hex::ToHex;

pub fn rotating_key_xor(input: &Vec<u8>, key: &[u8]) -> Vec<u8> {
    input.iter().zip(key.iter().cycle())
        .map(|(l, r)| l ^ *r)
        .take(input.len())
        .collect()
}

#[test]
fn challenge5() {
    let test_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_string().into_bytes();
    assert_eq!(rotating_key_xor(&test_string, "ICE".as_bytes()).to_hex(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}
