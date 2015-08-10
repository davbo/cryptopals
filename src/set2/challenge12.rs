extern crate rustc_serialize;

extern crate openssl;

use set1::challenge8::score_ciphertext_for_ecb_mode;

use self::rustc_serialize::base64::FromBase64;

use self::openssl::crypto::symm::{Crypter, Type, Mode};

const MESSAGE: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
const KEY: &'static [u8] = b"YELLOW SUBMARINE";

pub fn encryption_oracle(prepend_bytes: &[u8]) -> Vec<u8> {

    let decoded_message = MESSAGE.from_base64().unwrap();
    let mut plaintext = Vec::new();
    plaintext.extend(prepend_bytes.iter());
    plaintext.extend(decoded_message.iter());

    let crypter = Crypter::new(Type::AES_128_ECB);
    crypter.init(Mode::Encrypt, KEY, vec![]);
    crypter.pad(false);
    let mut ciphertext = crypter.update(plaintext.as_ref());
    ciphertext.extend(crypter.finalize().into_iter());
    ciphertext
}

#[test]
fn challenge_12() {
    let mut block_size = 0;
    for i in 0.. 40 {
        let mut prepend_vec = Vec::new();
        prepend_vec.extend(vec![b'A';i].iter());
        let res = encryption_oracle(&prepend_vec);
        if score_ciphertext_for_ecb_mode(res) == 1 {
            println!("Found block size {:?}", i/2);
            block_size = i/2;
            break;
        }
    }
    // Decrypt each byte in the blocksize
    let mut decrypted_bytes = Vec::new();
    // Probably shouldn't be assuming we'd know the message length..
    let message_length = MESSAGE.len() - (MESSAGE.len()%block_size);
    let mut complete;
    for i in 1.. message_length {
        let capture_block = vec![0 as u8; message_length-i];
        let result = encryption_oracle(&capture_block);
        let (target_permutation, _) = result.split_at(message_length);
        let mut capture_block = vec![0 as u8; message_length-i];
        capture_block.extend(decrypted_bytes.iter());
        complete = true;
        for test_byte in 0.. 255 {
            capture_block.push(test_byte);
            let result = encryption_oracle(&capture_block);
            let (test_permutation, _) = result.split_at(message_length);
            capture_block.pop();
            if test_permutation == target_permutation {
                // Found a match, continue building the prefix
                complete = false;
                decrypted_bytes.push(test_byte);
                break;
            }
        }
        if complete { break; }
    }
    println!("Decrypted: {:?}", String::from_utf8(decrypted_bytes).unwrap());
}
