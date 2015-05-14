extern crate rand;
extern crate rustc_serialize;

extern crate openssl;

use set1::challenge8::score_ciphertext_for_ecb_mode;

use self::rand::Rng;
use self::rand::distributions::range::Range;
use self::rand::distributions::Sample;

use self::rustc_serialize::base64::{self, FromBase64};

use self::openssl::crypto::symm::{Crypter, Type, Mode};

const MESSAGE: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
const KEY: &'static [u8] = b"YELLOW SUBMARINE";

pub fn encryption_oracle(mut prepend_bytes: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let plaintext = MESSAGE.from_base64().unwrap();
    prepend_bytes.push_all(&plaintext);

    let crypter = Crypter::new(Type::AES_128_ECB);
    crypter.init(Mode::Encrypt, KEY, vec![]);
    crypter.pad(false);
    let mut ciphertext = crypter.update(prepend_bytes.as_slice());
    ciphertext.extend(crypter.finalize().into_iter());
    ciphertext
}

#[test]
fn challenge_12() {
    for i in 1.. 40 {
        let mut prepend_vec = Vec::new();
        prepend_vec.resize(i, b'A');
        let res = encryption_oracle(prepend_vec);
        if score_ciphertext_for_ecb_mode(res) == 1 {
            println!("Found block size {:?}", i/2);
            break;
        }
    }
}
