extern crate rand;
extern crate openssl;

use set2::challenge10::cbc_mode;
use set2::challenge9::Paddable;
use set1::challenge8::score_ciphertext_for_ecb_mode;

use self::openssl::crypto::symm::{Crypter, Type, Mode};

use self::rand::Rng;
use self::rand::distributions::range::Range;
use self::rand::distributions::Sample;

pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let use_cbc_mode: bool = rng.gen();

    let mut prepend_append_range = Range::new(5,10);
    let count_prepend_bytes = prepend_append_range.sample(&mut rng);
    let count_append_bytes = prepend_append_range.sample(&mut rng);


    println!("input: {:?} - len {}", input, input.len());
    let prepend_bytes: Vec<u8> = (0.. count_prepend_bytes).map(|_| -> u8 { rng.gen() }).collect();
    let append_bytes: Vec<u8> = (0.. count_append_bytes).map(|_| -> u8 { rng.gen() }).collect();

    let mut plaintext: Vec<u8> = prepend_bytes.iter().cloned().chain(input.iter().cloned().chain(append_bytes.iter().cloned())).collect();
    plaintext.pad(16);
    println!("plaintext: {:?} - len {}", plaintext, plaintext.len());


    let key: Vec<u8> = (0.. 16).map(|_| -> u8 { rng.gen() }).collect();

    if use_cbc_mode {
        println!("Using CBC mode");
        cbc_mode(plaintext, key.as_slice(), key.as_slice(), Mode::Encrypt)
    } else {
        println!("Using ECB mode");
        let crypter = Crypter::new(Type::AES_128_ECB);
        crypter.init(Mode::Encrypt, key.as_slice(), vec![]);
        crypter.pad(false);
        let mut ciphertext = crypter.update(plaintext.as_slice());
        ciphertext.extend(crypter.finalize().into_iter());
        ciphertext
    }
}

#[test]
fn challenge11() {
    let ciphertext = encryption_oracle(b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE");
    if score_ciphertext_for_ecb_mode(ciphertext) == 1 {
        println!("Detected ECB Mode");
    } else {
        println!("Detected CBC Mode");
    }
}
