extern crate rand;
extern crate openssl;

use set2::challenge10::cbc_mode;
use set2::challenge9::Paddable;

use self::openssl::symm::{Crypter, Mode, Cipher};

use self::rand::Rng;

pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let use_cbc_mode: bool = rng.gen();

    let count_prepend_bytes = rng.gen_range(5,10);
    let count_append_bytes = rng.gen_range(5,10);


    println!("input: {:?} - len {}", input, input.len());
    let prepend_bytes: Vec<u8> = (0.. count_prepend_bytes).map(|_| -> u8 { rng.gen() }).collect();
    let append_bytes: Vec<u8> = (0.. count_append_bytes).map(|_| -> u8 { rng.gen() }).collect();

    let mut plaintext: Vec<u8> = prepend_bytes.iter().cloned().chain(input.iter().cloned().chain(append_bytes.iter().cloned())).collect();
    plaintext.pad(16);
    println!("plaintext: {:?} - len {}", plaintext, plaintext.len());


    let key: Vec<u8> = (0.. 16).map(|_| -> u8 { rng.gen() }).collect();

    if use_cbc_mode {
        println!("Using CBC mode");
        cbc_mode(plaintext, key.as_ref(), key.as_ref(), Mode::Encrypt)
    } else {
        println!("Using ECB mode");
        let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key.as_ref(), None).unwrap();
        crypter.pad(false);
        let mut ciphertext = vec![0;plaintext.len()+16];
        crypter.update(plaintext.as_ref(), &mut ciphertext).ok();
        crypter.finalize(&mut ciphertext).ok();
        ciphertext
    }
}

#[test]
fn challenge11() {
    use set1::challenge8::score_ciphertext_for_ecb_mode;
    let ciphertext = encryption_oracle(b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE");
    if score_ciphertext_for_ecb_mode(ciphertext) == 1 {
        println!("Detected ECB Mode");
    } else {
        println!("Detected CBC Mode");
    }
}
