extern crate rustc_serialize;
extern crate openssl;
extern crate rand;

use self::openssl::symm::{Crypter, Mode, Cipher};

use set1::challenge2::fixed_xor;


pub fn cbc_mode(message: Vec<u8>, key: &[u8], iv: &[u8], mode: Mode) -> Vec<u8> {
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), mode, key, None).unwrap();
    crypter.pad(false);

    let mut pad = Vec::new();
    pad.extend(iv.iter());
    let mut result : Vec<u8> = Vec::new();
    for chunk in message.chunks(16) {
        let mut cipheroutput = vec![0;32];
        match mode {
            Mode::Decrypt => {
                crypter.update(chunk, &mut cipheroutput).ok();
                let chunk_dec = fixed_xor(&pad, &cipheroutput[0..16]);
                pad.clear();
                pad.extend(chunk.iter());
                result.extend(chunk_dec.iter());
            },
            Mode::Encrypt => {
                crypter.update(&fixed_xor(&pad, &chunk), &mut cipheroutput).ok();
                pad.clear();
                pad.extend(cipheroutput[0..16].iter());
                result.extend(cipheroutput[0..16].iter());
            }
        }
    }
    result
}


#[test]
fn challenge10() {
    use self::rustc_serialize::base64::FromBase64;
    use std::io::Read;
    use std::fs::File;
    use std::env::current_dir;

    let mut contents = Vec::new();
    let path = current_dir().unwrap().join("data").join("10.txt");
    let _ = File::open(&path).unwrap().read_to_end(&mut contents);
    contents = contents.from_base64().unwrap();

    let key = b"YELLOW SUBMARINE";
    let iv = vec![0;16];

    let decrypted_data = cbc_mode(contents, key, iv.as_ref(), Mode::Decrypt);
    let decrypted_string = String::from_utf8_lossy(&decrypted_data);
    println!("{}", decrypted_string);
}

#[test]
fn enc_dec() {
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0;16];
    assert_eq!(cbc_mode(cbc_mode(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], key, iv.as_ref(), Mode::Encrypt), key, iv.as_ref(), Mode::Decrypt),
    vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn enc_dec_longer() {
    use self::rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let aes_key = rng.gen::<[u8;16]>();
    let iv = vec![0;16];
    let test_input = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let expected_result = test_input.clone();
    assert_eq!(cbc_mode(cbc_mode(test_input, &aes_key, &iv, Mode::Encrypt), &aes_key, &iv, Mode::Decrypt),
               expected_result);
}
