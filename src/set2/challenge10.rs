extern crate rustc_serialize;
extern crate openssl;

use self::openssl::crypto::symm::{Crypter, Type, Mode};

use set1::challenge2::fixed_xor;


pub fn cbc_mode(message: Vec<u8>, key: &[u8], iv: &[u8], mode: Mode) -> Vec<u8> {
    let crypter = Crypter::new(Type::AES_128_ECB);
    crypter.init(mode, key, vec![]);
    crypter.pad(false);

    let mut pad = Vec::new();
    pad.push_all(iv);
    let mut result : Vec<u8> = Vec::new();
    for chunk in message.chunks(16) {
        let chunk_enc = fixed_xor(pad.as_slice(), crypter.update(chunk).as_slice());
        pad.clear();
        pad.push_all(chunk);
        result.push_all(chunk_enc.as_slice());
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

    let decrypted_data = cbc_mode(contents, key, iv.as_slice(), Mode::Decrypt);
    let decrypted_string = String::from_utf8_lossy(&decrypted_data);
    println!("{}", decrypted_string);
}

#[test]
fn enc_dec() {
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0;16];
    assert_eq!(cbc_mode(cbc_mode(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], key, iv.as_slice(), Mode::Encrypt), key, iv.as_slice(), Mode::Decrypt),
    vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}
