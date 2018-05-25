extern crate rustc_serialize;
extern crate openssl;


#[test]
fn challenge7() {
    use self::openssl::symm::{decrypt, Cipher};
    use self::rustc_serialize::base64::FromBase64;
    use std::io::Read;
    use std::fs::File;
    use std::env::current_dir;

    let mut contents = Vec::new();
    let path = current_dir().unwrap().join("data").join("7.txt");
    let _ = File::open(&path).unwrap().read_to_end(&mut contents);
    contents = contents.from_base64().unwrap();

    let key = b"YELLOW SUBMARINE";
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, &contents).unwrap();
    let decrypted_string = String::from_utf8(plaintext).unwrap();
    assert!(decrypted_string.contains("Play that funky music"));
}
