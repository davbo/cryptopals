extern crate "rustc-serialize" as rustc_serialize;
extern crate openssl;


#[test]
fn challenge7() {
    use self::openssl::crypto::symm::{Crypter, Type, Mode};
    use self::rustc_serialize::base64::FromBase64;
    use std::io::Read;
    use std::fs::File;
    use std::env::current_dir;

    let mut contents = Vec::new();
    let path = current_dir().unwrap().join("data").join("7.txt");
    let _ = File::open(&path).unwrap().read_to_end(&mut contents);
    contents = contents.from_base64().unwrap();

    let key = b"YELLOW SUBMARINE";
    let crypter = Crypter::new(Type::AES_128_ECB);
    crypter.init(Mode::Decrypt, key, vec![]);
    crypter.pad(false);
    let decrypted_data = crypter.update(contents.as_slice());
    let decrypted_string = String::from_utf8(decrypted_data).unwrap();
    assert!(decrypted_string.contains("Play that funky music"));
}
