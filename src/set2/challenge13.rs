extern crate openssl;

use self::openssl::symm;


const KEY: &'static [u8] = b"YELLOW SUBMARINE";

struct Profile {
    uid: u32,
    email: String,
    role: String,
}

impl Profile {

    pub fn new(email: String) -> Profile {
        let mut sanitised_input = String::new();
        sanitised_input = email.replace("&", "").replace("=", "");
        Profile {
            email: sanitised_input,
            uid: 10,
            role: "user".to_string(),
        }

    }

}

impl ToString for Profile {
    fn to_string(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }
}

fn encrypt(plaintext: String) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    symm::encrypt(cipher, KEY, None, &plaintext.as_bytes()).unwrap()
}

fn decrypt(ciphertext: Vec<u8>) -> String {
    let cipher = symm::Cipher::aes_128_ecb();
    let plaintext = symm::decrypt(cipher, KEY, None, &ciphertext).unwrap();
    String::from_utf8(plaintext).unwrap()
}

#[test]
fn profile_prints_url_formatted() {
    let test_prof = Profile::new("foo@bar.com".to_string());
    assert_eq!(test_prof.to_string(),
    "email=foo@bar.com&uid=10&role=user");
}

#[test]
fn eat_metachars() {
    let test_prof = Profile::new("foo@bar.com&role=admin".to_string());
    assert_eq!(test_prof.to_string(),
    "email=foo@bar.comroleadmin&uid=10&role=user");
}

#[test]
fn encrypt_decrypt() {
    let test_prof = Profile::new("foo@bar.com".to_string());
    assert_eq!(decrypt(encrypt(test_prof.to_string())),
    "email=foo@bar.com&uid=10&role=user");
}

#[test]
fn challenge13() {
    let mut test_email = String::from("a@bar.com");
    let mut len_enc = encrypt(Profile::new(test_email.clone()).to_string()).len();
    let mut test_len = len_enc;
    while (test_len == len_enc) {
        test_email.insert(0, 'a');
        test_len = encrypt(Profile::new(test_email.clone()).to_string()).len();
    }
    println!("test_email: {0}, test_len: {1}, len_enc: {2}", test_email, test_len, len_enc);
    test_email.insert(0, 'a');
    test_email.insert(0, 'a');
    test_email.insert(0, 'a');
    test_email.insert(0, 'a');
    let ciphertext = encrypt(Profile::new(test_email.clone()).to_string());
    println!("ciphertext: {0:?}, len: {1}", ciphertext, ciphertext.len());
    let mut username = String::from("aaaaaaaaaaadmin").into_bytes();
    let padding_len = 16-"admin".len();
    username.extend(vec![padding_len as u8; padding_len].iter());
    username.extend(String::from("@bar.com").into_bytes().iter());
    let embedded_admin = encrypt(Profile::new(String::from_utf8(username).unwrap()).to_string());
    println!("{0:?} - {1:?}", ciphertext, embedded_admin);
    let mut built_message: Vec<u8> = Vec::new();
    built_message.extend(ciphertext[..ciphertext.len()-16].iter());
    built_message.extend(embedded_admin[16..32].iter());
    println!("{0:?}", built_message);
    let decrypted = decrypt(built_message.clone());
    println!("{0}", decrypted);
    assert_eq!(decrypted, "email=aaaaaaaaaaaaaaaaaaaaa@bar.com&uid=10&role=admin");


}
