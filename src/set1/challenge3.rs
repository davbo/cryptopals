extern crate serialize;
extern crate collections;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::File;
use std::os;

use self::collections::string::FromUtf8Error;
use self::serialize::hex::{FromHex, ToHex};

use set1::challenge1::convert_to_base64;
use set1::challenge2::fixed_xor;

static ENCRYPTED_MESSAGE : &'static str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";


pub fn decrypt_message(test_key: &str) -> Result<String, FromUtf8Error> {
    String::from_utf8(fixed_xor(ENCRYPTED_MESSAGE, test_key).from_hex().unwrap())
}

pub fn letter_frequency_from_file(file_path: &Path) -> BTreeMap<char, usize> {
    let contents = String::from_utf8(File::open(file_path).read_to_end().unwrap()).unwrap();

    let mut count: BTreeMap<char, usize> = BTreeMap::new();

    // count the number of occurrences of letters in the vec
    for x in contents.chars() {
        let X = x.to_uppercase();
        match count.entry(X) {
            Entry::Vacant(view) => {
                view.insert(1);
            },
            Entry::Occupied(mut view) => {
                let v = view.get_mut();
                *v += 1;
            },
        }
    }
    count
}


#[test]
fn challenge3() {
    let ENGLISH_CORPUS = os::getcwd().unwrap().join("example.txt");
    let letter_count = letter_frequency_from_file(&ENGLISH_CORPUS);
    let mut results: Vec<(usize, String)> = Vec::new();
    let mut message: String;
    for x in 1u8.. 255 {
        let mut vec : Vec<u8> = vec![x];
        vec.resize(ENCRYPTED_MESSAGE.len()/2, x);
        let test_val = vec.to_hex();
        let res = decrypt_message(test_val.as_slice());
        match res {
            Ok(decrypted_message) => {
                let mut score = 0;
                for ch in decrypted_message.chars() {
                    match letter_count.get(&ch.to_uppercase()) {
                        Some(char_score) => score += *char_score,
                        None => {},
                    }
                }
                if (score > 0) {
                    let message = decrypted_message.clone();
                    results.push((score, message));
                }
            }
            Err(msg) => {},
        }
    }
    results.sort_by(|&(s1, _), &(s2, _)| s1.cmp(&s2));
    let (best_score, ref msg) = results.pop().unwrap();
    assert_eq!("Cooking MC's like a pound of bacon", msg.as_slice());
}
