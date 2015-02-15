extern crate "rustc-serialize" as rustc_serialize;
extern crate collections;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::old_io::File;
use std::env::current_dir;


use self::collections::string::FromUtf8Error;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;

use set1::challenge2::fixed_xor;



pub fn decrypt_message(encrypted_message: &str, test_key: &str) -> Result<String, FromUtf8Error> {
    String::from_utf8(fixed_xor(encrypted_message, test_key).from_hex().unwrap())
}

pub fn letter_frequency_from_file(file_path: &Path) -> BTreeMap<char, usize> {
    let contents = String::from_utf8(File::open(file_path).read_to_end().unwrap()).unwrap();

    let mut count: BTreeMap<char, usize> = BTreeMap::new();

    // count the number of occurrences of letters in the vec
    for ch in contents.chars() {
        match count.entry(ch.to_uppercase()) {
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

pub fn single_character_xor(encrypted_message: &str) -> Vec<(usize, String)> {
    let english_corpus = current_dir().unwrap().join("data").join("example.txt");
    let letter_count = letter_frequency_from_file(&english_corpus);
    let mut results: Vec<(usize, String)> = Vec::new();
    for x in 1u8.. 255 {
        let mut vec : Vec<u8> = vec![x];
        vec.resize(encrypted_message.len()/2, x);
        let test_val = vec.to_hex();
        let res = decrypt_message(encrypted_message, test_val.as_slice());
        match res {
            Ok(decrypted_message) => {
                let mut score = 0;
                for ch in decrypted_message.chars() {
                    match letter_count.get(&ch.to_uppercase()) {
                        Some(char_score) => score += *char_score,
                        None => {},
                    }
                }
                if score > 0 {
                    results.push((score, decrypted_message.clone()));
                }
            }
            Err(_) => {},
        }
    }
    results.sort_by(|&(s1, _), &(s2, _)| s1.cmp(&s2));
    results
}


#[test]
fn challenge3() {
    let encrypted_message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let mut results = single_character_xor(encrypted_message);
    let (_, ref msg) = results.pop().unwrap();
    assert_eq!("Cooking MC's like a pound of bacon", msg.as_slice());
}
