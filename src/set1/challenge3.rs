extern crate "rustc-serialize" as rustc_serialize;
extern crate collections;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::old_io::File;
use std::env::current_dir;


use self::collections::string::FromUtf8Error;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;
use self::rustc_serialize::hex::FromHexError;

use set1::challenge2::fixed_xor;



pub fn letter_frequency_from_file(file_path: &Path) -> BTreeMap<u8, usize> {
    let contents = String::from_utf8(File::open(file_path).read_to_end().unwrap()).unwrap();

    let mut count: BTreeMap<u8, usize> = BTreeMap::new();

    // count the number of occurrences of letters in the vec
    for ch in contents.chars() {
        let mut ch_bytes = [0;1];
        ch.encode_utf8(&mut ch_bytes);
        match count.entry(ch_bytes[0]) {
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

pub fn score_bytes(to_score: &Vec<u8>, corpus: &BTreeMap<u8, usize>) -> (usize, Vec<u8>) {
    let mut score = 0;
    let mut modulus = 0;
    let mut buf = 08;
    let mut adjusted_str : Vec<u8> = vec![];

    for byte in to_score {
        buf <<= 4;
        buf |= *byte;

        modulus += 1;
        if modulus == 2 {
            modulus = 0;
            adjusted_str.push(buf);
            match corpus.get(&buf) {
                Some(char_score) => { score += *char_score; }
                None => {},
            }
        }
    }
    (score, adjusted_str)
}

pub fn single_character_xor(encrypted_message: &[u8]) -> Vec<(usize, u8, String)> {
    let english_corpus = current_dir().unwrap().join("data").join("example.txt");
    let letter_count = letter_frequency_from_file(&english_corpus);
    let mut results: Vec<(usize, u8, String)> = Vec::new();
    for x in 0..255 {
        let mut vec : Vec<u8> = vec![x as u8];
        vec.resize(encrypted_message.len()/2, x as u8);
        let test_val = vec.to_hex();
        let res = fixed_xor(encrypted_message, test_val.as_bytes());
        let (score, adjusted_str) = score_bytes(&res, &letter_count);
        let as_string = match String::from_utf8(adjusted_str) {
            Ok(str) => str,
            Err(_) => String::new()
        };
        // println!("x: {}, score: {}, res: {:?}", x, score, as_string);



        if score > 0 {
            results.push((score, x, as_string));
        }
    }
    results.sort_by(|&(s1, _, _), &(s2, _, _)| s1.cmp(&s2));
    results
}


#[test]
fn challenge3() {
    let encrypted_message = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let mut results = single_character_xor(encrypted_message);
    let (score, byte, ref msg) = results.pop().unwrap();
    println!("score: {}, byte: {}, msg: {}", score, byte, msg);
    assert_eq!("Cooking MC's like a pound of bacon", msg.as_slice());
}
