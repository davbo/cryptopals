extern crate serialize;
extern crate collections;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::env::current_dir;


use set1::challenge2::fixed_xor;



pub fn letter_frequency_from_file(path: &PathBuf) -> BTreeMap<u8, usize> {
    let mut contents = String::new();
    let _ = File::open(path).unwrap().read_to_string(&mut contents);

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

pub fn score_bytes(to_score: &Vec<u8>, corpus: &BTreeMap<u8, usize>) -> usize {
    let mut score = 0;
    for byte in to_score {
        match corpus.get(&byte) {
            Some(char_score) => { score += *char_score; }
            None => {},
        }
    }
    score
}

pub fn single_character_xor(encrypted_message: &[u8]) -> Vec<(usize, u8, String)> {
    let english_corpus = current_dir().unwrap().join("data").join("example.txt");
    let letter_count = letter_frequency_from_file(&english_corpus);
    let mut results: Vec<(usize, u8, String)> = Vec::new();
    for x in 0u8..250 {
        let mut vec : Vec<u8> = vec![x as u8];
        vec.resize(encrypted_message.len(), x as u8);
        let res = fixed_xor(encrypted_message, vec.as_slice());
        let score = score_bytes(&res, &letter_count);

        if score > 0 {
            let as_string = match String::from_utf8(res) {
                Ok(str) => str,
                Err(_) => String::new()
            };
            results.push((score, x, as_string));
        }
    }
    results.sort_by(|&(s1, _, _), &(s2, _, _)| s1.cmp(&s2));
    results
}


#[test]
fn challenge3() {
    use self::serialize::hex::FromHex;

    let encrypted_message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let mut results = single_character_xor(encrypted_message.from_hex().unwrap().as_slice());
    let (score, byte, ref msg) = results.pop().unwrap();
    println!("score: {}, byte: {}, msg: {}", score, byte, msg);
    assert_eq!("Cooking MC's like a pound of bacon", msg.as_slice());
}
