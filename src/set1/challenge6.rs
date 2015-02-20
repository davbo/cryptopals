extern crate "rustc-serialize" as rustc_serialize;

use std::iter::AdditiveIterator;
use std::iter::Map;
use std::num::Int;
use std::str;

use self::rustc_serialize::hex::ToHex;

use set1::challenge3::single_character_xor;
use set1::challenge5::rotating_key_xor;

pub fn hamming(left: &str, right: &str) -> usize {
    assert_eq!(left.len(), right.len());

    left.bytes().zip(right.bytes())
        .map(|(l, r)| l ^ r)
        .map(|xored| xored.count_ones())
        .sum()
}

pub fn score_keysize(keysize: usize, encrypted_data: &str) -> usize {
    let mut keysize_iterator = encrypted_data.as_bytes().chunks(keysize);
    let first_block = str::from_utf8(keysize_iterator.next().unwrap()).unwrap();
    let second_block = str::from_utf8(keysize_iterator.next().unwrap()).unwrap();
    let distance = hamming(&first_block, &second_block);
    println!("Hamming dist: {}, keysize: {}, score: {}", distance, keysize, distance/keysize);
    distance/keysize
}

pub fn transpose_blocks(keysize: usize, encrypted_data: &str) -> Vec<String> {
    let keysize_iterator = encrypted_data.as_bytes().chunks(keysize);
    let mut blocks : Vec<String> = Vec::new();
    let num_blocks = encrypted_data.len() / keysize;
    println!("Num blocks: {}", num_blocks);
    blocks.resize(keysize, String::with_capacity(keysize));
    for mut block in keysize_iterator {
        let mut counter = range(0, keysize);
        for ch in block.chars() {
            let count = counter.next().unwrap();
            match ch {
                Ok(c) => {
                    blocks[count].push(c.clone());
                },
                Err(_) => {println!("err")}
            }
        }
    }
    blocks
}


#[test]
fn challenge6() {
    use self::rustc_serialize::base64::FromBase64;
    use std::old_io::File;
    use std::env::current_dir;

    let contents = File::open(&current_dir().unwrap().join("data").join("6.txt")).read_to_end().unwrap().from_base64().unwrap().to_hex();
    let mut scored_keysizes: Vec<(usize, usize)> = vec![];
    for keysize in 2..40 {
        scored_keysizes.push((score_keysize(keysize, &contents), keysize));
    }
    scored_keysizes.sort_by(|s1, s2| s1.0.cmp(&s2.0));
    for i in range(0,10) {
        let possible_keysize = scored_keysizes[i];
        println!("[{}] Trying with keysize: {} it scored: {}", i, possible_keysize.1, possible_keysize.0);
        let blocks = transpose_blocks(possible_keysize.1, &contents);
        let repeating_key = blocks.iter().map(|block| {
            match single_character_xor(&block).pop() {
                Some((score, ch, result)) => ch,
                None => 0
            }
        }).collect();
        println!("{}", rotating_key_xor(&contents, String::from_utf8(repeating_key).unwrap().as_slice()));
    }
}

#[test]
fn test_hamming() {
    assert_eq!(hamming("this is a test", "wokka wokka!!!"), 37);
}
