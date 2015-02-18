extern crate "rustc-serialize" as rustc_serialize;

use std::iter::AdditiveIterator;
use std::num::Int;
use std::str;

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
    hamming(&first_block, &second_block) / keysize
}


#[test]
fn challenge6() {
    use self::rustc_serialize::base64::FromBase64;
    use std::old_io::File;
    use std::env::current_dir;

    let contents = String::from_utf8(File::open(&current_dir().unwrap().join("data").join("6.txt")).read_to_end().unwrap().from_base64().unwrap()).unwrap();
    let mut likely_keysize: usize = 0;
    for keysize in 2..40 {
        if score_keysize(keysize, &contents) > likely_keysize {
            likely_keysize = keysize;
        }
    }
    println!("Suspected keysize: {}", likely_keysize);
}

#[test]
fn test_hamming() {
    assert_eq!(hamming("this is a test", "wokka wokka!!!"), 37);
}
