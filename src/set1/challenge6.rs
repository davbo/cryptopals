extern crate rustc_serialize;


pub fn hamming(left: &[u8], right: &[u8]) -> usize {
    assert_eq!(left.len(), right.len());

    let distance : u32 = left.iter().zip(right.iter())
        .map(|(l, r)| l ^ r)
        .map(|xored| xored.count_ones())
        .fold(0, |acc, item| acc + item);
    distance as usize

}

pub fn score_keysize(keysize: usize, encrypted_data: &Vec<u8>) -> usize {
    let mut keysize_iterator = encrypted_data.chunks(keysize);
    let average_over_distances = 5;
    let sum_distance : usize = (0.. average_over_distances).map(|_| {
        hamming(&keysize_iterator.next().unwrap(), &keysize_iterator.next().unwrap()) / keysize
    }).fold(0, |acc, item| acc + item);
    (sum_distance*100) / average_over_distances
}

pub fn transpose_blocks(keysize: usize, encrypted_data: &Vec<u8>) -> Vec<Vec<u8>> {
    let keysize_iterator = encrypted_data.chunks(keysize);
    let mut blocks : Vec<Vec<u8>> = vec![Vec::with_capacity(keysize); keysize];
    for block in keysize_iterator {
        let mut counter = 0.. keysize;
        for ch in block {
            let count = counter.next().unwrap();
            blocks[count].push(ch.clone());
        }
    }
    blocks
}


#[test]
fn challenge6() {
    use std::fs::File;
    use std::io::Read;
    use std::env::current_dir;

    use self::rustc_serialize::base64::FromBase64;

    use set1::challenge3::single_character_xor;
    use set1::challenge5::rotating_key_xor;

    let path = current_dir().unwrap().join("data").join("6.txt");
    let mut contents = Vec::new();
    let _ = File::open(&path).unwrap().read_to_end(&mut contents);
    contents = contents.from_base64().unwrap();
    let mut scored_keysizes: Vec<(usize, usize)> = vec![];
    for keysize in 2..65 {
        scored_keysizes.push((score_keysize(keysize, &contents), keysize));
    }
    scored_keysizes.sort_by(|s1, s2| s1.0.cmp(&s2.0));
    for i in 0.. 2 {
        let mut key_score = 0;
        let possible_keysize = scored_keysizes[i];
        let blocks = transpose_blocks(possible_keysize.1, &contents);
        let repeating_key : Vec<u8> = blocks.iter().map(|block| {
            match single_character_xor(block.as_ref()).pop() {
                Some((score, ch, _)) => {
                    key_score += score;
                    ch
                },
                None => {
                    println!("Fail: length: {}", block.len());
                    0
                }
            }
        }).collect();
        if key_score > 500000 {
            println!("Trying KEY: {}, it scored {}", String::from_utf8_lossy(repeating_key.as_ref()), key_score);
            println!("{}", String::from_utf8_lossy(rotating_key_xor(&contents, repeating_key.as_ref()).as_ref()).into_owned());
        }
    }
}

#[test]
fn test_hamming() {
    assert_eq!(hamming("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()), 37);
}

#[test]
fn test_keysize() {
    use self::rustc_serialize::hex::FromHex;
    let test_string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".from_hex().unwrap();
    let mut scored_keysizes: Vec<(usize, usize)> = vec![];
    for keysize in 2..7 {
        scored_keysizes.push((score_keysize(keysize, &test_string), keysize));
    }
    scored_keysizes.sort_by(|s1, s2| s1.0.cmp(&s2.0));

    assert_eq!(scored_keysizes[0].1, 3);
}
