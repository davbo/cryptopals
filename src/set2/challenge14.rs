extern crate rand;

use self::rand::Rng;
use self::rand::distributions::range::Range;
use self::rand::distributions::Sample;

use set1::challenge8::score_ciphertext_for_ecb_mode;
use set1::challenge8::find_repeating_blocks;
use set2::challenge12;

const MESSAGE: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
const KEY: &'static [u8] = b"YELLOW SUBMARINE";

fn random_input() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut prepend_append_range = Range::new(5,50);
    let count_prepend_bytes = prepend_append_range.sample(&mut rng);


    (0.. count_prepend_bytes).map(|_| -> u8 { rng.gen() }).collect()
}

fn encryption_oracle(attacker_input: &[u8]) -> Vec<u8> {
    let mut user_input = random_input();
    user_input.extend(attacker_input.iter().cloned());
    challenge12::encryption_oracle(&user_input)
}

fn find_target_permutation(byte_index: usize, block_size: usize, marker_cipher: Vec<u8>) -> Vec<u8> {
    let message_length = MESSAGE.len() - (MESSAGE.len()%block_size);
    let capture_block = vec![1 as u8; message_length-(byte_index+1)];
    let num_capture_blocks = capture_block.len() / 16;
    let mut attack_input = vec![0 as u8; block_size];
    attack_input.extend(capture_block);
    let mut target_permutation = vec![];
    let mut found_marker = false;
    while !found_marker {
        let ciphertext = encryption_oracle(&attack_input);
        println!("New cipher");
        {
            let chunks = ciphertext.chunks(block_size);
            let mut remaining = chunks.skip_while(|ch| !marker_cipher.starts_with(ch)).peekable();
            if !remaining.peek().is_none() {
                println!("found marker");
                found_marker = true;
                target_permutation = remaining.take(num_capture_blocks).flat_map(|s| s).map(|v| *v).collect();
            }

        }
    }
    target_permutation
}

fn find_marker_block(block_size: usize) -> Vec<u8> {
    let marker_discovery = vec![0 as u8; block_size*5];
    let ciphertext = encryption_oracle(&marker_discovery);
    let repeat_blocks = find_repeating_blocks(&ciphertext);
    let mut most_repeats : usize = 0;
    let mut marker_block = vec![];
    for (key, value) in repeat_blocks.iter() {
        if value > &most_repeats {
            most_repeats = *value;
            marker_block.clear();
            marker_block.extend(key.iter());
        }
    }
    marker_block
}

#[test]
fn challenge14() {
    let mut block_size = 16;
    let marker_block = find_marker_block(block_size);
    println!("Found marker block {:?}", marker_block);
    let target_permutation = find_target_permutation(0, block_size, marker_block);
    println!("Found target {:?}", target_permutation);

    // Decrypt each byte in the blocksize
    let mut decrypted_bytes = Vec::new();
    // Probably shouldn't be assuming we'd know the message length..
    let message_length = MESSAGE.len() - (MESSAGE.len()%block_size);
    let mut complete;
    for i in 1.. message_length {
        let capture_block = vec![0 as u8; message_length-i];
        let result = encryption_oracle(&capture_block);
        let (target_permutation, _) = result.split_at(message_length);
        let mut capture_block = vec![0 as u8; message_length-i];
        capture_block.extend(decrypted_bytes.iter());
        complete = true;
        for test_byte in 0.. 255 {
            capture_block.push(test_byte);
            let result = encryption_oracle(&capture_block);
            let (test_permutation, _) = result.split_at(message_length);
            capture_block.pop();
            if test_permutation == target_permutation {
                // Found a match, continue building the prefix
                complete = false;
                decrypted_bytes.push(test_byte);
                break;
            }
        }
        if complete { break; }
    }
    println!("Decrypted: {:?}", String::from_utf8(decrypted_bytes).unwrap());
    // assert!(false);
}
