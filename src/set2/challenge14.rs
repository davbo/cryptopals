extern crate rand;
use self::rand::Rng;
use self::rand::distributions::range::Range;
use self::rand::distributions::Sample;

use set1::challenge8::find_repeating_blocks;
use set2::challenge12;

const MESSAGE: &'static [u8] = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

fn random_input() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut prepend_append_range = Range::new(5,50);
    let count_prepend_bytes = prepend_append_range.sample(&mut rng);


    (0.. count_prepend_bytes).map(|_| -> u8 { rng.gen() }).collect()
}

fn encryption_oracle(attacker_input: &[u8]) -> Vec<u8> {
    println!("oracle");
    let mut user_input = random_input();
    user_input.extend(attacker_input.iter().cloned());
    challenge12::encryption_oracle(&user_input)
}

fn find_target_permutation(byte_index: usize, block_size: usize, marker_cipher: Vec<u8>, decrypted_bytes: &[u8]) -> Vec<u8> {
    let message_length = MESSAGE.len();
    let capture_block = vec![1 as u8; message_length-((byte_index)+1)];
    let mut attack_input = vec![9 as u8; block_size];
    attack_input.extend(capture_block);
    let num_capture_blocks = (attack_input.len() / block_size) + (decrypted_bytes.len() / block_size);
    let mut target_permutation = vec![];
    let mut found_marker = false;
    while !found_marker {
        let ciphertext = encryption_oracle(&attack_input);
        {
            let chunks = ciphertext.chunks(block_size);
            let mut remaining = chunks.skip_while(|ch| !marker_cipher.starts_with(ch)).peekable();
            if !remaining.peek().is_none() {
                found_marker = true;

                let target_block = if num_capture_blocks < remaining.size_hint().1.unwrap() {
                    remaining.nth(num_capture_blocks).unwrap()
                } else {
                    remaining.last().unwrap()
                };
                target_permutation.extend(target_block);
            }

        }
    }
    target_permutation
}

fn test_byte(candidate: u8, byte_index: usize, block_size: usize, marker_cipher: Vec<u8>, target_permutation: Vec<u8>, decrypted_bytes: &[u8]) -> bool {
    let message_length = MESSAGE.len();
    let mut capture_block = vec![1 as u8; message_length-(byte_index+1)];
    capture_block.extend(decrypted_bytes.iter());
    capture_block.push(candidate);
    let mut num_capture_blocks = capture_block.len() / block_size;
    if capture_block.len() % block_size != 0 {
        num_capture_blocks +=1;
    }
    let mut attack_input = vec![9 as u8; block_size];
    attack_input.extend(capture_block.clone());
    let mut found_marker = false;
    let mut result = false;
    while !found_marker {
        let ciphertext = encryption_oracle(&attack_input);
        {
            let chunks = ciphertext.chunks(block_size);
            let mut remaining = chunks.skip_while(|ch| !marker_cipher.starts_with(ch)).peekable();
            if !remaining.peek().is_none() {
                found_marker = true;
                let test_block = remaining.nth(num_capture_blocks);
                if candidate == 48 {
                    println!("Candidate: {}, Test block: {:?}, target: {:?}", candidate, test_block, target_permutation);
                }
                result = match test_block {
                    Some(block) if block == target_permutation.as_slice() => true,
                    _ => false,
                };
            }

        }
    }
    result
}

fn find_marker_block(block_size: usize) -> Vec<u8> {
    let marker_discovery = vec![9 as u8; block_size*5];
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
    let block_size = 16;
    let marker_block = find_marker_block(block_size);

    let message_length = MESSAGE.len();
    let mut decrypted_bytes = Vec::new();
    for i in 0.. message_length {
        let target_permutation = find_target_permutation(i, block_size, marker_block.clone(), &decrypted_bytes);
        let mut matched = false;
        for candidate in 0.. 128 {
            matched = test_byte(candidate, i, block_size, marker_block.clone(), target_permutation.clone(), &decrypted_bytes);
            if matched {
                decrypted_bytes.push(candidate);
                break;
            }
        }
        println!("i {} - decrypted {}", i, decrypted_bytes.len());
        if !matched {
            println!("Unable to decrypt {:?}", target_permutation);
            // break;
        }
    }
    assert!(String::from_utf8(decrypted_bytes).unwrap().starts_with(
        "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by"));
}
