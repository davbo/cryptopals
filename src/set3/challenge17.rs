extern crate rand;
extern crate rustc_serialize;
extern crate openssl;
use self::openssl::crypto::symm::Mode;
use set2::challenge10::cbc_mode;

const BLOCK_LENGTH: usize = 16;

const INPUT_STRINGS: [&'static str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

fn pad(mut input: Vec<u8>) -> Vec<u8> {
    let input_len = input.len();
    let padding_length = BLOCK_LENGTH - (input.len() % BLOCK_LENGTH);
    if padding_length == 0 {
        input.resize(input_len + BLOCK_LENGTH, 16u8);
    } else {
        input.resize(input_len + padding_length, padding_length as u8);
    }
    input
}


fn decrypt_and_check_padding(ciphertext: Vec<u8>, key: &[u8], iv: &[u8]) -> bool {
    let decrypted = cbc_mode(ciphertext, key, iv, Mode::Decrypt);
    let final_byte = decrypted[decrypted.len()-1];
    let expected_padding = vec![final_byte; final_byte as usize];
    decrypted.ends_with(&expected_padding)
}

#[test]
fn pkcs7_padding() {
    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,2,2], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14]));

    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));

    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]));
}

#[test]
fn challenge17() {
    use self::rustc_serialize::base64::FromBase64;
    use self::rand::{thread_rng, Rng};
    use set1::challenge2::fixed_xor;


    let mut rng = thread_rng();
    let aes_key = rng.gen::<[u8;16]>();
    let iv = rng.gen::<[u8;16]>();
    let choices = &INPUT_STRINGS;
    let input_string = rng.choose(choices).unwrap().from_base64().unwrap();
    let padded_input = pad(input_string);
    println!("Input: {:?}", padded_input);

    let ciphertext = cbc_mode(padded_input.clone(), &aes_key, &iv, Mode::Encrypt);
    assert!(decrypt_and_check_padding(ciphertext.clone(), &aes_key, &iv));

    let mut intermediary: Vec<u8> = vec![];
    for chunk in ciphertext.chunks(BLOCK_LENGTH).rev() {
        for target_index in (0..16).rev() {
            let expected_padding_byte: u8 = BLOCK_LENGTH as u8 - target_index as u8;
            for guess in 0..255 {
                let mut guess_block = vec![0;target_index];
                guess_block.push(guess);
                for val in intermediary.clone().iter().rev() {
                    if guess_block.len() == 16 {
                        break;
                    }
                    guess_block.push(val ^ expected_padding_byte);
                }
                if decrypt_and_check_padding(chunk.to_vec(), &aes_key, &guess_block) {
                    intermediary.push(guess_block[target_index] ^ expected_padding_byte);
                    break;
                }
            }
        }
    }
    let mut cipher_iter = ciphertext.chunks(BLOCK_LENGTH).rev();
    cipher_iter.next();
    let mut plaintext_blocks: Vec<Vec<u8>> = vec![];
    for (cipher_block, intermediary_block) in cipher_iter.zip(intermediary.chunks(BLOCK_LENGTH)) {
        let mut inter_block = intermediary_block.clone().to_owned();
        inter_block.reverse();
        plaintext_blocks.insert(0, fixed_xor(inter_block.as_slice(), cipher_block));
    }
    let plaintext: Vec<u8> = plaintext_blocks.concat();
    println!("{:?}", plaintext);
    assert_eq!(padded_input[padded_input.len()-plaintext.len()..].to_vec(), plaintext);
}
