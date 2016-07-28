extern crate rand;

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


#[test]
fn pkcs7_padding() {
    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,2,2], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14]));

    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]));

    assert_eq!(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15], pad(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]));
}

#[test]
fn challenge17() {
    let aes_key = rand::random::<[u8;16]>();
    println!("{:?}", aes_key);
    assert!(true);
}
