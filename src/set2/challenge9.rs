trait Paddable {
    fn pad(&mut self, block_size: usize);
}

impl Paddable for Vec<u8> {
    fn pad(&mut self, block_length: usize) {
        let padding_len = block_length - self.len();
        self.resize(block_length, padding_len as u8)
    }
}

#[test]
fn challenge9() {
    let input = String::from_str("YELLOW SUBMARINE");
    let mut input_as_bytes = input.into_bytes();
    input_as_bytes.pad(20);
    assert_eq!(input_as_bytes.len(), 20);
}
