pub trait Paddable {
    fn pad(&mut self, block_size: usize);
}

impl Paddable for Vec<u8> {
    fn pad(&mut self, block_length: usize) {
        let len = self.len();
        let padding_len = len % block_length;
        self.resize(len + padding_len, padding_len as u8)
    }
}

#[test]
fn challenge9() {
    let input = String::from_str("STRING OVER 16 BYTES");
    let mut input_as_bytes = input.into_bytes();
    input_as_bytes.pad(16);
    assert_eq!(input_as_bytes.len(), 32);
}
