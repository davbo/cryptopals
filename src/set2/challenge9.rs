pub trait Paddable {
    fn pad(&mut self, block_length: usize);
}

impl Paddable for Vec<u8> {
    fn pad(&mut self, block_length: usize) {
        let len = self.len();
        let modulus_block_length = len % block_length;
        if modulus_block_length != 0 {
            let pad_by = block_length - modulus_block_length;
            self.resize(len + pad_by, pad_by as u8)
        }
    }
}

#[test]
fn challenge9() {
    let input = String::from_str("STRING OVER 16 BYTES");
    let mut input_as_bytes = input.into_bytes();
    input_as_bytes.pad(16);
    assert_eq!(input_as_bytes.len(), 32);
}

#[test]
fn should_stay_at_block_length() {
    let input = String::from_str("YELLOW SUBMARINE");
    let mut input_as_bytes = input.into_bytes();
    input_as_bytes.pad(16);
    assert_eq!(input_as_bytes.len(), 16);
}
