extern crate serialize;

#[test]
fn challenge4() {
    use self::serialize::hex::FromHex;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufReadExt;
    use std::env::current_dir;
    use set1::challenge3::single_character_xor;
    let f = File::open(&current_dir().unwrap().join("data").join("4.txt")).unwrap();
    let reader = BufReader::new(f);
    for encrypted_message in reader.lines() {
        match encrypted_message {
            Ok(candidate) => {
                let mut results = single_character_xor(candidate.from_hex().unwrap().as_slice());
                if results.len() > 0 {
                    let (best_score, _, ref msg) = results.pop().unwrap();
                    if best_score > 6500 {
                        assert_eq!("Now that the party is jumping\n", msg.as_slice());
                        break;
                    }
                }
            },
            Err(_) => {}
        }
    }
}
