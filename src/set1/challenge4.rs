extern crate rustc_serialize;
use std::ops::Deref;

#[test]
fn challenge4() {
    use self::rustc_serialize::hex::FromHex;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::env::current_dir;
    use set1::challenge3::single_character_xor;
    let f = File::open(&current_dir().unwrap().join("data").join("4.txt")).unwrap();
    let reader = BufReader::new(f);
    for encrypted_message in reader.lines() {
        match encrypted_message {
            Ok(candidate) => {
                let mut results = single_character_xor(candidate.from_hex().unwrap().deref());
                if results.len() > 0 {
                    let (best_score, _, ref msg) = results.pop().unwrap();
                    if best_score > 6500 {
                        assert_eq!("Now that the party is jumping\n", msg);
                        break;
                    }
                }
            },
            Err(_) => {}
        }
    }
}
