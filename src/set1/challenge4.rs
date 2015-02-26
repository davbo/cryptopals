#[test]
fn challenge4() {
    use std::old_io::File;
    use std::old_io::BufferedReader;
    use std::env::current_dir;
    use set1::challenge3::single_character_xor;
    // let mut file = BufferedReader::new(File::open(&current_dir().unwrap().join("data").join("4.txt")));
    // for encrypted_message in file.lines() {
    //     match encrypted_message {
    //         Ok(candidate) => {
    //             let mut results = single_character_xor(candidate.as_slice());
    //             if results.len() > 0 {
    //                 let (best_score, _, ref msg) = results.pop().unwrap();
    //                 if best_score > 2000 {
    //                     assert_eq!("Now that the party is jumping\n", msg.as_slice());
    //                 }
    //             }
    //         },
    //         Err(_) => {}
    //     }
    // }
}
