extern crate core;
extern crate collections;

use std::iter::AdditiveIterator;
use std::slice::SliceExt;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

pub fn score_ciphertext_for_ecb_mode(candidate: Vec<u8>) -> usize {
    let mut count: BTreeMap<&[u8], usize> = BTreeMap::new();

    for win in candidate.windows(4) {
        match count.entry(win) {
            Entry::Vacant(view) => {
                view.insert(0);
            },
            Entry::Occupied(mut view) => {
                let v = view.get_mut();
                *v += 1;
            },
        }
    }
    let counts : Vec<&usize> = count.values().collect();
    let summer = counts.iter().cloned();
    summer.map(|v| *v).sum()
}

#[test]
fn challenge8() {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::env::current_dir;
    let f = File::open(&current_dir().unwrap().join("data").join("8.txt")).unwrap();
    let reader = BufReader::new(f);
    let mut scored_ciphertexts : Vec<(String, usize)> = vec![];
    for ciphertext in reader.lines() {
        match ciphertext {
            Ok(candidate) => {
                scored_ciphertexts.push((candidate.clone(), score_ciphertext_for_ecb_mode(candidate.into_bytes())));
            }
            Err(_) => {}
        }
    }
    scored_ciphertexts.sort_by(|&(_, score1), &(_, score2)| score1.cmp(&score2));
    let (best_candidate, top_score) = scored_ciphertexts.pop().unwrap();
    println!("{} - {}", best_candidate, top_score);
}
