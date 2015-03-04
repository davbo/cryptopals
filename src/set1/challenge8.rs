use std::slice::SliceExt;

pub fn score_ciphertext_for_ecb_mode(candidate: Vec<u8>) -> usize {
    let mut score = 0;
    for out_win in candidate.windows(4) {
        for in_win in candidate.windows(4) {
            if out_win == in_win {
                score += 1
            }
        }
        score -= 1
    }
    score
}

#[test]
fn challenge8() {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufReadExt;
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
