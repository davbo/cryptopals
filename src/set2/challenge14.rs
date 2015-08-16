extern crate rand;

use self::rand::Rng;
use self::rand::distributions::range::Range;
use self::rand::distributions::Sample;

use set2::challenge12::encryption_oracle;


fn random_input() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut prepend_append_range = Range::new(5,10);
    let count_prepend_bytes = prepend_append_range.sample(&mut rng);


    (0.. count_prepend_bytes).map(|_| -> u8 { rng.gen() }).collect()
}

#[test]
fn challenge14() {

}
