
#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rabe::schemes::bsw::*;

fn criterion_benchmark(c: &mut Criterion) {

    // setup scheme
    let (pk, msk) = setup();
    // a set of two attributes matching the policy
    let mut att_matching: Vec<String> = Vec::new();
    att_matching.push(String::from("A"));
    att_matching.push(String::from("B"));
    // our plaintext
    let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
        .into_bytes();
    // our policy
    let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

    c.bench_function("bsw cp-abe encrypt 2 attributes", |b| {
        b.iter(|| encrypt(&pk, &policy, &plaintext))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);



#[bench]
fn bench_cp_decrypt(b: &mut Bencher) {
    // setup scheme
    let (pk, msk) = setup();
    // a set of two attributes matching the policy
    let mut att_matching: Vec<String> = Vec::new();
    att_matching.push(String::from("A"));
    att_matching.push(String::from("B"));
    // our plaintext
    let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
        .into_bytes();
    // our policy
    let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
    // cp-abe ciphertext
    let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext).unwrap();
    // a cp-abe SK key matching
    let sk_matching: CpAbeSecretKey = keygen(&pk, &msk, &att_matching).unwrap();
    b.iter(|| decrypt(&sk_matching, &ct_cp));
}
