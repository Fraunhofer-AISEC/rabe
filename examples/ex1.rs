extern  crate rabe;

use rabe::schemes::ac17::*;
use rabe::utils::policy::pest::PolicyLanguage;

fn main() {
    let (pk, msk) = setup();
    let plaintext = String::from("our plaintext!").into_bytes();
    let policy = String::from(r#""A" and "B""#);
    let ct: Ac17KpCiphertext = kp_encrypt(
        &pk,
        &vec!["A".to_string(), "B".to_string()],
        &plaintext
    ).unwrap();
    let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
    assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
}