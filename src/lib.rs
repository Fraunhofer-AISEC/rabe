// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT
extern crate bn;
extern crate rand;
use std::collections::LinkedList;
use std::string::String;
use bn::*;
use rand::Rng;

pub struct AbePublicKey
{
    _g1: bn::G1,
    _g2: bn::G2,
    _e: bn::Gt,
    _g1_beta: bn::G1,
    _g2_beta: bn::G2
}

pub struct AbeMasterKey
{
    _msk: bn::Fr
}

pub struct AbeSecretKey
{
    _sk: f32
}

pub fn abe_setup () -> (AbePublicKey, AbeMasterKey)
{
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random values for alpha and beta
    let rnd_alpha = Fr::random(rng);
    let rnd_beta = Fr::random(rng);
    // generator of group G1:g1 and generator of group G2: g2
    let g1 = G1::one();
    let g2 = G2::one();
    // calculate g1^b and g2^b
    let g1_beta = g1 * rnd_beta;
    let g2_beta = g2 * rnd_beta;
    // calculate pairing
    let e = pairing(g1, g2).pow(rnd_alpha);
    // now generate PK from calculated values
    let pk = AbePublicKey { _g1: g1, _g2: g2, _e: e, _g1_beta: g1_beta, _g2_beta: g2_beta };
    // now generate MSK from calculated values
    let msk = AbeMasterKey { _msk: rnd_alpha };
    return (pk, msk);
}

pub fn abe_keygen (pk: &AbePublicKey,
                   msk: &AbeMasterKey,
                   attributes: &LinkedList<String>) -> Option<AbeSecretKey>
{
    for str in attributes.iter() {
        print!("{}", str);
    }
    return None;
}

pub fn abe_encrypt (pk: &AbePublicKey,
                    policy: String,
                    plaintext: &Vec<u8>,
                    ciphertext: &mut Vec<u8>) -> bool
{
    return true;
}

pub fn abe_decrypt (pk: &AbePublicKey,
                    sk: &AbeSecretKey,
                    ciphertext: &Vec<u8>,
                    plaintext: &mut Vec<u8>) -> bool
{
    return true;
}

pub fn abe_public_key_serialize (pk: &AbePublicKey,
                                 pk_serialized: &mut Vec<u8>) -> bool
{
    return true;
}

pub fn abe_public_key_deserialize (pk_data: &Vec<u8>) -> Option<AbePublicKey>
{
    return None;
}

#[cfg(test)]
mod tests {
    use abe_setup;
    use abe_keygen;
    use AbePublicKey;
    use AbeMasterKey;
    use std::collections::LinkedList;
    use std::string::String;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn test_setup() {
        let (pk,msk) = abe_setup ();
    }
    fn test_keygen() {
        let (pk,msk) = abe_setup ();
        let mut attrs: LinkedList<String> = LinkedList::new();
        attrs.push_back(String::from("a1"));
        attrs.push_back(String::from("a2"));
        attrs.push_back(String::from("a3"));
        let sk = abe_keygen (&pk,&msk,&attrs);
        assert!(!sk.is_none());
        //assert_ne!(None, sk);
    }
}
