extern crate blake2_rfc;
extern crate bn;

use bn::*;
use blake2_rfc::blake2b::blake2b;

/////////////////////////////////////////////////////////////////////
// HASH TO GROUP FUNTIONS
/////////////////////////////////////////////////////////////////////

// used to hash to G1
pub fn blake2b_hash_g1(g: bn::G1, data: &String) -> bn::G1 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to G2
pub fn blake2b_hash_g2(g: bn::G2, data: &String) -> bn::G2 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to Fr
pub fn blake2b_hash_fr(data: &String) -> Fr {
    let hash = blake2b(64, &[], data.as_bytes());
    return Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}
