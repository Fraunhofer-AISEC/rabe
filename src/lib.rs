#[macro_use]
extern crate serde_derive;
extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;
extern crate blake2_rfc;

use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;


#[macro_use]
extern crate arrayref;

pub mod policy;
pub mod ac17;
pub mod aw11;
pub mod bsw;
pub mod lsw;
pub mod tools;
pub mod secretsharing;

use ac17::*;

//#[doc = /**
// * DOC
// *
// */]


#[no_mangle]
pub extern "C" fn ac17kpabe_context_create() -> *mut Ac17Context {
    let (pk, msk) = ac17_setup();
    let _ctx = unsafe { transmute(Box::new(Ac17Context { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn ac17kpabe_context_destroy(ctx: *mut Ac17Context) {
    let _ctx: Box<Ac17Context> = unsafe { transmute(ctx) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn ac17kpabe_secret_key_create(
    ctx: *mut Ac17Context,
    policy: *mut c_char,
) -> *mut Ac17KpSecretKey {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _ctx = unsafe { &mut *ctx };
    let sk = ac17kp_keygen(&_ctx._msk, &pol).unwrap();
    let _sk = unsafe {
        transmute(Box::new(Ac17KpSecretKey {
            _policy: sk._policy.clone(),
            _k: sk._k.clone(),
            _k_0: sk._k_0.clone(),
        }))
    };
    _sk
}

#[no_mangle]
pub extern "C" fn ac17kpabe_secret_key_destroy(sk: *mut Ac17KpSecretKey) {
    let _sk: Box<Ac17KpSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}
/*
#[no_mangle]
pub extern "C" fn ac17kpabe_encrypt_native(
    pk: *mut Ac17PublicKey,
    attributes: *mut Vec<String>,
    //data??,
) -> i32 {
    let _attr = unsafe { &mut *attributes };
    let mut attr_vec: Vec<_> = _attr.iter() // do NOT into_iter()
        .map(|arg| arg.to_string())
        .collect();
    let _pk = unsafe { &mut *pk };
    //conv data?? to [u8],
    let ct = ac17kp_encrypt(&_pk, &attr_vec, _data).unwrap();
    let _ct = unsafe {
        transmute(Box::new(Ac17KpCiphertext {
            _attr: ct._attr.clone(),
            _c_0: ct._c_0.clone(),
            _c: ct._c.clone(),
            _c_p: ct._c_p.clone(),
            _ct: ct._ct.clone(),
            _iv: ct._iv.clone(),
        }))
    };
    _ct
}
*/

#[no_mangle]
pub extern "C" fn ac17kpabe_decrypt_native(sk: *mut Ac17KpCiphertext, ct: *mut c_char) -> i32 {
    //TODO: Deserialize ct
    //TODO: Call abe_decrypt
    //TODO: serialize returned pt and store under pt
    return 1;
}



// TESTS:

#[cfg(test)]
mod tests {
    // bsw cp-abe
    use cpabe_setup;
    use cpabe_keygen;
    use cpabe_encrypt;
    use cpabe_decrypt;
    use cpabe_delegate;
    use CpAbeCiphertext;
    use CpAbeSecretKey;
    // ac17 abe
    use ac17_setup;
    // ac17 cp-abe
    use ac17cp_keygen;
    use ac17cp_encrypt;
    use ac17cp_decrypt;
    use Ac17CpCiphertext;
    use Ac17CpSecretKey;
    // ac17 kp-abe
    use ac17kp_keygen;
    use ac17kp_encrypt;
    use ac17kp_decrypt;
    use Ac17KpCiphertext;
    use Ac17KpSecretKey;
    // lse kp-abe
    use KpAbeCiphertext;
    use KpAbeSecretKey;
    use kpabe_setup;
    use kpabe_keygen;
    use kpabe_encrypt;
    use kpabe_decrypt;
    // aw11 cp-abe
    use aw11_global;
    use aw11_setup;
    use aw11_keygen;
    use aw11_encrypt;
    use aw11_decrypt;
    use Aw11GlobalKey;
    use Aw11PublicKey;
    use Aw11MasterKey;
    use Aw11Ciphertext;
    use Aw11SecretKey;
    // general tools
    use traverse_str;
    use calc_pruned_str;
    //use traverse_json;
    use gen_shares;
    use recover_secret;
    //use blake2b_hash_g1;
    //use blake2b_hash_fr;
    // general struct
    use AbePolicy;
    // other libs
    use std::string::String;
    use bn::*;
    use rand;
    use num_bigint::BigInt;
    use bincode::rustc_serialize::encode;
    use rustc_serialize::Encodable;
    use bincode::SizeLimit::Infinite;
    use rustc_serialize::hex::ToHex;

    pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| {
            BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
                .unwrap()
                .to_str_radix(10)
        })
    }

    fn setup_sets() -> Vec<Vec<String>> {
        let mut _return: Vec<Vec<String>> = Vec::new();
        // a set of one attribute
        let mut _one: Vec<String> = Vec::new();
        _one.push(String::from("0"));
        // a set of five attributes
        let mut _five: Vec<String> = Vec::new();
        for _i in 0usize..5 {
            _five.push(_i.to_string());
        }
        // a set of five attributes
        let mut _ten: Vec<String> = Vec::new();
        for _i in 0usize..10 {
            _ten.push(_i.to_string());
        }
        // a set of five attributes
        let mut _twenty_five: Vec<String> = Vec::new();
        for _i in 0usize..25 {
            _twenty_five.push(_i.to_string());
        }
        // a set of five attributes
        let mut _fifty: Vec<String> = Vec::new();
        for _i in 0usize..50 {
            _fifty.push(_i.to_string());
        }
        // a set of five attributes
        let mut _hundred: Vec<String> = Vec::new();
        for _i in 0usize..100 {
            _hundred.push(_i.to_string());
        }
        _return.push(_one);
        _return.push(_five);
        _return.push(_ten);
        _return.push(_twenty_five);
        _return.push(_fifty);
        _return.push(_hundred);

        return _return;
    }


    #[test]
    fn test_traverse() {
        let policyfalse = String::from(r#"joking-around?"#);
        let policy1 = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy2 = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy3 = String::from(
            r#"{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}"#,
        );

        let mut _set0: Vec<String> = Vec::new();
        _set0.push(String::from("X"));
        _set0.push(String::from("Y"));

        let mut _set1: Vec<String> = Vec::new();
        _set1.push(String::from("A"));
        _set1.push(String::from("B"));

        let mut _set2: Vec<String> = Vec::new();
        _set2.push(String::from("C"));
        _set2.push(String::from("D"));

        let mut _set3: Vec<String> = Vec::new();
        _set3.push(String::from("A"));
        _set3.push(String::from("B"));
        _set3.push(String::from("C"));
        _set3.push(String::from("D"));

        assert_eq!(traverse_str(&_set1, &policyfalse), false);

        assert_eq!(traverse_str(&_set0, &policy1), false);
        assert_eq!(traverse_str(&_set1, &policy1), true);
        assert_eq!(traverse_str(&_set2, &policy1), false);
        assert_eq!(traverse_str(&_set3, &policy1), true);

        assert_eq!(traverse_str(&_set1, &policy2), true);
        assert_eq!(traverse_str(&_set2, &policy2), false);
        assert_eq!(traverse_str(&_set3, &policy2), true);

        assert_eq!(traverse_str(&_set1, &policy3), false);
        assert_eq!(traverse_str(&_set2, &policy3), false);
        assert_eq!(traverse_str(&_set3, &policy3), true);
    }

    #[test]
    fn test_cp_abe_and() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();


        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }

    #[test]
    fn test_bsw_cp_delegate() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of three attributes matching the policy
        let mut _atts: Vec<String> = Vec::new();
        _atts.push(String::from("A"));
        _atts.push(String::from("B"));
        _atts.push(String::from("C"));
        // a set of two delegated attributes
        let _delegate: Vec<_> = _atts[1..2].iter().cloned().collect();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();
        // a cp-abe SK key matching
        let sk: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &_atts).unwrap();
        // a delegated cp-abe SK key matching
        let sk_delegate: CpAbeSecretKey = cpabe_delegate(&pk, &sk, &_delegate).unwrap();
        // and now decrypt using delegated key
        let _matching = cpabe_decrypt(&sk_delegate, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt using delegated sk"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }

    /* CURRENTLY TODO !!!
    #[test]
    fn test_cp_dabe_and() {
        // global setup
        let _gp = aw11_global();
        
        // setup attribute authority 1 with
        // a set of two attributes "A" and "B"
        let mut att_authority1: Vec<String> = Vec::new();
        att_authority1.push(String::from("A"));
        att_authority1.push(String::from("B"));
        let (_auth1_pk, _auth1_msk) = aw11_setup(_gp, att_authority1);

        // setup attribute authority 1 with
        // a set of two attributes "C" and "D"
        let mut att_authority2: Vec<String> = Vec::new();
        att_authority2.push(String::from("C"));
        att_authority2.push(String::from("D"));
        let (_auth2_pk, _auth2_msk) = aw11_setup(_gp, att_authority2);
        
		// setup attribute authority 1 with
        // a set of two attributes "E" and "F"
        let mut att_authority3: Vec<String> = Vec::new();
        att_authority3.push(String::from("E"));
        att_authority3.push(String::from("F"));
        let (_auth3_pk, _auth3_pk) = aw11_setup(_gp, att_authority3);

		// setup a user "bob" and give him some attribute-keys
		aw11_keygen

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();


        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }
*/
    /*
TODO: FIX MULTIPLE ATTRIBUTES !!!!
    #[test]
    fn test_kp_abe_and() {
        // setup scheme
        let (pk, msk) = kpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"OR": [{"ATT": "C"}, {"ATT": "B"}]}"#);
        //let policy = String::from(r#"{"ATT": "A"}"#);

        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_matching, &plaintext)
            .unwrap();

        // kp-abe ciphertext
        //let ct_kp_not_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_not_matching, &plaintext)
        //    .unwrap();

        // a kp-abe SK key
        let sk: KpAbeSecretKey = kpabe_keygen(&pk, &msk, &policy).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = kpabe_decrypt(&sk, &ct_kp_matching);
        match _matching {
            None => println!("KP-ABE: Cannot decrypt"),
            Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }
*/
    #[test]
    fn test_ac17kp_and() {
        // setup scheme
        let (pk, msk) = ac17_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // kp-abe ciphertext
        let ct: Ac17KpCiphertext = ac17kp_encrypt(&pk, &att_matching, &plaintext).unwrap();

        // a kp-abe SK key
        let sk: Ac17KpSecretKey = ac17kp_keygen(&msk, &policy).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = ac17kp_decrypt(&sk, &ct);
        match _matching {
            None => println!("AC17-KP-ABE: Cannot decrypt"),
            Some(x) => println!("AC17-KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }

    #[test]
    fn test_ac17cp_and() {
        // setup scheme
        let (pk, msk) = ac17_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = ac17cp_encrypt(&pk, &policy, &plaintext).unwrap();

        // kp-abe ciphertext
        //let ct_kp_not_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_not_matching, &plaintext)
        //    .unwrap();

        // a kp-abe SK key
        let sk: Ac17CpSecretKey = ac17cp_keygen(&msk, &att_matching).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = ac17cp_decrypt(&sk, &ct);
        match _matching {
            None => println!("AC17-CP-ABE: Cannot decrypt"),
            Some(x) => println!("AC17-CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let _rng = &mut rand::thread_rng();
        let _secret = Fr::random(_rng);
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 2, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(_k).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        _input.push(_shares[2]);
        //println!("_share1: {:?}", into_dec(_shares[1]).unwrap());
        //println!("_share2: {:?}", into_dec(_shares[2]).unwrap());
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        );
        //println!("_reconstructed: {:?}", into_dec(_reconstruct).unwrap());
        assert!(_k == _reconstruct);
    }

    #[test]
    fn pruning_test() {
        // a set of two attributes
        let mut _attributes: Vec<String> = Vec::new();
        _attributes.push(String::from("1"));
        _attributes.push(String::from("3"));

        let _result1 = calc_pruned_str(
            &_attributes,
            &String::from(r#"{"AND": [{"OR": [{"ATT": "1"}, {"ATT": "2"}]}, {"AND": [{"ATT": "2"}, {"ATT": "3"}]}]}"#),
        );
        let _result2 = calc_pruned_str(
            &_attributes,
            &String::from(
                r#"{"OR": [{"ATT": "1"}, {"AND": [{"ATT": "2"}, {"ATT": "3"}]}]}"#,
            ),
        );
        let _result3 = calc_pruned_str(
            &_attributes,
            &String::from(r#"{"AND": [{"OR": [{"ATT": "1"}, {"ATT": "2"}]}, {"OR": [{"ATT": "4"}, {"ATT": "3"}]}]}"#),
        );

        let (_match1, _list1) = _result1.unwrap();
        assert!(_match1 == false);
        assert!(_list1.is_empty() == true);
        let (_match2, _list2) = _result2.unwrap();
        assert!(_match2 == true);
        assert!(_list2 == vec!["1".to_string()]);
        let (_match3, _list3) = _result3.unwrap();
        assert!(_match3 == true);
        assert!(_list3 == vec!["1".to_string(), "3".to_string()]);
    }


    #[test]
    fn test_secret_sharing_or() {
        // OR
        let _rng = &mut rand::thread_rng();
        let _secret = Fr::random(_rng);
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 1, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(K).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        );
        assert!(_k == _reconstruct);
    }

    #[test]
    fn test_to_msp() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_zero, _zero, _minus];
        let p2 = vec![_plus, _zero, _plus];
        let p3 = vec![_zero, _minus, _zero];
        let p4 = vec![_plus, _plus, _zero];
        let mut _msp_static = AbePolicy {
            _m: vec![p1, p2, p3, p4],
            _pi: vec![
                String::from("A"),
                String::from("B"),
                String::from("C"),
                String::from("D"),
            ],
            _deg: 3,
        };
        match AbePolicy::from_string(&policy) {
            None => assert!(false),
            Some(_msp) => {
                for i in 0..4 {
                    let p = &_msp._m[i];
                    let p_test = &_msp_static._m[i];
                    for j in 0..3 {
                        //println!("_mspg[{:?}][{:?}]: {:?}", i, j, p[j]);
                        //println!("_msps[{:?}][{:?}]: {:?}", i, j, p_test[j]);
                        assert!(p[j] == p_test[j]);
                    }
                    //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                    assert!(_msp_static._pi[i] == _msp._pi[i]);
                }
                assert!(_msp_static._deg == _msp._deg);
            }
        }
    }
}
