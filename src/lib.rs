extern crate bn;
use std::collections::LinkedList;
use std::string::String;

pub struct AbePublicKey
{
    _pkey: f32
}

pub struct AbeMasterKey
{
    _msk: f32
}

pub struct AbeSecretKey
{
    _sk: f32
}

pub fn abe_setup () -> (Option<AbePublicKey>,Option<AbeMasterKey>)
{
    let pk = AbePublicKey { _pkey: 0.0 };
    let msk = AbeMasterKey { _msk: 0.0 };

    
    return (None, None);
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
        assert!(!pk.is_none());
        assert!(!msk.is_none());
    }
    fn test_keygen() {
        //let (pk,msk) = abe_setup ();
        let mut attrs: LinkedList<String> = LinkedList::new();
        attrs.push_back(String::from("a1"));
        attrs.push_back(String::from("a2"));
        attrs.push_back(String::from("a3"));
        match abe_setup () {
            (Some(pk),Some(msk)) => { let sk = abe_keygen (&pk,&msk,&attrs);
                                     assert!(!sk.is_none()); },
            _ => assert!(false)
        }
        //assert_ne!(None, sk);
    }
}
