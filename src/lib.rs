extern crate bn;
use std::collections::LinkedList;
use std::string::String;

pub struct AbePublicKey
{
    pkey: f32
}

pub struct AbeMasterKey
{
    msk: f32
}

pub struct AbeSecretKey
{
    sk: f32
}

pub fn abe_setup () -> (AbePublicKey,AbeMasterKey)
{
    let pk = AbePublicKey { pkey: 0.0 };
    let msk = AbeMasterKey { msk: 0.0 };

    
    return (pk, msk);
}

pub fn abe_keygen (attributes: &LinkedList<String>) -> AbeSecretKey
{
    let sk = AbeSecretKey { sk: 0.0 };
    for str in attributes.iter() {
        print!("{}", str);
    }
    return sk;
}

#[cfg(test)]
mod tests {
    use abe_setup;
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
        let mut attrs: LinkedList<String> = LinkedList::new();
        attrs.push_back(String::from("a1"));
        attrs.push_back(String::from("a2"));
        attrs.push_back(String::from("a3"));
        //assert!((pk, msk) = abe_setup (&attrs));
    }
}
