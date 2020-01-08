//! Abstract operations exposed by the library.

/// Secure generation of fresh key pairs.
pub trait System<S, SP> {
    /// Generate fresh key pair with currently recommended security level (4096 bit modulus).
    fn new() -> SP {
        Self::setup("_hOPE".to_string(), 4)
    }
    fn setup(_name: String, _degree: usize) -> SP;
}

/// Secure generation of fresh key pairs.
pub trait Keygen<KP> {
    /// Generate fresh key pair with currently recommended security level).
    fn keygen() -> KP;
}

/// Encryption of plaintext.
pub trait Enc<EK, PT, CT> {
    /// Encrypt plaintext `m` under key `sk` into a ciphertext.
    fn encrypt(sk: &EK, m: PT) -> CT;
}

/// Decryption of ciphertext.
pub trait Dec<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `pk` into a plaintext.
    fn decrypt(pk: &DK, c: CT) -> PT;
}

/// Addition of two ciphertexts.
pub trait Add<EK, CT1, CT2, CT3> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: CT1, c2: CT2) -> CT3;
}

/// subtraction of two ciphertexts.
pub trait Sub<EK, CT1, CT2, CT3> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the subtraction of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn sub(ek: &EK, c1: CT1, c2: CT2) -> CT3;
}

/// Multiplication of ciphertext with plaintext.
pub trait Mul<EK, CT1, PT2, CT2> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: CT1, m2: PT2) -> CT2;
}

/// Comparison of two ciphertexts
pub trait Com<CT1, CT2> {
    /// Compare ciphertext `c1` and ciphertext `c1` to obtain the larger one
    /// true means ciphertext `c1` is larger, false means ciphertext `c2` is larger
    fn comp(c1: CT1, m2: CT2) -> bool;
}
