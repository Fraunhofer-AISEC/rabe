
[![Crates.io](https://img.shields.io/crates/v/rabe?style=plastic)](https://crates.io/crates/rabe)
[![Docs.rs](https://img.shields.io/docsrs/rabe?style=plastic)](https://docs.rs/rabe)
[![License](https://img.shields.io/crates/l/rabe?style=plastic)](https://github.com/Fraunhofer-AISEC/rabe/blob/master/LICENSE)

# Rabe

rabe is a rust library implementing several Attribute Based Encryption (ABE) schemes using a modified version of the `bn` library of zcash (type-3 pairing / Baretto Naering curve). The modification of `bn` brings in `serde` or `borsh` instead of the deprecated `rustc_serialize`.
The standard serialization library is `serde`. If you want to use `borsh`, you need to specify it as feature.

For integration in distributed applications contact [us](mailto:info@aisec.fraunhofer.de).

# Implemented Ciphertext Policy Schemes (CP-ABE)

## BDABE CP-ABE

Georg Bramm, Mark Gall, Julian Schütte , "Blockchain based Distributed Attribute-based Encryption". In Proceedings of the 15th International Joint Conference on e-Business and Telecommunications (ICETE 2018) - Volume 2: SECRYPT, pages 99-110. Available from https://doi.org/10.5220/0006852602650276

## AC17 CP-ABE

Shashank Agrawal, Melissa Chase, "FAME: Fast Attribute-based Message Encryption", (Section 3). In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security 2017. Available from https://eprint.iacr.org/2017/807.pdf

## AW11 CP-ABE

Lewko, Allison, and Brent Waters, "Decentralizing Attribute-Based Encryption.", (Appendix D). In Eurocrypt 2011. Available from http://eprint.iacr.org/2010/351.pdf

## BSW CP-ABE

John Bethencourt, Amit Sahai, Brent Waters, "Ciphertext-Policy Attribute-Based Encryption" In IEEE Symposion on Security and Privacy, 2007. Available from https://doi.org/10.1109/SP.2007.11

## MKE08 CP-ABE

S Müller, S Katzenbeisser, C Eckert , "Distributed Attribute-based Encryption". Published in International Conference on Information Security and Cryptology, Heidelberg, 2008. Available from http://www2.seceng.informatik.tu-darmstadt.de/assets/mueller/icisc08.pdf


# Implemented Key Policy Schemes (KP-ABE)

## AC17 KP-ABE

Shashank Agrawal, Melissa Chase, "FAME: Fast Attribute-based Message Encryption". In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security 2017. Available from https://eprint.iacr.org/2017/807.pdf

## LSW KP-ABE 

Allison Lewko, Amit Sahai and Brent Waters, "Revocation Systems with Very Small Private Keys". In IEEE Symposium on Security and Privacy, 2010. SP'10. Available from http://eprint.iacr.org/2008/309.pdf

## YCT14 KP-ABE

Xuanxia Yao, Zhi Chen, Ye Tian, "A lightweight attribute-based encryption scheme for the Internet of things". In Future Generation Computer Systems. Available from http://www.sciencedirect.com/science/article/pii/S0167739X14002039


# Building rabe lib

In order to compile and test:
- install rust nightly
- git clone library 
- install build-essential
- and then run `cargo build --release && RUST_BACKTRACE=1 cargo test -- --nocapture` 
- rabe is also available with borsh serialization. just add `--features borsh` to build command

# Building rabe console app

See [README.md](./rabe-console/README.md)

