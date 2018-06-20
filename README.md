A Rust implementation of some Attribute Based Encryption (ABE) schemes using a modified version of the bn library of zcash (type-3 pairing / Baretto Naering curve).
The modification enabled serde and disabled rustc_serialize.

Implemented CP-ABE Schemes:
- AC17 CP-ABE
- AW11 CP-ABE
- BSW CP-ABE
- MKE08 CP-ABE
- BDABE CP-ABE

Implemented KP-ABE Schemes:
- AC17 KP-ABE
- LSW KP-ABE 

In order to compile and test:
- install rust
- git clone library 
- and then run 'cargo build && RUST_BACKTRACE=1 cargo test -- --nocapture'

In order to run on the console use 
- target/debug/rabe

For example, in order to create msk and pk of an AC17 KP-ABE scheme run:
```bash
$ ./target/debug/rabe --scheme AC17KP setup
```

To compile the C testfile:
```bash
gcc test.c -lrabe -L./target/debug -o test
```
