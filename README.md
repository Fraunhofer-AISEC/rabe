[![pipeline status](https://git-int.aisec.fraunhofer.de/sas/rust-abe/badges/master/pipeline.svg)](https://git-int.aisec.fraunhofer.de/sas/rust-abe/pipelines)

A Rust implementation of some ABE scheme's using the bn library of zcash (type-3 pairing / baretto naering curve)

Implemented CP-ABE Schemes:
- BSW CP-ABE
- AC17 CP-ABE
- AW11 CP-ABE
- MKE08 CP-ABE
- BDABE CP-ABE

Implemented KP-ABE Schemes:
- AC17 KP-ABE
- LSW KP-ABE (still buggy!)

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
gcc test.c -lrabe -L./target/debug -o test
