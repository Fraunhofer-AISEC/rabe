A Rust implementation of some ABE scheme's using the bn library (type-3 pairing on a baretto naering curve)

Implemented Schemes:
- BSW CP-ABE
- AC17 CP-ABE
- AC17 KP-ABE
- LSW KP-ABE (buggy! TODO: need to fix coeff reconstruction)

In order to compile and test:
- install rust
- git clone library 
- and then run 'cargo build && RUST_BACKTRACE=1 cargo test -- --nocapture'

To compile the C testfile:
gcc test.c -lrabe -L./target/debug -o test
