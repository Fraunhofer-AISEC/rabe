A Rust implementation of KP-ABE using the bn library based on the FAME scheme 
by Chase et al. In order to compile install rust, clone library and then 
run 'cargo build'

To compile the C testfile:
gcc test.c -lrabe -L./target/debug -o test
