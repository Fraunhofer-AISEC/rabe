A Rust implementation of some ABE scheme's using the bn library 
(type-3 pairing / baretto naering curve)

Implemented Schemes:
- BSW CP-ABE
- AC17 CP-ABE
- AC17 KP-ABE
- AW11 CP-ABE
- LSW KP-ABE (buggy! TODO: need to fix coeff reconstruction)

In order to compile and test:
- install rust
- git clone library 
- and then run 'cargo build && RUST_BACKTRACE=1 cargo test -- --nocapture'

In order to run:
```bash
ABE 0.1.0
Schanzenbach, Martin <martin.schanzenbach@aisec.fraunhofer.de>
Bramm, Georg <georg.bramm@aisec.fraunhofer.de>
ABE schemes written in Rust

USAGE:
    rabe [OPTIONS] --scheme <scheme> [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --attributes <attributes>...    attributes to use.
        --file <file>                   file to use.
        --msk <msk>                     master secret key file. [default: msk.key]
        --pk <pk>                       public key file. [default: pk.key]
        --policy <policy>               policy to use.
        --scheme <scheme>               scheme to use. [values: AC17CP, AC17KP, BSWCP, LSWKP]
        --sk <sk>                       user key file. [default: sk.key]

SUBCOMMANDS:
    decrypt    decrypts a file using a key.
    encrypt    encrypts a file using attributes (kp-schemes) or a policy (cp-schemes).
    help       Prints this message or the help of the given subcommand(s)
    keygen     creates a user key sk using attributes (cp-schemes) or a policy (kp-schemes).
    setup      sets up a scheme, creates msk and pk.
```
For example, in order to create msk and pk of an AC17 KP-ABE scheme run:
```bash
$ ./target/debug/rabe --scheme AC17KP setup
```

To compile the C testfile:
gcc test.c -lrabe -L./target/debug -o test
