# Rabe console app

This is an example console app, to test the implemented schemes

For integration in distributed applications contact [us](mailto:info@aisec.fraunhofer.de).


# Building 

In order to compile and test:
- install rust nightly
- git clone library
- install build-essential
- Do one of the following
  - run `cargo run -p rabe-console` from parent directory
  - run `cargo run` from this directory
  - compile using `cargo build --release` and afterwards run executable `./target/release/rabe`

## Example calls using executable
- Setup a AC17 KP-ABE scheme
  * ```bash
    $ rabe --s AC17CP setup
    ```
  * This generates msk.key and pk.key 
- Generate a new key with attributes "A" and "B"
  * ```bash
    $ rabe --s AC17CP keygen --a 'A B'
    ```