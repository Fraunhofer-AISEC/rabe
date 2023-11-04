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
- Setup a AC17 CP-ABE scheme
  * ```bash
    $ rabe --s AC17CP setup
    ```
  * This generates msk.key and pk.key 
- Generate a new key with **attributes** "A" and "B"
  * ```bash
    $ rabe --s AC17CP keygen --a 'A and B'
    ```
  * This generates a new key with **attributes** "A" and "B" and saves it to sk.key
- Encrypt a message with the HUMAN or JSON language **policy** "A" and "B"
  * ```bash
    $ rabe --s AC17CP --l HUMAN encrypt message.txt '"A" and "B"'
    OR
    rabe --s AC17CP --l JSON encrypt message.txt '{"name":"and","children":[{"name":"B"},{"name":"A"}]}'
    ```
  * This generates a ciphertext and saves it to message.txt.ct

- Decrypt a ciphertext with sk.key
  * ```bash
    $ rabe --s AC17CP decrypt message.txt.ct
    ```
  * This decrypts the ciphertext and saves it to message.txt