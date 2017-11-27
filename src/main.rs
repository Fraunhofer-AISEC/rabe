#[macro_use]
extern crate clap;
extern crate bn;
extern crate rand;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;
extern crate blake2_rfc;


mod policy;
mod ac17;
mod bsw;
mod lsw;
mod tools;

use rustc_serialize::json;
use clap::{Arg, App, SubCommand, ArgMatches};
use std::process;
use ac17::*;
use bsw::*;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[macro_use]
extern crate arrayref;

const MSK_FILE: &'static str = "msk.key";
const PK_FILE: &'static str = "pk.key";
const SK_FILE: &'static str = "sk.key";

fn main() {

    arg_enum! {
    #[derive(Debug)]
    enum Scheme {
        AC17CP,
        AC17KP,
        BSWCP,
        LSWKP
    }
}
    let _abe_app = App::new("ABE")
        .version("0.1.0")
        .author(crate_authors!("\n"))
        .about("ABE schemes written in Rust")
        .arg(
            Arg::with_name("scheme")
                .long("scheme")
                .required(true)
                .takes_value(true)
                .value_name("scheme")
                .possible_values(&Scheme::variants())
                .help("scheme to use."),
        )
        .arg(
            Arg::with_name("msk")
                .long("msk")
                .required(false)
                .takes_value(true)
                .default_value(MSK_FILE)
                .value_name("msk")
                .help("master secret key file."),
        )
        .arg(
            Arg::with_name("pk")
                .long("pk")
                .required(false)
                .takes_value(true)
                .default_value(PK_FILE)
                .value_name("pk")
                .help("public key file."),
        )
        .arg(
            Arg::with_name("attributes")
                .long("attributes")
                .required(false)
                .takes_value(true)
                .multiple(true)
                .value_name("attributes")
                .help("attributes to use."),
        )
        .arg(
            Arg::with_name("policy")
                .long("policy")
                .required(false)
                .takes_value(true)
                .value_name("policy")
                .help("policy to use."),
        )
        .arg(
            Arg::with_name("sk")
                .long("sk")
                .required(false)
                .takes_value(true)
                .default_value(SK_FILE)
                .value_name("sk")
                .help("user key file."),
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .required(false)
                .takes_value(true)
                .value_name("file")
                .help("file to use."),
        )
        .subcommand(SubCommand::with_name("setup").about(
            "sets up a scheme, creates msk and pk.",
        ))
        .subcommand(SubCommand::with_name("keygen").about(
            "creates a user key sk using attributes (cp-schemes) or a policy (kp-schemes).",
        ))
        .subcommand(SubCommand::with_name("encrypt").about(
            "encrypts a file using attributes (kp-schemes) or a policy (cp-schemes).",
        ))
        .subcommand(SubCommand::with_name("decrypt").about(
            "decrypts a file using a key.",
        ))
        .get_matches();

    if let Err(e) = run(_abe_app) {
        println!("Application error: {}", e);
        process::exit(1);
    }

    fn run(matches: ArgMatches) -> Result<(), String> {
        let _scheme = value_t!(matches.value_of("scheme"), Scheme).unwrap();
        match matches.subcommand() {
            ("setup", Some(matches)) => run_setup(matches, &_scheme),
            ("keygen", Some(matches)) => run_keygen(matches, &_scheme),
            ("encrypt", Some(matches)) => run_encrypt(matches, &_scheme),
            ("decrypt", Some(matches)) => run_decrypt(matches, &_scheme),
            _ => Ok(()),
        }
    }

    fn run_setup(matches: &ArgMatches, _enum: &Scheme) -> Result<(), String> {
        let mut _msk_file = "msk.key";
        let mut _pk_file = "pk.key";
        let mut _encoded_msk: String = String::new();
        let mut _encoded_pk: String = String::new();
        match matches.value_of("msk") {
            None => {}
            Some(x) => _msk_file = x,
        }
        match matches.value_of("pk") {
            None => {}
            Some(x) => _pk_file = x,
        }
        match _enum {
            AC17CP => {
                let (_msk, _pk) = ac17_setup();
                _encoded_msk = json::encode(&_msk).unwrap();
                _encoded_pk = json::encode(&_pk).unwrap();
            }
            AC17KP => {
                let (_msk, _pk) = ac17_setup();
                _encoded_msk = json::encode(&_msk).unwrap();
                _encoded_pk = json::encode(&_pk).unwrap();
            }
            BSWCP => {
                let (_msk, _pk) = cpabe_setup();
                _encoded_msk = json::encode(&_msk).unwrap();
                _encoded_pk = json::encode(&_pk).unwrap();
            }
            LSWKP => {
                //let (_msk, _pk) = kpabe_setup();
                //_encoded_msk = json::encode(&_msk).unwrap();
                //_encoded_pk = json::encode(&_pk).unwrap();
            }
        }
        //println!("msk : {}", _encoded_msk);
        //println!("pk : {}", _encoded_pk);
        write_file(Path::new(_msk_file), _encoded_msk);
        write_file(Path::new(_pk_file), _encoded_pk);
        Ok(())
    }

    fn run_keygen(matches: &ArgMatches, _enum: &Scheme) -> Result<(), String> {
        let mut _sk_file = SK_FILE;
        let mut _msk_file = MSK_FILE;
        let mut _pk_file = PK_FILE;
        let mut _encoded_msk: String = String::new();
        let mut _encoded_pk: String = String::new();
        let mut _encoded_sk: String = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        match matches.value_of("msk") {
            None => {}
            Some(x) => _msk_file = x,
        }
        match matches.value_of("pk") {
            None => {}
            Some(x) => _pk_file = x,
        }
        match matches.value_of("sk") {
            None => {}
            Some(x) => _sk_file = x,
        }
        match matches.values_of("attributes") {
            None => {}
            Some(x) => _attributes = x.map(|s| s.to_string()).collect(),
        }
        match matches.value_of("policy") {
            None => {}
            Some(x) => _policy = x.to_string(),
        }
        let _msk_string = read_file(Path::new(_msk_file));
        let _pk_string = read_file(Path::new(_pk_file));
        match _enum {
            AC17CP => {
                let _msk: Ac17MasterKey = json::decode(&_msk_string).unwrap();
                let _sk = ac17cp_keygen(&_msk, &_attributes);
                _encoded_sk = json::encode(&_sk).unwrap();
            }
            AC17KP => {
                let _msk: Ac17MasterKey = json::decode(&_msk_string).unwrap();
                let _sk = ac17kp_keygen(&_msk, &_policy);
                _encoded_sk = json::encode(&_sk).unwrap();
            }
            BSWCP => {
                let _msk: CpAbeMasterKey = json::decode(&_msk_string).unwrap();
                let _pk: CpAbePublicKey = json::decode(&_pk_string).unwrap();
                let _sk = cpabe_keygen(&_pk, &_msk, &_attributes);
                _encoded_sk = json::encode(&_sk).unwrap();
            }
            LSWKP => {
                //let _sk = kpabe_keygen();
                //_encoded_sk = json::encode(&_msk).unwrap();
            }
        }
        //println!("sk: {}", _encoded_sk);
        write_file(Path::new(_sk_file), _encoded_sk);
        Ok(())
    }

    fn run_encrypt(matches: &ArgMatches, _enum: &Scheme) -> Result<(), String> {
        let mut _pk_file = PK_FILE;
        let mut _file: String = String::new();
        let mut _encoded_ct: String = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        match matches.value_of("pk") {
            None => {}
            Some(x) => _pk_file = x,
        }
        match matches.values_of("attributes") {
            None => {}
            Some(x) => _attributes = x.map(|s| s.to_string()).collect(),
        }
        match matches.value_of("policy") {
            None => {}
            Some(x) => _policy = x.to_string(),
        }
        match matches.value_of("file") {
            None => {}
            Some(x) => _file = x.to_string(),
        }
        let _pk_string = read_file(Path::new(_pk_file));
        let buffer: Vec<u8> = read_to_vec(Path::new(&_file));
        match _enum {
            AC17CP => {
                let _pk: Ac17PublicKey = json::decode(&_pk_string).unwrap();
                let _ct = ac17cp_encrypt(&_pk, &_policy, &buffer);
                _encoded_ct = json::encode(&_ct).unwrap();
            }
            AC17KP => {
                let _pk: Ac17PublicKey = json::decode(&_pk_string).unwrap();
                let _ct = ac17kp_encrypt(&_pk, &_attributes, &buffer);
                _encoded_ct = json::encode(&_ct).unwrap();
            }
            BSWCP => {
                let _pk: CpAbePublicKey = json::decode(&_pk_string).unwrap();
                let _ct = cpabe_encrypt(&_pk, &_policy, &buffer);
                _encoded_ct = json::encode(&_ct).unwrap();
            }
            LSWKP => {
                //let _ct = kpabe_encrypt();
                //_encoded_ct = json::encode(&_ct).unwrap();
            }
        }
        //println!("ct: {}", _encoded_ct);
        write_file(Path::new(&_file), _encoded_ct);
        Ok(())
    }

    fn run_decrypt(matches: &ArgMatches, _enum: &Scheme) -> Result<(), String> {
        let mut _sk_file = SK_FILE;
        let mut _file: String = String::new();
        let mut _encoded_sk: String = String::new();
        let mut _pt: Vec<u8> = Vec::new();
        let mut _pt_option: Option<Vec<u8>> = None;
        match matches.value_of("sk") {
            None => {}
            Some(x) => _sk_file = x,
        }
        match matches.value_of("file") {
            None => {}
            Some(x) => _file = x.to_string(),
        }
        match _enum {
            AC17CP => {
                let _sk: Ac17CpSecretKey = json::decode(&_sk_file).unwrap();
                let _ct: Ac17CpCiphertext = json::decode(&_file).unwrap();
                _pt_option = ac17cp_decrypt(&_sk, &_ct);
            }
            AC17KP => {
                let _sk: Ac17KpSecretKey = json::decode(&_sk_file).unwrap();
                let _ct: Ac17KpCiphertext = json::decode(&_file).unwrap();
                _pt_option = ac17kp_decrypt(&_sk, &_ct);
            }
            BSWCP => {
                let _sk: CpAbeSecretKey = json::decode(&_sk_file).unwrap();
                let _ct: CpAbeCiphertext = json::decode(&_file).unwrap();
                _pt_option = cpabe_decrypt(&_sk, &_ct);
            }
            LSWKP => {
                //let _ct = kpabe_encrypt();
                //_encoded_ct = json::encode(&_ct).unwrap();
            }
        }
        match _pt_option {
            None => {
                println!("Error could not decrypt!");
            }
            Some(_pt_u) => {
                _pt = _pt_u;
                write_from_vec(Path::new(&_file), &_pt);
            }
        }
        Ok(())
    }

    fn read_file(_path: &Path) -> String {
        let display = _path.display();
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(_path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", display, why.description()),
            Ok(file) => file,
        };
        // Read the file contents into a string, returns `io::Result<usize>`
        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(why) => panic!("couldn't read {}: {}", display, why.description()),
            Ok(_) => print!("{} contains:\n{}", display, s),
        }
        return s;
    }

    fn read_to_vec(_path: &Path) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let display = _path.display();
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(_path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", display, why.description()),
            Ok(file) => file,
        };
        // read the whole file
        file.read_to_end(&mut data);
        return data;
    }

    fn write_from_vec(_path: &Path, _data: &Vec<u8>) {
        let display = _path.display();
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(_path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", display, why.description()),
            Ok(file) => file,
        };
        match file.write_all(_data) {
            Err(why) => panic!("couldn't write to {}: {}", display, why.description()),
            Ok(_) => println!("successfully wrote to {}", display),
        }
    }

    fn write_file(_path: &Path, _content: String) -> bool {
        let display = _path.display();

        // Open a file in write-only mode, returns `io::Result<File>`
        let mut file = match File::create(_path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.description()),
            Ok(file) => file,
        };
        let mut _ret: bool = false;
        // Write the `LOREM_IPSUM` string to `file`, returns `io::Result<()>`
        match file.write_all(_content.as_bytes()) {
            Err(why) => {
                _ret = false;
                panic!("couldn't write to {}: {}", display, why.description());
            }
            Ok(_) => {
                _ret = true;
                println!("successfully wrote to {}", display);
            }
        }
        return _ret;
    }
}
