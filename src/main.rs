//! This is the documentation for the RABE console application.
//!
//! * Developped by Georg Bramm, Fraunhofer AISEC
//! * Date: 04/2018
//!
#[allow(dead_code)]

extern crate bn;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate crypto;
extern crate bincode;
extern crate num_bigint;
extern crate blake2_rfc;
extern crate base64;

mod utils;
mod schemes;

use clap::{Arg, App, SubCommand, ArgMatches};
use std::process;
use schemes::ac17::*;
use schemes::aw11::*;
use schemes::bsw::*;
use schemes::mke08::*;
use schemes::bdabe::*;
use schemes::lsw::*;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::fmt;
use base64::{encode, decode};
use serde_cbor::{to_vec, from_slice};
use serde_cbor::ser::to_vec_packed;

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;

extern crate serde_cbor;

const CT_EXTENSION: &'static str = "rabe";
const KEY_EXTENSION: &'static str = "key";
const GP_FILE: &'static str = "gp";
const MSK_FILE: &'static str = "msk";
const SK_FILE: &'static str = "sk";
const SKA_FILE: &'static str = "ska";
const PK_FILE: &'static str = "pk";
const JSON: &'static str = "json";

const SK_BEGIN: &'static str = "-----BEGIN USER PRIVATE KEY BLOCK-----\n";
const SK_END: &'static str = "\n-----END USER PRIVATE KEY BLOCK-----";
const MSK_BEGIN: &'static str = "-----BEGIN MASTER SECRET KEY BLOCK-----\n";
const MSK_END: &'static str = "\n-----END MASTER SECRET KEY BLOCK-----";
const PK_BEGIN: &'static str = "-----BEGIN MASTER PUBLIC KEY BLOCK-----\n";
const PK_END: &'static str = "\n-----END MASTER PUBLIC KEY BLOCK-----";
const CT_BEGIN: &'static str = "-----BEGIN CIPHERTEXT BLOCK-----\n";
const CT_END: &'static str = "\n-----END CIPHERTEXT BLOCK-----";
const GP_BEGIN: &'static str = "-----BEGIN GLOBAL BLOCK-----\n";
const GP_END: &'static str = "\n-----END GLOBAL BLOCK-----";
const AU_BEGIN: &'static str = "-----BEGIN AUTHORITY BLOCK-----\n";
const AU_END: &'static str = "\n-----END AUTHORITY BLOCK-----";

#[derive(Debug)]
struct RabeError {
    details: String,
}

impl RabeError {
    fn new(msg: &str) -> RabeError {
        RabeError { details: msg.to_string() }
    }
}

impl fmt::Display for RabeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for RabeError {
    fn description(&self) -> &str {
        &self.details
    }
}

fn main() {

    arg_enum! {
	    #[derive(Debug)]
	    enum Scheme {
	        AC17CP,
	        AC17KP,
	        AW11,
	        BDABE,
	        BSW,
	        LSW,
	        MKE08
	    }
	}
    let _abe_app = App::new("RABE")
        .version("0.1.2")
        .author(crate_authors!("\n"))
        .about("ABE in Rust")
        .arg(
            Arg::with_name("scheme")
                .long("scheme")
                .required(true)
                .takes_value(true)
                .value_name("scheme")
                .possible_values(&Scheme::variants())
                .help("scheme to use."),
        )
        .subcommand(
            SubCommand::with_name("setup")
                .about("sets up a scheme, creates msk and pk or gp.")
                .arg(
                    Arg::with_name(MSK_FILE)
                        .long(MSK_FILE)
                        .required(false)
                        .takes_value(true)
                        .value_name(MSK_FILE)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name("pk")
                        .long("pk")
                        .required(false)
                        .takes_value(true)
                        .value_name("pk")
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name("gp")
                        .long("gp")
                        .required(false)
                        .takes_value(true)
                        .value_name("gk")
                        .help("global parameters file."),
                ) 
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .required(false)
                        .takes_value(false)
                        .value_name("json")
                        .help("export the key in json format."),
                ),
        )
        .subcommand(
            SubCommand::with_name("authgen")
                .about(
                    "creates a new authority using attributes (cp-schemes) or a policy (kp-schemes).",
                )
                .arg(
                    Arg::with_name("gp")
                        .long("gp")
                        .required(false)
                        .takes_value(true)
                        .default_value(GP_FILE)
                        .value_name("gp")
                        .help("global parameters file."),
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
                        .short("attr")
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
                    Arg::with_name("name")
                        .long("name")
                        .required(false)
                        .takes_value(true)
                        .value_name("name")
                        .help("name of the attribute authority (MKE08/BDABE)"),
                ) 
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .required(false)
                        .takes_value(false)
                        .value_name("json")
                        .help("export the key in json format."),
                ),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about(
                    "creates a user key sk using attributes (cp-schemes) or a policy (kp-schemes).",
                )
                .arg(
                    Arg::with_name("gp")
                        .long("gp")
                        .required(false)
                        .takes_value(true)
                        .default_value(GP_FILE)
                        .value_name("gp")
                        .help("global parameters file."),
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
                    Arg::with_name("ska")
                        .long("ska")
                        .required(false)
                        .takes_value(true)
                        .default_value(SK_FILE)
                        .value_name("ska")
                        .help("authrotiy secret key file."),
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
                    Arg::with_name("name")
                        .long("name")
                        .required(false)
                        .takes_value(true)
                        .value_name("name")
                        .help("name (gid) of the user (AW11)"),
                ) 
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .required(false)
                        .takes_value(false)
                        .value_name("json")
                        .help("export the key in json format."),
                ),
        )
        .subcommand(
            SubCommand::with_name("delegate")
                .about("delegates some user key attributes (cp-schemes)")
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
                    Arg::with_name("json")
                        .long("json")
                        .required(false)
                        .takes_value(false)
                        .value_name("json")
                        .help("export the key in json format."),
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .about(
                    "encrypts a file using attributes (kp-schemes) or a policy (cp-schemes).",
                )
                .arg(
                    Arg::with_name("gp")
                        .long("gp")
                        .required(false)
                        .takes_value(true)
                        .default_value(GP_FILE)
                        .value_name("gp")
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name("pk")
                        .long("pk")
                        .required(false)
                        .takes_value(true)
                        .default_value(PK_FILE)
                        .value_name("pk")
                        .multiple(true)
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
                    Arg::with_name("file")
                        .long("file")
                        .required(false)
                        .takes_value(true)
                        .value_name("file")
                        .help("file to use."),
                )
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .required(false)
                        .takes_value(false)
                        .value_name("json")
                        .help("export the file in json format."),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("decrypts a file using a key.")
                .arg(
                    Arg::with_name("gp")
                        .long("gp")
                        .required(false)
                        .takes_value(true)
                        .default_value(GP_FILE)
                        .value_name("gp")
                        .help("global parameters file."),
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
                ),
        )
        .get_matches();

    if let Err(e) = run(_abe_app) {
        println!("Application error: {}", e);
        process::exit(1);
    }

    fn run(matches: ArgMatches) -> Result<(), RabeError> {
        let _scheme = value_t!(matches.value_of("scheme"), Scheme).unwrap();
        match matches.subcommand() {
            ("setup", Some(matches)) => run_setup(matches, _scheme),
            ("authgen", Some(matches)) => run_authgen(matches, _scheme),
            ("keygen", Some(matches)) => run_keygen(matches, _scheme),
            ("delegate", Some(matches)) => run_delegate(matches, _scheme),
            ("encrypt", Some(matches)) => run_encrypt(matches, _scheme),
            ("decrypt", Some(matches)) => run_decrypt(matches, _scheme),
            _ => Ok(()),
        }
    }

    fn run_setup(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(MSK_FILE);
                _msk_file.push_str(".");
                _msk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(GP_FILE);
                _gp_file.push_str(".");
                _gp_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match _scheme {        	
            Scheme::AC17CP | Scheme::AC17KP => {
                let (_pk, _msk) = schemes::ac17::setup();
                if _as_json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    let serialized_msk = to_vec_packed(&_msk).unwrap();
                    let serialized_pk = to_vec_packed(&_pk).unwrap();
                    write_file(
                        Path::new(&_msk_file),
                        [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                    );
                }
            }
            Scheme::AW11 => {
                let _gp = schemes::aw11::setup();
                let serialized_gp = to_vec_packed(&_gp).unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_gp_file),
                        serde_json::to_string_pretty(&_gp).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        [GP_BEGIN, &encode(&serialized_gp).as_str(), GP_END].concat(),
                    );

                }
            }
            Scheme::BDABE => {
                let (_pk, _msk) = schemes::bdabe::setup();
                if _as_json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    let serialized_msk = to_vec_packed(&_msk).unwrap();
                    let serialized_pk = to_vec_packed(&_pk).unwrap();
                    write_file(
                        Path::new(&_msk_file),
                        [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                    );
                }
            }
            Scheme::BSW => {
                let (_pk, _msk) = schemes::bsw::setup();
                if _as_json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    let serialized_msk = to_vec_packed(&_msk).unwrap();
                    let serialized_pk = to_vec_packed(&_pk).unwrap();
                    write_file(
                        Path::new(&_msk_file),
                        [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                    );

                }
            }
            Scheme::LSW => {
                let (_pk, _msk) = schemes::lsw::setup();
                if _as_json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    let serialized_msk = to_vec_packed(&_msk).unwrap();
                    let serialized_pk = to_vec_packed(&_pk).unwrap();
                    write_file(
                        Path::new(&_msk_file),
                        [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                    );
                }
            } 
            Scheme::MKE08 => {
                let (_pk, _msk) = schemes::mke08::setup();
                if _as_json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    let serialized_msk = to_vec_packed(&_msk).unwrap();
                    let serialized_pk = to_vec_packed(&_pk).unwrap();
                    write_file(
                        Path::new(&_msk_file),
                        [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                    );
                }
            }          
        }
        Ok(())
    }

    fn run_authgen(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _name: String = String::from("");
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _au_file = String::from("");
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(MSK_FILE);
                _msk_file.push_str(".");
                _msk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(GP_FILE);
                _gp_file.push_str(".");
                _gp_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.values_of("attributes") {
            None => {}
            Some(_attr) => {
                let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                for _a in _b {
                    for _at in _a.split_whitespace() {
                        _attributes.push(_at.to_string());
                    }
                }
            }
        }
        match arguments.value_of("policy") {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of("name") {
            None => {}
            Some(_n) => {
                _name = _n.to_string();
                _au_file.push_str(&_n.to_string());
                _au_file.push_str(".");
                _au_file.push_str(KEY_EXTENSION)
            }
        }
        match _scheme { 
            Scheme::AC17CP => {
                return Err(RabeError::new("AC17CP is not a multi-authoriy scheme"));
            }
            Scheme::AC17KP => {
                return Err(RabeError::new("AC17KP is not a multi-authoriy scheme"));
            }
            Scheme::BSW => {
                return Err(RabeError::new("BSW is not a multi-authoriy scheme"));
            }
            Scheme::LSW => {
                return Err(RabeError::new("LSW is not a multi-authoriy scheme"));
            }
            Scheme::AW11 => {
                let mut _gp: Aw11GlobalKey;
                if _as_json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
                    _gp = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                }
                match schemes::aw11::authgen(&_gp, &_attributes) {
                    None => {
                        return Err(RabeError::new(
                            "could not generate authority. Attribute set empty.",
                        ));
                    }
                    Some((_pk, _msk)) => {
                        if _as_json {
                            write_file(
                                Path::new(&_msk_file),
                                serde_json::to_string_pretty(&_msk).unwrap(),
                            );
                            write_file(
                                Path::new(&_pk_file),
                                serde_json::to_string_pretty(&_pk).unwrap(),
                            );
                        } else {
                            let serialized_msk = to_vec_packed(&_msk).unwrap();
                            let serialized_pk = to_vec_packed(&_pk).unwrap();
                            write_file(
                                Path::new(&_msk_file),
                                [MSK_BEGIN, &encode(&serialized_msk).as_str(), MSK_END].concat(),
                            );
                            write_file(
                                Path::new(&_pk_file),
                                [PK_BEGIN, &encode(&serialized_pk).as_str(), PK_END].concat(),
                            );
                        }
                    }
                }
            }
            Scheme::BDABE => {
                let mut _pk: BdabePublicKey;
                let mut _msk: BdabeMasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: BdabeSecretAuthorityKey = schemes::bdabe::authgen(&_pk, &_msk, &_name);
                if _as_json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_au_file),
                        [AU_BEGIN, &encode(&serialized_sk).as_str(), AU_END].concat(),
                    );
                }
            }
            Scheme::MKE08 => {
                let mut _pk: Mke08PublicKey;
                let mut _msk: Mke08MasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: Mke08SecretAuthorityKey = schemes::mke08::authgen(&_name);
                if _as_json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_au_file),
                        [AU_BEGIN, &encode(&serialized_sk).as_str(), AU_END].concat(),
                    );
                }
            }   
        }
        Ok(())
    }

    fn run_keygen(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _ska_file = String::from("");
        let mut _name = String::from("");
        let mut _name_file = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(MSK_FILE);
                _msk_file.push_str(".");
                _msk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(GP_FILE);
                _gp_file.push_str(".");
                _gp_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(SK_FILE);
                _sk_file.push_str(".");
                _sk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(SKA_FILE) {
            None => {
                _ska_file.push_str(SKA_FILE);
                _ska_file.push_str(".");
                _ska_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _ska_file = _file.to_string(),
        }
        match arguments.values_of("attributes") {
            None => {}
            Some(_attr) => {
                let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                for _a in _b {
                    for _at in _a.split_whitespace() {
                        _attributes.push(_at.to_string());
                    }
                }
            }
        }
        match arguments.value_of("policy") {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of("name") {
            None => {}
            Some(_n) => {
                _name = _n.to_string();
                _name_file.push_str(&_n.to_string());
                _name_file.push_str(".");
                _name_file.push_str(KEY_EXTENSION);
            }
        }
        match _scheme {
            Scheme::AC17CP => {
                let mut _msk: Ac17MasterKey;
                if _as_json {
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: Ac17CpSecretKey = schemes::ac17::cp_keygen(&_msk, &_attributes).unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_sk_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::AC17KP => {
                let mut _msk: Ac17MasterKey;
                if _as_json {
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: Ac17KpSecretKey = schemes::ac17::kp_keygen(&_msk, &_policy).unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_sk_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::BSW => {
                let mut _pk: CpAbePublicKey;
                let mut _msk: CpAbeMasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: CpAbeSecretKey = schemes::bsw::keygen(&_pk, &_msk, &_attributes).unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_sk_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::LSW => {
                let mut _pk: KpAbePublicKey;
                let mut _msk: KpAbeMasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: KpAbeSecretKey = schemes::lsw::keygen(&_pk, &_msk, &_policy).unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_sk_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::AW11 => {
                let mut _pk: Aw11GlobalKey;
                let mut _msk: Aw11MasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: Aw11SecretKey = schemes::aw11::keygen(&_pk, &_msk, &_name, &_attributes)
                    .unwrap();
                if _as_json {
                    write_file(
                        Path::new(&_name_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_name_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::BDABE => {
                let mut _pk: BdabePublicKey;
                let mut _msk: BdabeSecretAuthorityKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_ska_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_ska_file))))
                        .unwrap()).unwrap();
                }
                let _sk: BdabeUserKey = schemes::bdabe::keygen(&_pk, &_msk, &_name);
                if _as_json {
                    write_file(
                        Path::new(&_name_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_name_file),
                        [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                    );
                }
            }
            Scheme::MKE08 => {
                let mut _pk: Mke08PublicKey;
                let mut _msk: Mke08MasterKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_msk_file))))
                        .unwrap()).unwrap();
                }
                if _name != String::from("") {
                    let _sk: Mke08UserKey = schemes::mke08::keygen(&_pk, &_msk, &_name);
                    if _as_json {
                        write_file(
                            Path::new(&_name_file),
                            serde_json::to_string_pretty(&_sk).unwrap(),
                        );
                    } else {
                        let serialized_sk = to_vec_packed(&_sk).unwrap();
                        write_file(
                            Path::new(&_name_file),
                            [SK_BEGIN, &encode(&serialized_sk).as_str(), SK_END].concat(),
                        );
                    }
                } else {
                    return Err(RabeError::new("MKE08: name for user key not set."));
                }

            }
        }
        Ok(())
    }

    fn run_delegate(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _dg_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(SK_FILE);
                _sk_file.push_str(".");
                _sk_file.push_str(KEY_EXTENSION);
                _dg_file.push_str(SK_FILE);
                _dg_file.push_str("_dele");
                _dg_file.push_str(".");
                _dg_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.values_of("attributes") {
            None => {}
            Some(_attr) => {
                let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                for _a in _b {
                    for _at in _a.split_whitespace() {
                        _attributes.push(_at.to_string());
                    }
                }
            }
        }
        match arguments.value_of("policy") {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match _scheme {
            Scheme::AC17CP => {
                return Err(RabeError::new(
                    "AC17CP does not support the delegation algorithm.",
                ));
            }
            Scheme::AC17KP => {
                return Err(RabeError::new(
                    "AC17KP does not support the delegation algorithm.",
                ));
            }
            Scheme::BSW => {
                let mut _pk: CpAbePublicKey;
                let mut _msk: CpAbeSecretKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _msk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                }
                let _sk: Option<CpAbeSecretKey> = schemes::bsw::delegate(&_pk, &_msk, &_attributes);
                match _sk {
                    None => {
                        return Err(RabeError::new(
                            "Error: could not delegate attributes. Attributes are not a subset.",
                        ));
                    }
                    Some(_delegated_key) => {
                        if _as_json {
                            write_file(
                                Path::new(&_dg_file),
                                serde_json::to_string_pretty(&_delegated_key).unwrap(),
                            );
                        } else {
                            let serialized_dk = to_vec_packed(&_delegated_key).unwrap();
                            write_file(
                                Path::new(&_dg_file),
                                [SK_BEGIN, &encode(&serialized_dk).as_str(), SK_END].concat(),
                            );
                        }
                    }
                }
            }
            Scheme::LSW => {
                return Err(RabeError::new("LSW delegation is not supported (yet)."));
            }
            Scheme::AW11 => {
                return Err(RabeError::new(
                    "AW11 does not support the delegation algorithm.",
                ));
            }
            Scheme::BDABE => {
                return Err(RabeError::new(
                    "BDABE does not support the delegation algorithm.",
                ));
            }
            Scheme::MKE08 => {
                return Err(RabeError::new(
                    "MKE08 does not support the delegation algorithm.",
                ));
            }
        }
        Ok(())
    }

    fn run_encrypt(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _pk_files: Vec<String> = Vec::new();
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _ct_file: String = String::new();
        let mut _pt_file: String = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => {
                let files: Vec<_> = arguments.values_of(PK_FILE).unwrap().collect();
                for file in files {
                    _pk_files.push(file.to_string())
                }
            }
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(GP_FILE);
                _gp_file.push_str(".");
                _gp_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.values_of("attributes") {
            None => {}
            Some(_attr) => {
                let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                for _a in _b {
                    for _at in _a.split_whitespace() {
                        _attributes.push(_at.to_string());
                    }
                }
            }
        }
        match arguments.value_of("policy") {
            None => {}
            Some(x) => _policy = x.to_string(),
        }
        match arguments.value_of("file") {
            None => {}
            Some(_file) => {
                _pt_file = _file.to_string();
                _ct_file = _pt_file.to_string();
                _ct_file.push_str(".");
                _ct_file.push_str(CT_EXTENSION);
            }
        }
        let buffer: Vec<u8> = read_to_vec(Path::new(&_pt_file));
        match _scheme {
            Scheme::AC17CP => {
                let mut _pk: Ac17PublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let _ct = schemes::ac17::cp_encrypt(&_pk, &_policy, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }

            }
            Scheme::AC17KP => {
                let mut _pk: Ac17PublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let _ct = schemes::ac17::kp_encrypt(&_pk, &_attributes, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            }
            Scheme::BSW => {
                let mut _pk: CpAbePublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let _ct = schemes::bsw::encrypt(&_pk, &_policy, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            }
            Scheme::LSW => {
                let mut _pk: KpAbePublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let _ct = schemes::lsw::encrypt(&_pk, &_attributes, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            }
            Scheme::AW11 => {
                let mut _gp: Aw11GlobalKey;
                let mut _pk: Aw11PublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _gp = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                }
                let mut _pks: Vec<Aw11PublicKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: Aw11PublicKey;
                    if _as_json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = from_slice(&decode(&read_raw(&read_file(Path::new(&filename))))
                            .unwrap()).unwrap();
                    }
                    _pks.push(_pka);
                }
                let _ct = schemes::aw11::encrypt(&_gp, &_pks, &_policy, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            } 
            Scheme::BDABE => {
                let mut _pk: BdabePublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let mut _attr_vec: Vec<BdabePublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: BdabePublicAttributeKey;
                    if _as_json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = from_slice(&decode(&read_raw(&read_file(Path::new(&filename))))
                            .unwrap()).unwrap();
                    }
                    _attr_vec.push(_pka);
                }
                let _ct = schemes::bdabe::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            } 
            Scheme::MKE08 => {
                let mut _pk: Mke08PublicKey;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                }
                let mut _attr_vec: Vec<Mke08PublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: Mke08PublicAttributeKey;
                    if _as_json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = from_slice(&decode(&read_raw(&read_file(Path::new(&filename))))
                            .unwrap()).unwrap();
                    }
                    _attr_vec.push(_pka);
                }
                let _ct = schemes::mke08::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
                if _as_json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    let serialized_ct = to_vec_packed(&_ct).unwrap();
                    write_file(
                        Path::new(&_ct_file),
                        [CT_BEGIN, &encode(&serialized_ct).as_str(), CT_END].concat(),
                    );
                }
            } 
        }
        Ok(())
    }

    fn run_decrypt(arguments: &ArgMatches, _scheme: Scheme) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _file: String = String::from("");
        let mut _pt_option: Option<Vec<u8>> = None;
        let mut _policy: String = String::new();
        let mut _as_json = false;
        match arguments.value_of(JSON) {
            None => {}
            Some(_value) => _as_json = true,
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(SK_FILE);
                _sk_file.push_str(".");
                _sk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(GP_FILE);
                _gp_file.push_str(".");
                _gp_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(PK_FILE);
                _pk_file.push_str(".");
                _pk_file.push_str(KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of("file") {
            None => {}
            Some(x) => _file = x.to_string(),
        }
        match arguments.value_of("policy") {
            None => {}
            Some(x) => _policy = x.to_string(),
        }
        match _scheme {
            Scheme::AC17CP => {
                let mut _sk: Ac17CpSecretKey;
                let mut _ct: Ac17CpCiphertext;
                if _as_json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::ac17::cp_decrypt(&_sk, &_ct);
            }
            Scheme::AC17KP => {
                let mut _sk: Ac17KpSecretKey;
                let mut _ct: Ac17KpCiphertext;
                if _as_json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::ac17::kp_decrypt(&_sk, &_ct);
            }
            Scheme::BSW => {
                let mut _sk: CpAbeSecretKey;
                let mut _ct: CpAbeCiphertext;
                if _as_json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::bsw::decrypt(&_sk, &_ct);
            }
            Scheme::LSW => {
                let mut _sk: KpAbeSecretKey;
                let mut _ct: KpAbeCiphertext;
                if _as_json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::lsw::decrypt(&_sk, &_ct);
            }
            Scheme::AW11 => {
                let mut _gp: Aw11GlobalKey;
                let mut _sk: Aw11SecretKey;
                let mut _ct: Aw11Ciphertext;
                if _as_json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _gp = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::aw11::decrypt(&_gp, &_sk, &_ct);
            } 
            Scheme::BDABE => {
                let mut _pk: BdabePublicKey;
                let mut _sk: BdabeUserKey;
                let mut _ct: BdabeCiphertext;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                        .unwrap()).unwrap();
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::bdabe::decrypt(&_pk, &_sk, &_ct);
            } 
            Scheme::MKE08 => {
                let mut _pk: Mke08PublicKey;
                let mut _sk: Mke08UserKey;
                let mut _ct: Mke08Ciphertext;
                if _as_json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                    _sk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                        .unwrap()).unwrap();
                    _ct = from_slice(&decode(&read_raw(&read_file(Path::new(&_file)))).unwrap())
                        .unwrap();
                }
                _pt_option = schemes::mke08::decrypt(&_pk, &_sk, &_ct);
            } 
        }
        match _pt_option {
            None => {
                return Err(RabeError::new("Error: could not decrypt!"));
            }
            Some(_pt_u) => {
                write_from_vec(Path::new(&_file), &_pt_u);
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
            Ok(_) => print!("successfully read {}", display),
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

    fn read_raw(_raw: &String) -> String {
        let lines = &mut _raw.lines();
        let middle = lines.nth(1).unwrap().to_string();
        return middle;
    }

    fn write_file(_path: &Path, _content: String) -> bool {
        let display = _path.display();
        let mut file = match File::create(_path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.description()),
            Ok(file) => file,
        };
        let mut _ret: bool = false;
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

trait StringUtils {
    fn substring(&self, start: usize, len: usize) -> &str;
    fn slice(&self, range: impl RangeBounds<usize>) -> &str;
    fn find(&self, char: char) -> usize;
}

impl StringUtils for str {
    fn substring(&self, start: usize, len: usize) -> &str {
        let mut char_pos = 0;
        let mut byte_start = 0;
        let mut it = self.chars();
        loop {
            if char_pos == start {
                break;
            }
            if let Some(c) = it.next() {
                char_pos += 1;
                byte_start += c.len_utf8();
            } else {
                break;
            }
        }
        char_pos = 0;
        let mut byte_end = byte_start;
        loop {
            if char_pos == len {
                break;
            }
            if let Some(c) = it.next() {
                char_pos += 1;
                byte_end += c.len_utf8();
            } else {
                break;
            }
        }
        &self[byte_start..byte_end]
    }
    fn slice(&self, range: impl RangeBounds<usize>) -> &str {
        let start = match range.start_bound() {
            Bound::Included(bound) |
            Bound::Excluded(bound) => *bound,
            Bound::Unbounded => 0,
        };
        let len = match range.end_bound() {
            Bound::Included(bound) => *bound + 1,
            Bound::Excluded(bound) => *bound,
            Bound::Unbounded => self.len(),
        } - start;
        self.substring(start, len)
    }
    fn find(&self, char: char) -> usize {
        let char_vec: Vec<char> = self.chars().collect();
        let mut counter: usize = 0;
        for c in char_vec {
            if c == char {
                break;
            } else {
                counter += 1;
            }
        }
        return counter;
    }
}
