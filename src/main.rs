//! This is the documentation for the RABE console application.
//!
//! * Developped by Georg Bramm, Fraunhofer AISEC
//! * Date: 04/2018
//!
extern crate base64;
extern crate bincode;
extern crate blake2_rfc;
#[allow(dead_code)]
extern crate bn;
extern crate crypto;
extern crate num_bigint;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate paillier;
extern crate mongodb;
extern crate bson;
#[macro_use]
extern crate lazy_static;

mod schemes;
mod utils;

use base64::{decode, encode};
use clap::{App, Arg, ArgMatches, SubCommand};
use schemes::abe::ac17::*;
use schemes::abe::aw11::*;
use schemes::abe::bdabe::*;
use schemes::abe::bsw::*;
use schemes::abe::lsw::*;
use schemes::abe::mke08::*;
use utils::file::{write_file, read_file, read_raw, write_from_vec, read_to_vec};
use serde_cbor::ser::to_vec_packed;
use serde_cbor::from_slice;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::process;



#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate serde_cbor;

// File extensions
const CT_EXTENSION: &'static str = "rct";
const KEY_EXTENSION: &'static str = "rkey";
const KEY_DELEGATE_EXTENSION: &'static str = "rdel";
const DOT: &'static str = ".";

// Object names
const ATTRIBUTES: &'static str = "attr";
const ATTRIBUTES_LONG: &'static str = "attribute(s)";
const POLICY: &'static str = "policy";
const NAME: &'static str = "name";
const SCHEME: &'static str = "scheme";
const JSON: &'static str = "json";
const FILE: &'static str = "file";

// Default file names
const GP_FILE: &'static str = "gp";
const MSK_FILE: &'static str = "msk";
const PK_FILE: &'static str = "pk";
const SK_FILE: &'static str = "sk";
const SKA_FILE: &'static str = "ska";
const PKA_FILE: &'static str = "pka";
const AU_PK_FILE: &'static str = "pkau";
const AU_SK_FILE: &'static str = "skau";

// Default file descriptions
const GP_FILE_LONG: &'static str = "global parameters";
const MSK_FILE_LONG: &'static str = "master secret key";
const SK_FILE_LONG: &'static str = "secret key";
const PK_FILE_LONG: &'static str = "public key";
const SKA_FILE_LONG: &'static str = "secret attribute key";
const PKA_FILE_LONG: &'static str = "public attribute key";
//const AU_PK_FILE_LONG: &'static str = "attribute authority public key";
const AU_SK_FILE_LONG: &'static str = "attribute authority secret key";

// Key file header and footer
const GP_BEGIN: &'static str = "-----BEGIN GLOBAL PARAMETERS-----\n";
const GP_END: &'static str = "\n-----END GLOBAL PARAMETERS-----";
const SK_BEGIN: &'static str = "-----BEGIN SECRET KEY-----\n";
const SK_END: &'static str = "\n-----END SECRET KEY-----";
const MSK_BEGIN: &'static str = "-----BEGIN MASTER SECRET KEY-----\n";
const MSK_END: &'static str = "\n-----END MASTER SECRET KEY-----";
const PK_BEGIN: &'static str = "-----BEGIN PUBLIC KEY-----\n";
const PK_END: &'static str = "\n-----END PUBLIC KEY-----";
const CT_BEGIN: &'static str = "-----BEGIN CIPHERTEXT-----\n";
const CT_END: &'static str = "\n-----END CIPHERTEXT-----";
const SKA_BEGIN: &'static str = "-----BEGIN SECRET ATTRIBUTE KEY-----\n";
const SKA_END: &'static str = "\n-----END SECRET ATTRIBUTE KEY-----";
const PKA_BEGIN: &'static str = "-----BEGIN PUBLIC ATTRIBUTE-----\n";
const PKA_END: &'static str = "\n-----END PUBLIC ATTRIBUTE-----";
const AU_PK_BEGIN: &'static str = "-----BEGIN PUBLIC AUTHORITY-----\n";
const AU_PK_END: &'static str = "\n-----END PUBLIC AUTHORITY-----";
const AU_SK_BEGIN: &'static str = "-----BEGIN SECRET AUTHORITY-----\n";
const AU_SK_END: &'static str = "\n-----END SECRET AUTHORITY-----";

// Application commands
const CMD_SETUP: &'static str = "setup";
const CMD_AUTHGEN: &'static str = "authgen";
const CMD_KEYGEN: &'static str = "keygen";
const CMD_DELEGATE: &'static str = "delegate";
const CMD_ENCRYPT: &'static str = "encrypt";
const CMD_DECRYPT: &'static str = "decrypt";
const CMD_REQ_ATTR_PK: &'static str = "req-attr-pk";
const CMD_REQ_ATTR_SK: &'static str = "req-attr-sk";

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
        write!(f, "Error: {}", self.details)
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
    // Default file names
    let _gp_default = [GP_FILE, DOT, KEY_EXTENSION].concat();
    let _msk_default = [MSK_FILE, DOT, KEY_EXTENSION].concat();
    let _pk_default = [PK_FILE, DOT, KEY_EXTENSION].concat();

    let _sk_default = [SK_FILE, DOT, KEY_EXTENSION].concat();
    let _ska_default = [SKA_FILE, DOT, KEY_EXTENSION].concat();
    let _pka_default = [PKA_FILE, DOT, KEY_EXTENSION].concat();
    let _au_pk_default = [AU_PK_FILE, DOT, KEY_EXTENSION].concat();
    let _au_sk_default = [AU_SK_FILE, DOT, KEY_EXTENSION].concat();

    let _abe_app = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            Arg::with_name(SCHEME)
                .long(SCHEME)
                .required(true)
                .takes_value(true)
                .possible_values(&Scheme::variants())
                .help("scheme(s) to use."),
        )
        .arg(
            Arg::with_name(JSON)
                .long(JSON)
                .required(false)
                .takes_value(false),
        )
        .subcommand(
            // Setup
            SubCommand::with_name(CMD_SETUP)
                .about("sets up a new scheme, creates the msk and pk or gp.")
                .arg(
                    Arg::with_name(MSK_FILE)
                        .long(MSK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(GP_FILE)
                        .long(GP_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                ),
        )
        .subcommand(
            // Authgen
            SubCommand::with_name(CMD_AUTHGEN)
                .about("creates a new authority using attribute(s) or a policy.")
                .arg(
                    Arg::with_name(GP_FILE)
                        .long(GP_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(MSK_FILE)
                        .long(MSK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("attributes to use."),
                )
                .arg(
                    Arg::with_name(POLICY)
                        .required(false)
                        .takes_value(true)
                        .help("policy to use."),
                )
                .arg(
                    Arg::with_name(NAME)
                        .required(false)
                        .takes_value(true)
                        .help("name/id of the new attribute authority (MKE08/BDABE)"),
                ),
        )
        .subcommand(
            // Keygen
            SubCommand::with_name(CMD_KEYGEN)
                .about(
                    "creates a user key sk using attributes (cp-schemes) or a policy (kp-schemes).",
                )
                .arg(
                    Arg::with_name(GP_FILE)
                        .long(GP_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(MSK_FILE)
                        .long(MSK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .long(SK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .long(AU_SK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("authrotiy secret key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("attributes to use."),
                )
                .arg(
                    Arg::with_name(POLICY)
                        .long(POLICY)
                        .required(false)
                        .takes_value(true)
                        .help("policy to use."),
                )
                .arg(
                    Arg::with_name(NAME)
                        .long(NAME)
                        .required(false)
                        .takes_value(true)
                        .help("name/id of the user (AW11)"),
                ),
        )
        .subcommand(
            // Delegate
            SubCommand::with_name(CMD_DELEGATE)
                .about("delegates attributes to a new subkey (cp-schemes)")
                .arg(
                    Arg::with_name(SK_FILE)
                        .long(SK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("attribute(s) to use."),
                ),
        )
        .subcommand(
            // Encrypt
            SubCommand::with_name(CMD_ENCRYPT)
                .about(
                    "encrypts a file using attributes (kp-schemes) or a policy (cp-schemes).",
                )
                .arg(
                    Arg::with_name(GP_FILE)
                        .long(GP_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .default_value(&_pk_default)
                        .help("public key file(s)."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("the attribute(s) to use."),
                )
                .arg(
                    Arg::with_name(POLICY)
                        .long(POLICY)
                        .required(false)
                        .takes_value(true)
                        .help("the policy to use."),
                )
                .arg(
                    Arg::with_name(FILE)
                        .long(FILE)
                        .required(true)
                        .takes_value(true)
                        .help("the file to encrypt."),
                ),
        )
        .subcommand(
            // Decrypt
            SubCommand::with_name(CMD_DECRYPT)
                .about("decrypts a file using a key.")
                .arg(
                    Arg::with_name(GP_FILE)
                        .long(GP_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .long(SK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(FILE)
                        .long(FILE)
                        .required(true)
                        .takes_value(true)
                        .help("file to use."),
                ),
        )
        .subcommand(
            // Request Attribute PK
            SubCommand::with_name(CMD_REQ_ATTR_PK)
                .about(
                    "Requests the attribute public key from an authority (BDABE).",
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .long(PK_FILE_LONG)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file of the system."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .long(AU_SK_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("secret key file of authority."),
                )
                .arg(
                    Arg::with_name(PKA_FILE)
                        .long(PKA_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pka_default)
                        .help("public attribute key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .help("attribute to use."),
                ),
        )
        .subcommand(
            // Request Attribute SK
            SubCommand::with_name(CMD_REQ_ATTR_SK)
                .about(
                    "Requests the attribute public key from an authority (BDABE).",
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .long(SK_FILE_LONG)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(SKA_FILE)
                        .long(SKA_FILE_LONG)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_ska_default)
                        .help("secret attribute key file."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .long(AU_SK_FILE_LONG)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("secret attribute authority key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .long(ATTRIBUTES_LONG)
                        .required(false)
                        .takes_value(true)
                        .help("attribute to use."),
                ),
        )
        .get_matches();

    if let Err(e) = run(_abe_app) {
        println!("Application error: {}", e);
        process::exit(1);
    }

    fn run(matches: ArgMatches) -> Result<(), RabeError> {
        let _scheme = value_t!(matches.value_of("scheme"), Scheme).unwrap();
        let _json: bool = matches.is_present(JSON);
        match matches.subcommand() {
            (CMD_SETUP, Some(matches)) => run_setup(matches, _scheme, _json),
            (CMD_AUTHGEN, Some(matches)) => run_authgen(matches, _scheme, _json),
            (CMD_KEYGEN, Some(matches)) => run_keygen(matches, _scheme, _json),
            (CMD_DELEGATE, Some(matches)) => run_delegate(matches, _scheme, _json),
            (CMD_ENCRYPT, Some(matches)) => run_encrypt(matches, _scheme, _json),
            (CMD_DECRYPT, Some(matches)) => run_decrypt(matches, _scheme, _json),
            (CMD_REQ_ATTR_PK, Some(matches)) => run_req_attr_pk(matches, _scheme, _json),
            (CMD_REQ_ATTR_SK, Some(matches)) => run_req_attr_sk(matches, _scheme, _json),
            _ => Ok(()),
        }
    }

    fn run_setup(arguments: &ArgMatches, _scheme: Scheme, _as_json: bool) -> Result<(), RabeError> {
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(&MSK_FILE);
                _msk_file.push_str(&DOT);
                _msk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(&GP_FILE);
                _gp_file.push_str(&DOT);
                _gp_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match _scheme {
            Scheme::AC17CP | Scheme::AC17KP => {
                let (_pk, _msk) = schemes::abe::ac17::setup();
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
                let _gp = schemes::abe::aw11::setup();
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
                let (_pk, _msk) = schemes::abe::bdabe::setup();
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
                let (_pk, _msk) = schemes::abe::bsw::setup();
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
                let (_pk, _msk) = schemes::abe::lsw::setup();
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
                let (_pk, _msk) = schemes::abe::mke08::setup();
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

    fn run_authgen(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _name: String = String::from("");
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _au_file = String::from("");
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(&MSK_FILE);
                _msk_file.push_str(&DOT);
                _msk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(&GP_FILE);
                _gp_file.push_str(&DOT);
                _gp_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        match arguments.value_of(POLICY) {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of(NAME) {
            None => {}
            Some(_n) => {
                _name = _n.to_string();
                _au_file.push_str(&_n.to_string());
                _au_file.push_str(&DOT);
                _au_file.push_str(&KEY_EXTENSION)
            }
        }
        match _scheme {
            Scheme::AC17CP | Scheme::AC17KP | Scheme::BSW | Scheme::LSW => {
                return Err(RabeError::new("sorry, this is not a multi-authoriy scheme"));
            }
            Scheme::AW11 => {
                let mut _gp: Aw11GlobalKey;
                if _as_json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
                    _gp = from_slice(&decode(&read_raw(&read_file(Path::new(&_gp_file))))
                        .unwrap()).unwrap();
                }
                match schemes::abe::aw11::authgen(&_gp, &_attributes) {
                    None => {
                        return Err(RabeError::new(
                            "sorry, could not generate authority. The attribute set empty.",
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
                                [AU_SK_BEGIN, &encode(&serialized_msk).as_str(), AU_SK_END].concat(),
                            );
                            write_file(
                                Path::new(&_pk_file),
                                [AU_PK_BEGIN, &encode(&serialized_pk).as_str(), AU_PK_END].concat(),
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
                let _sk: BdabeSecretAuthorityKey =
                    schemes::abe::bdabe::authgen(&_pk, &_msk, &_name);
                if _as_json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_au_file),
                        [AU_SK_BEGIN, &encode(&serialized_sk).as_str(), AU_SK_END].concat(),
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
                let _sk: Mke08SecretAuthorityKey = schemes::abe::mke08::authgen(&_name);
                if _as_json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    let serialized_sk = to_vec_packed(&_sk).unwrap();
                    write_file(
                        Path::new(&_au_file),
                        [AU_SK_BEGIN, &encode(&serialized_sk).as_str(), AU_SK_END].concat(),
                    );
                }
            }
        }
        Ok(())
    }

    fn run_keygen(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _ska_file = String::from("");
        let mut _name = String::from("");
        let mut _name_file = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(&MSK_FILE);
                _msk_file.push_str(&DOT);
                _msk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => {
                _msk_file = _file.to_string();
            }
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(&GP_FILE);
                _gp_file.push_str(&DOT);
                _gp_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(SKA_FILE) {
            None => {
                _ska_file.push_str(&SKA_FILE);
                _ska_file.push_str(&DOT);
                _ska_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _ska_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        match arguments.value_of(POLICY) {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of(NAME) {
            None => {}
            Some(_n) => {
                _name = _n.to_string();
                _name_file.push_str(&_n.to_string());
                _name_file.push_str(&DOT);
                _name_file.push_str(&KEY_EXTENSION);
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
                let _sk: Ac17CpSecretKey = schemes::abe::ac17::cp_keygen(&_msk, &_attributes)
                    .unwrap();
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
                let _sk: Ac17KpSecretKey = schemes::abe::ac17::kp_keygen(&_msk, &_policy).unwrap();
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
                let _sk: CpAbeSecretKey = schemes::abe::bsw::keygen(&_pk, &_msk, &_attributes)
                    .unwrap();
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
                let _sk: KpAbeSecretKey = schemes::abe::lsw::keygen(&_pk, &_msk, &_policy).unwrap();
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
                let _sk: Aw11SecretKey =
                    schemes::abe::aw11::keygen(&_pk, &_msk, &_name, &_attributes).unwrap();
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
                let _sk: BdabeUserKey = schemes::abe::bdabe::keygen(&_pk, &_msk, &_name);
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
                    let _sk: Mke08UserKey = schemes::abe::mke08::keygen(&_pk, &_msk, &_name);
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
                    return Err(RabeError::new(
                        "sorry, the name/id for the user key is not set.",
                    ));
                }
            }
        }
        Ok(())
    }

    fn run_delegate(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _dg_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
                _dg_file.push_str(&SK_FILE);
                _dg_file.push_str(&DOT);
                _dg_file.push_str(&KEY_DELEGATE_EXTENSION);
                _dg_file.push_str(&DOT);
                _dg_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        match arguments.value_of(POLICY) {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match _scheme {
            Scheme::AC17CP | Scheme::AC17KP | Scheme::LSW | Scheme::AW11 | Scheme::BDABE |
            Scheme::MKE08 => {
                return Err(RabeError::new(
                    "sorry, this scheme does not support the delegation algorithm.",
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
                let _sk: Option<CpAbeSecretKey> =
                    schemes::abe::bsw::delegate(&_pk, &_msk, &_attributes);
                match _sk {
                    None => {
                        return Err(RabeError::new(
                            "sorry, could not delegate attributes. The given attributes are not a subset.",
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
        }
        Ok(())
    }

    fn run_encrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _pk_files: Vec<String> = Vec::new();
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _ct_file: String = String::new();
        let mut _pt_file: String = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
                _pk_files.push(_pk_file.clone());
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
                _gp_file.push_str(&GP_FILE);
                _gp_file.push_str(&DOT);
                _gp_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        match arguments.value_of(POLICY) {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of(FILE) {
            None => {}
            Some(_file) => {
                _pt_file = _file.to_string();
                _ct_file = _pt_file.to_string();
                _ct_file.push_str(&DOT);
                _ct_file.push_str(&CT_EXTENSION);
            }
        }
        let buffer: Vec<u8> = read_to_vec(Path::new(&_pt_file));
        match _scheme {
            Scheme::AC17CP => {
                let mut _pk: Ac17PublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    _pk_file = _pk_files[0].clone();
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    } else {
                        _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                            .unwrap()).unwrap();
                    }
                    let _ct = schemes::abe::ac17::cp_encrypt(&_pk, &_policy, &buffer);
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
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the AC17CP Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::AC17KP => {
                let mut _pk: Ac17PublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    _pk_file = _pk_files[0].clone();
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    } else {
                        _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                            .unwrap()).unwrap();
                    }
                    let _ct = schemes::abe::ac17::kp_encrypt(&_pk, &_attributes, &buffer);
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
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the AC17KP Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::BSW => {
                let mut _pk: CpAbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = from_slice(&decode(
                            &read_raw(&read_file(Path::new(&_pk_files[0].clone()))),
                        ).unwrap()).unwrap();
                    }
                    let _ct = schemes::abe::bsw::encrypt(&_pk, &_policy, &buffer);
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
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the BSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::LSW => {
                let mut _pk: KpAbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = from_slice(&decode(
                            &read_raw(&read_file(Path::new(&_pk_files[0].clone()))),
                        ).unwrap()).unwrap();
                    }
                    let _ct = schemes::abe::lsw::encrypt(&_pk, &_attributes, &buffer);
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
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the LSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::AW11 => {
                let mut _gp: Aw11GlobalKey;
                if _as_json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
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
                let _ct = schemes::abe::aw11::encrypt(&_gp, &_pks, &_policy, &buffer);
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
                let _ct = schemes::abe::bdabe::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
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
                let _ct = schemes::abe::mke08::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
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

    fn run_decrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _file: String = String::from("");
        let mut _pt_option: Option<Vec<u8>> = None;
        let mut _policy: String = String::new();
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(GP_FILE) {
            None => {
                _gp_file.push_str(&GP_FILE);
                _gp_file.push_str(&DOT);
                _gp_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _gp_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(FILE) {
            None => {}
            Some(x) => _file = x.to_string(),
        }
        match arguments.value_of(POLICY) {
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
                _pt_option = schemes::abe::ac17::cp_decrypt(&_sk, &_ct);
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
                _pt_option = schemes::abe::ac17::kp_decrypt(&_sk, &_ct);
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
                _pt_option = schemes::abe::bsw::decrypt(&_sk, &_ct);
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
                _pt_option = schemes::abe::lsw::decrypt(&_sk, &_ct);
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
                _pt_option = schemes::abe::aw11::decrypt(&_gp, &_sk, &_ct);
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
                _pt_option = schemes::abe::bdabe::decrypt(&_pk, &_sk, &_ct);
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
                _pt_option = schemes::abe::mke08::decrypt(&_pk, &_sk, &_ct);
            }
        }
        match _pt_option {
            None => {
                return Err(RabeError::new("sorry, could not decrypt!"));
            }
            Some(_pt_u) => {
                write_from_vec(Path::new(&_file), &_pt_u);
            }
        }
        Ok(())
    }

    fn run_req_attr_pk(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _pk_file = String::from("");
        let mut _au_sk_file = String::from("");
        let mut _pka_file = String::from("");
        let mut _attributes: Vec<String> = Vec::new();
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(AU_SK_FILE) {
            None => {
                _au_sk_file.push_str(&AU_SK_FILE);
                _au_sk_file.push_str(&DOT);
                _au_sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _au_sk_file = _file.to_string(),
        }
        match arguments.value_of(PKA_FILE) {
            None => {
                _pka_file.push_str(&PKA_FILE);
                _pka_file.push_str(&DOT);
                _pka_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pka_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        if _attributes.len() == 1 {
            match _scheme {
                Scheme::AC17CP | Scheme::AC17KP | Scheme::AW11 | Scheme::BSW | Scheme::LSW => {
                    return Err(RabeError::new(
                        "sorry, this scheme does not support the request attribute PK algorithm.",
                    ));
                }
                Scheme::MKE08 => {
                    let mut _pk: Mke08PublicKey;
                    let mut _ska: Mke08SecretAuthorityKey;
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                        _ska = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                            .unwrap()).unwrap();
                        _ska = from_slice(&decode(&read_raw(&read_file(Path::new(&_au_sk_file))))
                            .unwrap()).unwrap();
                    }
                    match schemes::abe::mke08::request_authority_pk(&_pk, &_attributes[0], &_ska) {
                        None => {}
                        Some(_a_pk) => {
                            if _as_json {
                                write_file(
                                    Path::new(&_pka_file),
                                    serde_json::to_string_pretty(&_a_pk).unwrap(),
                                );
                            } else {
                                let serialized_a_pk = to_vec_packed(&_a_pk).unwrap();
                                write_file(
                                    Path::new(&_pka_file),
                                    [PKA_BEGIN, &encode(&serialized_a_pk).as_str(), PKA_END]
                                        .concat(),
                                );
                            }
                        }
                    }
                }
                Scheme::BDABE => {
                    let mut _pk: BdabePublicKey;
                    let mut _ska: BdabeSecretAuthorityKey;
                    if _as_json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                        _ska = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _pk = from_slice(&decode(&read_raw(&read_file(Path::new(&_pk_file))))
                            .unwrap()).unwrap();
                        _ska = from_slice(&decode(&read_raw(&read_file(Path::new(&_au_sk_file))))
                            .unwrap()).unwrap();
                    }
                    match schemes::abe::bdabe::request_attribute_pk(&_pk, &_ska, &_attributes[0]) {
                        None => {}
                        Some(_a_pk) => {
                            if _as_json {
                                write_file(
                                    Path::new(&_pka_file),
                                    serde_json::to_string_pretty(&_a_pk).unwrap(),
                                );
                            } else {
                                let serialized_a_pk = to_vec_packed(&_a_pk).unwrap();
                                write_file(
                                    Path::new(&_pka_file),
                                    [PKA_BEGIN, &encode(&serialized_a_pk).as_str(), PKA_END]
                                        .concat(),
                                );
                            }
                        }
                    }
                }
            }
        } else {
            return Err(RabeError::new(
                "sorry, could not request because only one attribute is allowed.",
            ));
        }
        Ok(())
    }

    fn run_req_attr_sk(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _as_json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _ask_file = String::from("");
        let mut _au_sk_file = String::from("");
        let mut _attributes: Vec<String> = Vec::new();
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(AU_SK_FILE) {
            None => {
                _au_sk_file.push_str(&AU_SK_FILE);
                _au_sk_file.push_str(&DOT);
                _au_sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _au_sk_file = _file.to_string(),
        }
        match arguments.value_of(SKA_FILE) {
            None => {
                _ask_file.push_str(&SKA_FILE);
                _ask_file.push_str(&DOT);
                _ask_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _ask_file = _file.to_string(),
        }
        match arguments.values_of(ATTRIBUTES) {
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
        if _attributes.len() == 1 {
            match _scheme {
                Scheme::AC17CP | Scheme::AC17KP | Scheme::AW11 | Scheme::BSW | Scheme::LSW => {
                    return Err(RabeError::new(
                        "sorry, this scheme does not support the request attribute SK algorithm.",
                    ));
                }
                Scheme::MKE08 => {
                    let mut _usk: Mke08UserKey;
                    let mut _ska: Mke08SecretAttributeKey;
                    let mut _skau: Mke08SecretAuthorityKey;
                    if _as_json {
                        _usk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                        _skau = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _usk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                            .unwrap()).unwrap();
                        _skau = from_slice(&decode(&read_raw(&read_file(Path::new(&_au_sk_file))))
                            .unwrap()).unwrap();
                    }
                    match schemes::abe::mke08::request_authority_sk(
                        &_attributes[0],
                        &_skau,
                        &_usk._pk_u,
                    ) {
                        None => {}
                        Some(_a_sk) => {
                            if _as_json {
                                write_file(
                                    Path::new(&_ask_file),
                                    serde_json::to_string_pretty(&_a_sk).unwrap(),
                                );
                            } else {
                                let serialized_a_sk = to_vec_packed(&_a_sk).unwrap();
                                write_file(
                                    Path::new(&_ask_file),
                                    [SKA_BEGIN, &encode(&serialized_a_sk).as_str(), SKA_END]
                                        .concat(),
                                );
                            }
                        }
                    }
                }
                Scheme::BDABE => {
                    let mut _usk: BdabeUserKey;
                    let mut _ska: BdabeSecretAttributeKey;
                    let mut _skau: BdabeSecretAuthorityKey;
                    if _as_json {
                        _usk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                        _skau = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _usk = from_slice(&decode(&read_raw(&read_file(Path::new(&_sk_file))))
                            .unwrap()).unwrap();
                        _skau = from_slice(&decode(&read_raw(&read_file(Path::new(&_au_sk_file))))
                            .unwrap()).unwrap();
                    }
                    match schemes::abe::bdabe::request_attribute_sk(
                        &_usk._pk,
                        &_skau,
                        &_attributes[0],
                    ) {
                        None => {}
                        Some(_a_sk) => {
                            if _as_json {
                                write_file(
                                    Path::new(&_ask_file),
                                    serde_json::to_string_pretty(&_a_sk).unwrap(),
                                );
                            } else {
                                let serialized_a_sk = to_vec_packed(&_a_sk).unwrap();
                                write_file(
                                    Path::new(&_ask_file),
                                    [SKA_BEGIN, &encode(&serialized_a_sk).as_str(), SKA_END]
                                        .concat(),
                                );
                            }
                        }
                    }
                }
            }
        } else {
            return Err(RabeError::new(
                "sorry, could not request because only one attribute is allowed.",
            ));
        }
        Ok(())
    }
}
