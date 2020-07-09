//! This is the documentation for the RABE console application.
//!
//! * Developped by Georg Bramm, Fraunhofer AISEC
//! * Date: 04/2018
//!
#![allow(dead_code)]

extern crate bn;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate crypto;
extern crate bincode;
extern crate num_bigint;
extern crate blake2_rfc;

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
use std::path::Path;
use std::fmt;

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;


const CT_EXTENSION: &'static str = "rabe";
const KEY_EXTENSION: &'static str = "key";
const GP_FILE: &'static str = "gp";
const MSK_FILE: &'static str = "msk";
const SK_FILE: &'static str = "sk";
const SKA_FILE: &'static str = "ska";
const PK_FILE: &'static str = "pk";

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
        .version("0.1.1")
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
                    Arg::with_name("msk")
                        .long("msk")
                        .required(false)
                        .takes_value(true)
                        .value_name("msk")
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
                write_file(
                    Path::new(&_msk_file),
                    serde_json::to_string_pretty(&_msk).unwrap(),
                );
                write_file(
                    Path::new(&_pk_file),
                    serde_json::to_string_pretty(&_pk).unwrap(),
                );
            }
            Scheme::AW11 => {
                let _gp = schemes::aw11::setup();
                write_file(
                    Path::new(&_gp_file),
                    serde_json::to_string_pretty(&_gp).unwrap(),
                );
            }
            Scheme::BDABE => {
                let (_pk, _msk) = schemes::bdabe::setup();
                write_file(
                    Path::new(&_msk_file),
                    serde_json::to_string_pretty(&_msk).unwrap(),
                );
                write_file(
                    Path::new(&_pk_file),
                    serde_json::to_string_pretty(&_pk).unwrap(),
                );
            }
            Scheme::BSW => {
                let (_pk, _msk) = schemes::bsw::setup();
                write_file(
                    Path::new(&_msk_file),
                    serde_json::to_string_pretty(&_msk).unwrap(),
                );
                write_file(
                    Path::new(&_pk_file),
                    serde_json::to_string_pretty(&_pk).unwrap(),
                );
            }
            Scheme::LSW => {
                let (_pk, _msk) = schemes::lsw::setup();
                write_file(
                    Path::new(&_msk_file),
                    serde_json::to_string_pretty(&_msk).unwrap(),
                );
                write_file(
                    Path::new(&_pk_file),
                    serde_json::to_string_pretty(&_pk).unwrap(),
                );
            } 
            Scheme::MKE08 => {
                let (_pk, _msk) = schemes::mke08::setup();
                write_file(
                    Path::new(&_msk_file),
                    serde_json::to_string_pretty(&_msk).unwrap(),
                );
                write_file(
                    Path::new(&_pk_file),
                    serde_json::to_string_pretty(&_pk).unwrap(),
                );
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
            Some(_attr) => _attributes = _attr.map(|s| s.to_string()).collect(),
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
                let _gp: Aw11GlobalKey = serde_json::from_str(&read_file(Path::new(&_gp_file)))
                    .unwrap();
                match schemes::aw11::authgen(&_gp, &_attributes) {
                    None => {
                        return Err(RabeError::new(
                            "could not generate authority. Attribute set empty.",
                        ));
                    }
                    Some((_pk, _msk)) => {
                        write_file(
                            Path::new(&_msk_file),
                            serde_json::to_string_pretty(&_msk).unwrap(),
                        );
                        write_file(
                            Path::new(&_pk_file),
                            serde_json::to_string_pretty(&_pk).unwrap(),
                        );
                    }
                }
            }
            Scheme::BDABE => {
                let _pk: BdabePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _msk: BdabeMasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _sk: BdabeSecretAuthorityKey = schemes::bdabe::authgen(&_pk, &_msk, &_name);
                write_file(
                    Path::new(&_au_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::MKE08 => {
                let _pk: Mke08PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _msk: Mke08MasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _sk: Mke08SecretAuthorityKey = schemes::mke08::authgen(&_name);
                write_file(
                    Path::new(&_au_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
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
            Some(_attr) => _attributes = _attr.map(|s| s.to_string()).collect(),
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
                let _msk: Ac17MasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _sk: Ac17CpSecretKey = schemes::ac17::cp_keygen(&_msk, &_attributes).unwrap();
                write_file(
                    Path::new(&_sk_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::AC17KP => {
                let _msk: Ac17MasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _sk: Ac17KpSecretKey = schemes::ac17::kp_keygen(&_msk, &_policy).unwrap();
                write_file(
                    Path::new(&_sk_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::BSW => {
                let _msk: CpAbeMasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _pk: CpAbePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _sk: CpAbeSecretKey = schemes::bsw::keygen(&_pk, &_msk, &_attributes).unwrap();
                write_file(
                    Path::new(&_sk_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::LSW => {
                let _msk: KpAbeMasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _pk: KpAbePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _sk: KpAbeSecretKey = schemes::lsw::keygen(&_pk, &_msk, &_policy).unwrap();
                write_file(
                    Path::new(&_sk_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::AW11 => {
                let _msk: Aw11MasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                let _gp: Aw11GlobalKey = serde_json::from_str(&read_file(Path::new(&_gp_file)))
                    .unwrap();
                let _sk: Aw11SecretKey = schemes::aw11::keygen(&_gp, &_msk, &_name, &_attributes)
                    .unwrap();
                write_file(
                    Path::new(&_name_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::BDABE => {
                let _pk: BdabePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _ska: BdabeSecretAuthorityKey =
                    serde_json::from_str(&read_file(Path::new(&_ska_file))).unwrap();
                let _sk: BdabeUserKey = schemes::bdabe::keygen(&_pk, &_ska, &_name);
                write_file(
                    Path::new(&_name_file),
                    serde_json::to_string_pretty(&_sk).unwrap(),
                );
            }
            Scheme::MKE08 => {
                let _pk: Mke08PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _msk: Mke08MasterKey = serde_json::from_str(&read_file(Path::new(&_msk_file)))
                    .unwrap();
                if _name != String::from("") {
                    let _sk: Mke08UserKey = schemes::mke08::keygen(&_pk, &_msk, &_name);
                    write_file(
                        Path::new(&_name_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
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
            Some(_attr) => _attributes = _attr.map(|s| s.to_string()).collect(),
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
                let _msk: CpAbeSecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _pk: CpAbePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _sk: Option<CpAbeSecretKey> = schemes::bsw::delegate(&_pk, &_msk, &_attributes);
                match _sk {
                    None => {
                        return Err(RabeError::new(
                            "Error: could not delegate attributes. Attributes are not a subset.",
                        ));
                    }
                    Some(_delegated_key) => {
                        write_file(
                            Path::new(&_dg_file),
                            serde_json::to_string_pretty(&_delegated_key).unwrap(),
                        );
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
            Some(x) => _attributes = x.map(|s| s.to_string()).collect(),
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
                let _pk: Ac17PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _ct = schemes::ac17::cp_encrypt(&_pk, &_policy, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );

            }
            Scheme::AC17KP => {
                let _pk: Ac17PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _ct = schemes::ac17::kp_encrypt(&_pk, &_attributes, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
            }
            Scheme::BSW => {
                let _pk: CpAbePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _ct = schemes::bsw::encrypt(&_pk, &_policy, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
            }
            Scheme::LSW => {
                let _pk: KpAbePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _ct = schemes::lsw::encrypt(&_pk, &_attributes, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
            }
            Scheme::AW11 => {
                let _gp: Aw11GlobalKey = serde_json::from_str(&read_file(Path::new(&_gp_file)))
                    .unwrap();
                let _pk: Aw11PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let mut _pks: Vec<Aw11PublicKey> = Vec::new();
                for filename in _pk_files {
                    let _pk: Aw11PublicKey = serde_json::from_str(&read_file(Path::new(&filename)))
                        .unwrap();
                    _pks.push(_pk);
                }
                let _ct = schemes::aw11::encrypt(&_gp, &_pks, &_policy, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
            } 
            Scheme::BDABE => {
                let _pk: BdabePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let mut _attr_vec: Vec<BdabePublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let _pk: BdabePublicAttributeKey =
                        serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    _attr_vec.push(_pk);
                }
                let _ct = schemes::bdabe::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
            } 
            Scheme::MKE08 => {
                let _pk: Mke08PublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let mut _attr_vec: Vec<Mke08PublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let _pk: Mke08PublicAttributeKey =
                        serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    _attr_vec.push(_pk);
                }
                let _ct = schemes::mke08::encrypt(&_pk, &_attr_vec, &_policy, &buffer);
                write_file(
                    Path::new(&_ct_file),
                    serde_json::to_string_pretty(&_ct).unwrap(),
                );
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
                let _sk: Ac17CpSecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: Ac17CpCiphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::ac17::cp_decrypt(&_sk, &_ct);
            }
            Scheme::AC17KP => {
                let _sk: Ac17KpSecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: Ac17KpCiphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::ac17::kp_decrypt(&_sk, &_ct);
            }
            Scheme::BSW => {
                let _sk: CpAbeSecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: CpAbeCiphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::bsw::decrypt(&_sk, &_ct);
            }
            Scheme::LSW => {
                let _sk: KpAbeSecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: KpAbeCiphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::lsw::decrypt(&_sk, &_ct);
            }
            Scheme::AW11 => {
                let _gp: Aw11GlobalKey = serde_json::from_str(&read_file(Path::new(&_gp_file)))
                    .unwrap();
                let _sk: Aw11SecretKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: Aw11Ciphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::aw11::decrypt(&_gp, &_sk, &_ct);
            } 
            Scheme::BDABE => {
                let _pk: BdabePublicKey = serde_json::from_str(&read_file(Path::new(&_pk_file)))
                    .unwrap();
                let _sk: BdabeUserKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: BdabeCiphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
                _pt_option = schemes::bdabe::decrypt(&_pk, &_sk, &_ct);
            } 
            Scheme::MKE08 => {
                let _pk: Mke08PublicKey = serde_json::from_str(&read_file(Path::new(&_gp_file)))
                    .unwrap();
                let _sk: Mke08UserKey = serde_json::from_str(&read_file(Path::new(&_sk_file)))
                    .unwrap();
                let _ct: Mke08Ciphertext = serde_json::from_str(&read_file(Path::new(&_file)))
                    .unwrap();
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
            Err(why) => panic!("couldn't open {}: {}", display, why.to_string()),
            Ok(file) => file,
        };
        // Read the file contents into a string, returns `io::Result<usize>`
        let mut s = String::new();
        match file.read_to_string(&mut s) {
            Err(why) => panic!("couldn't read {}: {}", display, why.to_string()),
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
            Err(why) => panic!("couldn't open {}: {}", display, why.to_string()),
            Ok(file) => file,
        };
        // read the whole file
        match file.read_to_end(&mut data) {
            Ok(_r) => data,
            Err(e) => panic!("could not read file {:?} because {:?}", _path.to_str(), e.to_string())
        }
    }

    fn write_from_vec(_path: &Path, _data: &Vec<u8>) {
        let display = _path.display();
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(_path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", display, why.to_string()),
            Ok(file) => file,
        };
        match file.write_all(_data) {
            Err(why) => panic!("couldn't write to {}: {}", display, why.to_string()),
            Ok(_) => println!("successfully wrote to {}", display),
        }
    }

    fn write_file(_path: &Path, _content: String) -> bool {
        let display = _path.display();

        // Open a file in write-only mode, returns `io::Result<File>`
        let mut file = match File::create(_path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.to_string()),
            Ok(file) => file,
        };
        let mut _ret: bool = false;
        // Write the `LOREM_IPSUM` string to `file`, returns `io::Result<()>`
        match file.write_all(_content.as_bytes()) {
            Err(why) => {
                _ret = false;
                panic!("couldn't write to {}: {}", display, why.to_string());
            }
            Ok(_) => {
                _ret = true;
                println!("successfully wrote to {}", display);
            }
        }
        return _ret;
    }
}
