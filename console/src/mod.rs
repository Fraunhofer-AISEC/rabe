//! a rabe console application.
//!
//! * Developped by Georg Bramm, Fraunhofer AISEC
//! * Date: 02/2021
//!
extern crate base64;
extern crate blake2_rfc;
extern crate rand;
extern crate serde;
extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde_json;
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate serde_cbor;

use base64::{decode, encode};
use clap::{App, Arg, ArgMatches, SubCommand};
use crate::rabe::{
    RabeError,
    schemes::{
        ac17,
        aw11,
        bdabe,
        bsw,
        lsw,
        mke08,
        yct14
    },
    utils::{
        policy::pest::PolicyLanguage,
        file::{write_file, read_file, read_raw, write_from_vec, read_to_vec}
    }
};
use serde::Serialize;
use serde_cbor::{
    from_slice,
    ser::to_vec_packed
};
use std::{
    process,
    path::Path
};

// File extensions
const CT_EXTENSION: &'static str = "ct";
const KEY_EXTENSION: &'static str = "key";
const KEY_DELEGATE_EXTENSION: &'static str = "del";
const DOT: &'static str = ".";

// Object names
const ATTRIBUTES: &'static str = "attribute";
const POLICY: &'static str = "policy";
const NAME: &'static str = "name";
const SCHEME: &'static str = "scheme";
const JSON: &'static str = "json";
const LANG: &'static str = "lang";
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
            MKE08,
            YCT14
        }
    }
    arg_enum! {
        #[derive(Debug)]
        enum Lang {
            Human,
            Json,
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
        .arg(
            Arg::with_name(LANG)
                .long(LANG)
                .required(false)
                .takes_value(true)
                .possible_values(&Lang::variants())
                .help("policy language to use."),
        )
        .subcommand(
            // Setup
            SubCommand::with_name(CMD_SETUP)
                .about("sets up a new scheme, creates the msk and pk or gp.")
                .arg(
                    Arg::with_name(MSK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(GP_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("attributes to use."),
                ),
        )
        .subcommand(
            // Authgen
            SubCommand::with_name(CMD_AUTHGEN)
                .about("creates a new authority using attribute(s) or a policy.")
                .arg(
                    Arg::with_name(GP_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(MSK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
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
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(MSK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("authrotiy secret key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
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
                        .help("id of the user (AW11)"),
                ),
        )
        .subcommand(
            // Delegate
            SubCommand::with_name(CMD_DELEGATE)
                .about("delegates attributes to a new subkey (cp-schemes)")
                .arg(
                    Arg::with_name(SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
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
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .default_value(&_pk_default)
                        .help("public key file(s)."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .required(false)
                        .takes_value(true)
                        .multiple(true)
                        .help("the attribute(s) to use."),
                )
                .arg(
                    Arg::with_name(POLICY)
                        .required(false)
                        .takes_value(true)
                        .help("the policy to use."),
                )
                .arg(
                    Arg::with_name(FILE)
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
                        .required(false)
                        .takes_value(true)
                        .default_value(&_gp_default)
                        .help("global parameters file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(FILE)
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
                        .required(true)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file of the system."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("secret key file of authority."),
                )
                .arg(
                    Arg::with_name(PKA_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pka_default)
                        .help("public attribute key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
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
                        .required(true)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
                .arg(
                    Arg::with_name(SKA_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_ska_default)
                        .help("secret attribute key file."),
                )
                .arg(
                    Arg::with_name(AU_SK_FILE)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_au_sk_default)
                        .help("secret attribute authority key file."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
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

    fn run(argument_matches: ArgMatches) -> Result<(), RabeError> {
        if let Some(_s) = argument_matches.value_of(SCHEME) {
            let _scheme = match _s {
                "AC17CP" => Scheme::AC17CP,
                "AC17KP" => Scheme::AC17KP,
                "AW11" => Scheme::AW11,
                "BDABE" => Scheme::BDABE,
                "BSW" => Scheme::BSW,
                "LSW" => Scheme::LSW,
                "MKE08" => Scheme::MKE08,
                "YCT14" => Scheme::YCT14,
                _ => Scheme::BSW // this should not happen at all
            };
            let mut _lang;
            if let Some(_l) = argument_matches.value_of(LANG) {
                _lang = match _l {
                    "json" => PolicyLanguage::JsonPolicy,
                    _ => PolicyLanguage::HumanPolicy,
                };
            } else {
                _lang = PolicyLanguage::HumanPolicy;
            }
            let _json: bool = argument_matches.is_present(JSON);
            match argument_matches.subcommand() {
                (CMD_SETUP, Some(arguments)) => run_setup(arguments, _scheme, _json),
                (CMD_AUTHGEN, Some(arguments)) => run_authgen(arguments, _scheme, _lang, _json),
                (CMD_KEYGEN, Some(arguments)) => run_keygen(arguments, _scheme, _lang, _json),
                (CMD_DELEGATE, Some(arguments)) => run_delegate(arguments, _scheme, _lang, _json),
                (CMD_ENCRYPT, Some(arguments)) => run_encrypt(arguments, _scheme, _lang, _json),
                (CMD_DECRYPT, Some(arguments)) => run_decrypt(arguments, _scheme, _lang, _json),
                (CMD_REQ_ATTR_PK, Some(arguments)) => run_req_attr_pk(arguments, _scheme, _lang, _json),
                (CMD_REQ_ATTR_SK, Some(arguments)) => run_req_attr_sk(arguments, _scheme, _lang, _json),
                _ => Ok(()),
            }
        } else {
            println!("Application error: Scheme missing");
            process::exit(1);
        }
    }

    fn run_setup(arguments: &ArgMatches, _scheme: Scheme, _json: bool) -> Result<(), RabeError> {
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
                let (_pk, _msk) = ac17::setup();
                if _json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_msk, MSK_BEGIN, MSK_END)
                    );
                    write_file(
                        Path::new(&_pk_file),
                        ser_enc(_pk, PK_BEGIN, PK_END)
                    );
                }
            }
            Scheme::AW11 => {
                let _gp = aw11::setup();
                if _json {
                    write_file(
                        Path::new(&_gp_file),
                        serde_json::to_string_pretty(&_gp).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_gp, GP_BEGIN, GP_END)
                    );
                }
            }
            Scheme::BDABE => {
                let (_pk, _msk) = bdabe::setup();
                if _json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_msk, MSK_BEGIN, MSK_END)
                    );
                    write_file(
                        Path::new(&_pk_file),
                        ser_enc(_pk, PK_BEGIN, PK_END)
                    );
                }
            }
            Scheme::BSW => {
                let (_pk, _msk) = bsw::setup();
                if _json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_msk, MSK_BEGIN, MSK_END)
                    );
                    write_file(
                        Path::new(&_pk_file),
                        ser_enc(_pk, PK_BEGIN, PK_END)
                    );
                }
            }
            Scheme::LSW => {
                let (_pk, _msk) = lsw::setup();
                if _json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_msk, MSK_BEGIN, MSK_END)
                    );
                    write_file(
                        Path::new(&_pk_file),
                        ser_enc(_pk, PK_BEGIN, PK_END)
                    );
                }
            }
            Scheme::MKE08 => {
                let (_pk, _msk) = mke08::setup();
                if _json {
                    write_file(
                        Path::new(&_msk_file),
                        serde_json::to_string_pretty(&_msk).unwrap(),
                    );
                    write_file(
                        Path::new(&_pk_file),
                        serde_json::to_string_pretty(&_pk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_msk_file),
                        ser_enc(_msk, MSK_BEGIN, MSK_END)
                    );
                    write_file(
                        Path::new(&_pk_file),
                        ser_enc(_pk, PK_BEGIN, PK_END)
                    );
                }
            },
            Scheme::YCT14 => {
                let mut _attributes: Vec<String> = Vec::new();
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
                if _attributes.len() > 0 {
                    let (_pk, _msk) = yct14::setup(_attributes);
                    if _json {
                        write_file(
                            Path::new(&_msk_file),
                            serde_json::to_string_pretty(&_msk).unwrap(),
                        );
                        write_file(
                            Path::new(&_pk_file),
                            serde_json::to_string_pretty(&_pk).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_msk_file),
                            ser_enc(_msk, MSK_BEGIN, MSK_END)
                        );
                        write_file(
                            Path::new(&_pk_file),
                            ser_enc(_pk, PK_BEGIN, PK_END)
                        );
                    }
                }
                else {
                    return Err(RabeError::new("sorry, yct14 needs attributes at setup()"));
                }
            }
        }
        Ok(())
    }

    fn run_authgen(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
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
            Scheme::AW11 => {
                let mut _gp: aw11::Aw11GlobalKey;
                if _json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
                    _gp = match ser_dec(&_gp_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                match aw11::authgen(&_gp, &_attributes) {
                    None => {
                        return Err(RabeError::new(
                            "sorry, could not generate authority. The attribute set empty.",
                        ));
                    }
                    Some((_pk, _msk)) => {
                        if _json {
                            write_file(
                                Path::new(&_msk_file),
                                serde_json::to_string_pretty(&_msk).unwrap(),
                            );
                            write_file(
                                Path::new(&_pk_file),
                                serde_json::to_string_pretty(&_pk).unwrap(),
                            );
                        } else {
                            write_file(
                                Path::new(&_msk_file),
                                ser_enc(_msk, AU_SK_BEGIN, AU_SK_END)
                            );
                            write_file(
                                Path::new(&_pk_file),
                                ser_enc(_pk, AU_PK_BEGIN, AU_PK_END)
                            );
                        }
                    }
                }
            }
            Scheme::BDABE => {
                let mut _pk: bdabe::BdabePublicKey;
                let mut _msk: bdabe::BdabeMasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: bdabe::BdabeSecretAuthorityKey =
                    bdabe::authgen(&_pk, &_msk, &_name);
                if _json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_au_file),
                        ser_enc(_sk, AU_SK_BEGIN, AU_SK_END)
                    );
                }
            }
            Scheme::MKE08 => {
                let mut _pk: mke08::Mke08PublicKey;
                let mut _msk: mke08::Mke08MasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: mke08::Mke08SecretAuthorityKey = mke08::authgen(&_name);
                if _json {
                    write_file(
                        Path::new(&_au_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_au_file),
                        ser_enc(_sk, AU_SK_BEGIN, AU_SK_END)
                    );
                }
            },
            _ => {
                return Err(RabeError::new("sorry, this is not a multi-authoriy scheme"));
            }
        }
        Ok(())
    }

    fn run_keygen(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
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
                let mut _msk: ac17::Ac17MasterKey;
                if _json {
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: ac17::Ac17CpSecretKey = ac17::cp_keygen(&_msk, &_attributes)
                    .unwrap();
                if _json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_sk_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::AC17KP => {
                let mut _msk: ac17::Ac17MasterKey;
                if _json {
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: ac17::Ac17KpSecretKey = ac17::kp_keygen(&_msk, &_policy, _lang).unwrap();
                if _json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_sk_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::BSW => {
                let mut _pk: bsw::CpAbePublicKey;
                let mut _msk: bsw::CpAbeMasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: bsw::CpAbeSecretKey = bsw::keygen(&_pk, &_msk, &_attributes)
                    .unwrap();
                if _json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_sk_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::LSW => {
                let mut _pk: lsw::KpAbePublicKey;
                let mut _msk: lsw::KpAbeMasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: lsw::KpAbeSecretKey = lsw::keygen(&_pk, &_msk, &_policy, _lang).unwrap();
                if _json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_sk_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::AW11 => {
                let mut _pk: aw11::Aw11GlobalKey;
                let mut _msk: aw11::Aw11MasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_gp_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: aw11::Aw11SecretKey =
                    aw11::keygen(&_pk, &_msk, &_name, &_attributes).unwrap();
                if _json {
                    write_file(
                        Path::new(&_name_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_name_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::BDABE => {
                let mut _pk: bdabe::BdabePublicKey;
                let mut _msk: bdabe::BdabeSecretAuthorityKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_ska_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_ska_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: bdabe::BdabeUserKey = bdabe::keygen(&_pk, &_msk, &_name);
                if _json {
                    write_file(
                        Path::new(&_name_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_name_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
            Scheme::MKE08 => {
                let mut _pk: mke08::Mke08PublicKey;
                let mut _msk: mke08::Mke08MasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                if _name != String::from("") {
                    let _sk: mke08::Mke08UserKey = mke08::keygen(&_pk, &_msk, &_name);
                    if _json {
                        write_file(
                            Path::new(&_name_file),
                            serde_json::to_string_pretty(&_sk).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_name_file),
                            ser_enc(_sk, SK_BEGIN, SK_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, the name/id for the user key is not set.",
                    ));
                }
            }
            Scheme::YCT14 => {
                let mut _pk: yct14::Yct14AbePublicKey;
                let mut _msk: yct14::Yct14AbeMasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: yct14::Yct14AbeSecretKey = yct14::keygen(&_pk, &_msk, &_policy, _lang).unwrap();
                if _json {
                    write_file(
                        Path::new(&_sk_file),
                        serde_json::to_string_pretty(&_sk).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_sk_file),
                        ser_enc(_sk, SK_BEGIN, SK_END)
                    );
                }
            }
        }
        Ok(())
    }

    fn run_delegate(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
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
            Scheme::BSW => {
                let mut _pk: bsw::CpAbePublicKey;
                let mut _msk: bsw::CpAbeSecretKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let _sk: Option<bsw::CpAbeSecretKey> =
                    bsw::delegate(&_pk, &_msk, &_attributes);
                match _sk {
                    None => {
                        return Err(RabeError::new(
                            "sorry, could not delegate attributes. The given attributes are not a subset.",
                        ));
                    }
                    Some(_del) => {
                        if _json {
                            write_file(
                                Path::new(&_dg_file),
                                serde_json::to_string_pretty(&_del).unwrap(),
                            );
                        } else {
                            write_file(
                                Path::new(&_dg_file),
                                ser_enc(_del, SK_BEGIN, SK_END)
                            );
                        }
                    }
                }
            }
            _ => {
                return Err(RabeError::new(
                    "sorry, this scheme does not support the delegation algorithm.",
                ));
            }
        }
        Ok(())
    }

    fn run_encrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
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
                let mut _pk: ac17::Ac17PublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    _pk_file = _pk_files[0].clone();
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    let _ct = ac17::cp_encrypt(&_pk, &_policy, &buffer, _lang);
                    if _json {
                        write_file(
                            Path::new(&_ct_file),
                            serde_json::to_string_pretty(&_ct).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_ct_file),
                            ser_enc(_ct, CT_BEGIN, CT_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the AC17CP Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::AC17KP => {
                let mut _pk: ac17::Ac17PublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    _pk_file = _pk_files[0].clone();
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    let _ct = ac17::kp_encrypt(&_pk, &_attributes, &buffer);
                    if _json {
                        write_file(
                            Path::new(&_ct_file),
                            serde_json::to_string_pretty(&_ct).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_ct_file),
                            ser_enc(_ct, CT_BEGIN, CT_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the AC17KP Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::BSW => {
                let mut _pk: bsw::CpAbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_files[0].clone()) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    let _ct = bsw::encrypt(&_pk, &_policy, &buffer, _lang);
                    if _json {
                        write_file(
                            Path::new(&_ct_file),
                            serde_json::to_string_pretty(&_ct).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_ct_file),
                            ser_enc(_ct, CT_BEGIN, CT_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the BSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::LSW => {
                let mut _pk: lsw::KpAbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_files[0].clone()) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    let _ct = lsw::encrypt(&_pk, &_attributes, &buffer);
                    if _json {
                        write_file(
                            Path::new(&_ct_file),
                            serde_json::to_string_pretty(&_ct).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_ct_file),
                            ser_enc(_ct, CT_BEGIN, CT_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the LSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
            Scheme::AW11 => {
                let mut _gp: aw11::Aw11GlobalKey;
                if _json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                } else {
                    _gp = match ser_dec(&_gp_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let mut _pks: Vec<aw11::Aw11PublicKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: aw11::Aw11PublicKey;
                    if _json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = match ser_dec(&filename) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    _pks.push(_pka);
                }
                let _ct = aw11::encrypt(&_gp, &_pks, &_policy, _lang, &buffer);
                if _json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_ct_file),
                        ser_enc(_ct, CT_BEGIN, CT_END)
                    );
                }
            }
            Scheme::BDABE => {
                let mut _pk: bdabe::BdabePublicKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let mut _attr_vec: Vec<bdabe::BdabePublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: bdabe::BdabePublicAttributeKey;
                    if _json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = match ser_dec(&filename) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    _attr_vec.push(_pka);
                }
                let _ct = bdabe::encrypt(&_pk, &_attr_vec, &_policy, &buffer, _lang);
                if _json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_ct_file),
                        ser_enc(_ct, CT_BEGIN, CT_END)
                    );
                }
            }
            Scheme::MKE08 => {
                let mut _pk: mke08::Mke08PublicKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                let mut _attr_vec: Vec<mke08::Mke08PublicAttributeKey> = Vec::new();
                for filename in _pk_files {
                    let mut _pka: mke08::Mke08PublicAttributeKey;
                    if _json {
                        _pka = serde_json::from_str(&read_file(Path::new(&filename))).unwrap();
                    } else {
                        _pka = match ser_dec(&filename) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    _attr_vec.push(_pka);
                }
                let _ct = mke08::encrypt(&_pk, &_attr_vec, &_policy, _lang, &buffer);
                if _json {
                    write_file(
                        Path::new(&_ct_file),
                        serde_json::to_string_pretty(&_ct).unwrap(),
                    );
                } else {
                    write_file(
                        Path::new(&_ct_file),
                        ser_enc(_ct, CT_BEGIN, CT_END)
                    );
                }
            }
            Scheme::YCT14 => {
                let mut _pk: yct14::Yct14AbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_files[0].clone()) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    let _ct = yct14::encrypt(&_pk, &_attributes, &buffer);
                    if _json {
                        write_file(
                            Path::new(&_ct_file),
                            serde_json::to_string_pretty(&_ct).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_ct_file),
                            ser_enc(_ct, CT_BEGIN, CT_END)
                        );
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the LSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
        }
        Ok(())
    }

    fn run_decrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _file: String = String::from("");
        let mut _pt_option: Result<Vec<u8>, RabeError>;
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
                let mut _sk: ac17::Ac17CpSecretKey;
                let mut _ct: ac17::Ac17CpCiphertext;
                if _json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = ac17::cp_decrypt(&_sk, &_ct);
            }
            Scheme::AC17KP => {
                let mut _sk: ac17::Ac17KpSecretKey;
                let mut _ct: ac17::Ac17KpCiphertext;
                if _json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = ac17::kp_decrypt(&_sk, &_ct);
            }
            Scheme::BSW => {
                let mut _sk: bsw::CpAbeSecretKey;
                let mut _ct: bsw::CpAbeCiphertext;
                if _json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = bsw::decrypt(&_sk, &_ct);
            }
            Scheme::LSW => {
                let mut _sk: lsw::KpAbeSecretKey;
                let mut _ct: lsw::KpAbeCiphertext;
                if _json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = lsw::decrypt(&_sk, &_ct);
            }
            Scheme::AW11 => {
                let mut _gp: aw11::Aw11GlobalKey;
                let mut _sk: aw11::Aw11SecretKey;
                let mut _ct: aw11::Aw11Ciphertext;
                if _json {
                    _gp = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _gp = match ser_dec(&_gp_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = aw11::decrypt(&_gp, &_sk, &_ct);
            }
            Scheme::BDABE => {
                let mut _pk: bdabe::BdabePublicKey;
                let mut _sk: bdabe::BdabeUserKey;
                let mut _ct: bdabe::BdabeCiphertext;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = bdabe::decrypt(&_pk, &_sk, &_ct);
            }
            Scheme::MKE08 => {
                let mut _pk: mke08::Mke08PublicKey;
                let mut _sk: mke08::Mke08UserKey;
                let mut _ct: mke08::Mke08Ciphertext;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_gp_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_gp_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = mke08::decrypt(&_pk, &_sk, &_ct);
            }
            Scheme::YCT14 => {
                let mut _sk: yct14::Yct14AbeSecretKey;
                let mut _ct: yct14::Yct14AbeCiphertext;
                if _json {
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = yct14::decrypt(&_sk, &_ct);
            }
        }
        match _pt_option {
            Err(e) => {
                return Err(e);
            }
            Ok(_pt_u) => {
                write_from_vec(Path::new(&_file), &_pt_u);
            }
        }
        Ok(())
    }

    fn run_req_attr_pk(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
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
                Scheme::MKE08 => {
                    let mut _pk: mke08::Mke08PublicKey;
                    let mut _ska: mke08::Mke08SecretAuthorityKey;
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                        _ska = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                        _ska = match ser_dec(&_au_sk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    match mke08::request_authority_pk(&_pk, &_attributes[0], &_ska) {
                        None => {}
                        Some(_a_pk) => {
                            if _json {
                                write_file(
                                    Path::new(&_pka_file),
                                    serde_json::to_string_pretty(&_a_pk).unwrap(),
                                );
                            } else {
                                write_file(
                                    Path::new(&_pka_file),
                                    ser_enc(_a_pk, PKA_BEGIN, PKA_END)
                                );
                            }
                        }
                    }
                }
                Scheme::BDABE => {
                    let mut _pk: bdabe::BdabePublicKey;
                    let mut _ska: bdabe::BdabeSecretAuthorityKey;
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                        _ska = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                        _ska = match ser_dec(&_au_sk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    match bdabe::request_attribute_pk(&_pk, &_ska, &_attributes[0]) {
                        None => {}
                        Some(_a_pk) => {
                            if _json {
                                write_file(
                                    Path::new(&_pka_file),
                                    serde_json::to_string_pretty(&_a_pk).unwrap(),
                                );
                            } else {
                                write_file(
                                    Path::new(&_pka_file),
                                    ser_enc(_a_pk, PKA_BEGIN, PKA_END)
                                );
                            }
                        }
                    }
                }
                _ => {
                    return Err(RabeError::new(
                        "sorry, this scheme does not support the request attribute PK algorithm.",
                    ));
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
        _lang: PolicyLanguage,
        _json: bool,
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
                Scheme::MKE08 => {
                    let mut _usk: mke08::Mke08UserKey;
                    let mut _ska: mke08::Mke08SecretAttributeKey;
                    let mut _skau: mke08::Mke08SecretAuthorityKey;
                    if _json {
                        _usk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                        _skau = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _usk = match ser_dec(&_sk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                        _skau = match ser_dec(&_au_sk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    match mke08::request_authority_sk(
                        &_attributes[0],
                        &_skau,
                        &_usk._pk_u,
                    ) {
                        None => {}
                        Some(_a_sk) => {
                            if _json {
                                write_file(
                                    Path::new(&_ask_file),
                                    serde_json::to_string_pretty(&_a_sk).unwrap(),
                                );
                            } else {
                                write_file(
                                    Path::new(&_ask_file),
                                    ser_enc(_a_sk, SKA_BEGIN, SKA_END),
                                );
                            }
                        }
                    }
                }
                Scheme::BDABE => {
                    let mut _usk: bdabe::BdabeUserKey;
                    let mut _ska: bdabe::BdabeSecretAttributeKey;
                    let mut _skau: bdabe::BdabeSecretAuthorityKey;
                    if _json {
                        _usk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                        _skau = serde_json::from_str(&read_file(Path::new(&_au_sk_file))).unwrap();
                    } else {
                        _usk = match ser_dec(&_sk_file) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                        _skau = match ser_dec(&_au_sk_file){
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    match bdabe::request_attribute_sk(
                        &_usk._pk,
                        &_skau,
                        &_attributes[0],
                    ) {
                        None => {}
                        Some(_a_sk) => {
                            if _json {
                                write_file(
                                    Path::new(&_ask_file),
                                    serde_json::to_string_pretty(&_a_sk).unwrap(),
                                );
                            } else {
                                write_file(
                                    Path::new(&_ask_file),
                                    ser_enc(_a_sk, SKA_BEGIN, SKA_END)
                                );
                            }
                        }
                    }
                }
                _ => {
                    return Err(RabeError::new(
                        "sorry, this scheme does not support the request attribute SK algorithm.",
                    ));
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

fn ser_enc<T: Serialize>(input: T, head: &str, tail: &str) -> String {
    use deflate::deflate_bytes;
    [
        head,
        &encode(
            &deflate_bytes(
                &to_vec_packed(&input).unwrap()
            )
        ),
        tail
    ].concat()
}
fn ser_dec(file_name: &String) -> Result<Vec<u8>, RabeError> {
    use inflate::inflate_bytes;
    let base64: Vec<u8> = decode(
        &read_raw(
            &read_file(
                Path::new(file_name)
            )
        )
    )?;
    match inflate_bytes(&base64) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(RabeError::new(e.to_string().as_str()))
    }

}