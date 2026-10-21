use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub fn read_file(path: &Path) -> String {
    let display = path.display();
    let mut file = match File::open(path) {
        Err(why) => {
            panic!("sorry, couldn't open {}: {}", path.display(), why)
        }
        Ok(file) => file,
    };
    let mut s = String::new();
    if let Err(why) = file.read_to_string(&mut s) {
        panic!("sorry, couldn't read {}: {}", display, why)
    }
    s
}

pub fn read_to_vec(path: &Path) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let display = path.display();
    let mut file = match File::open(path) {
        Err(why) => panic!("sorry, couldn't open {}: {}", display, why),
        Ok(file) => file,
    };
    match file.read_to_end(&mut data) {
        Ok(bytes) => {
            println!("parsed {:?} bytes", bytes);
            data
        }
        Err(e) => {
            println!("error parsing: {:?}", e);
            Vec::new()
        }
    }
}

pub fn write_from_vec(path: &Path, data: &[u8]) {
    let display = path.display();
    let mut file = match File::open(path) {
        Err(why) => panic!("sorry, couldn't open {}: {}", display, why),
        Ok(file) => file,
    };
    match file.write_all(data) {
        Err(why) => {
            panic!("sorry, couldn't write to {}: {}", display, why)
        }
        Ok(_) => println!("successfully wrote to {}", display),
    }
}

pub fn read_raw(raw: &str) -> String {
    raw.lines().nth(1).unwrap().to_string()
}

pub fn write_file(path: &Path, content: String) -> bool {
    let display = path.display();
    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };
    let mut _ret: bool = false;
    match file.write_all(content.as_bytes()) {
        Err(why) => {
            _ret = false;
            panic!("couldn't write to {}: {}", display, why);
        }
        Ok(_) => {
            _ret = true;
            println!("successfully wrote to {}", display);
        }
    }
    _ret
}
