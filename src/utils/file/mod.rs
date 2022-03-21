use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};

pub fn read_file(_path: &Path) -> String {
    let display = _path.display();
    let mut file = match File::open(_path) {
        Err(why) => {
            panic!(
                "sorry, couldn't open {}: {}",
                _path.display(),
                why.to_string()
            )
        }
        Ok(file) => file,
    };
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("sorry, couldn't read {}: {}", display, why.to_string()),
        Ok(_) => {},
    }
    return s;
}

pub fn read_to_vec(_path: &Path) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let display = _path.display();
    let mut file = match File::open(_path) {
        Err(why) => panic!("sorry, couldn't open {}: {}", display, why.to_string()),
        Ok(file) => file,
    };
    match file.read_to_end(&mut data) {
        Ok(bytes) => {
            println!("parsed {:?} bytes", bytes);
            return data;
        }
        Err(e) => {
            println!("error parsing: {:?}", e);
            return Vec::new();
        }
    }

}

pub fn write_from_vec(_path: &Path, _data: &Vec<u8>) {
    let display = _path.display();
    let mut file = match File::open(_path) {
        Err(why) => panic!("sorry, couldn't open {}: {}", display, why.to_string()),
        Ok(file) => file,
    };
    match file.write_all(_data) {
        Err(why) => {
            panic!(
                "sorry, couldn't write to {}: {}",
                display,
                why.to_string()
            )
        }
        Ok(_) => println!("successfully wrote to {}", display),
    }
}

pub fn read_raw(_raw: &String) -> String {
    let lines = &mut _raw.lines();
    let middle = lines.nth(1).unwrap().to_string();
    return middle;
}

pub fn write_file(_path: &Path, _content: String) -> bool {
    let display = _path.display();
    let mut file = match File::create(_path) {
        Err(why) => panic!("couldn't create {}: {}", display, why.to_string()),
        Ok(file) => file,
    };
    let mut _ret: bool = false;
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
