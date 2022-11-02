//! Utility program to parse a legacy encrypted keyblob (but not decrypt it).

use kmr_common::keyblob::legacy::EncryptedKeyBlob;

fn main() {
    let mut hex = false;
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        if arg == "--hex" {
            hex = !hex;
        } else {
            process(arg, hex);
        }
    }
}

fn process(filename: &str, hex: bool) {
    let _ = env_logger::builder().is_test(true).try_init();

    println!("File: {}", filename);
    let mut data: Vec<u8> = std::fs::read(filename).unwrap();
    if hex {
        let hexdata = std::str::from_utf8(&data).unwrap().trim();
        data = match hex::decode(hexdata) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "{}: Failed to parse hex ({:?}): len={} {}",
                    filename,
                    e,
                    hexdata.len(),
                    hexdata
                );
                return;
            }
        };
    }
    let keyblob = match EncryptedKeyBlob::deserialize(&data) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{}: Failed to parse: {:?}", filename, e);
            return;
        }
    };
    println!(
        "{}, KeyBlob  {{\n  nonce={}\n  ciphertext=...(len {}),\n  tag={},\n  hw_enforced={:?},\n  sw_enforced={:?},\n}}",
        filename,
        hex::encode(&keyblob.nonce),
        keyblob.ciphertext.len(),
        hex::encode(&keyblob.tag),
        keyblob.hw_enforced,
        keyblob.sw_enforced
    );

    // Also round-trip the keyblob to binary.
    let regenerated_data = keyblob.serialize().unwrap();
    assert_eq!(regenerated_data, data);
}
