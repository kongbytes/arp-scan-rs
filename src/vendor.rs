use std::fs::File;
use std::process;

use pnet::datalink::MacAddr;
use csv::{Position, Reader};

pub struct Vendor {
    reader: Option<Reader<File>>
}

impl Vendor {

    pub fn new() -> Self {

        let file_result = File::open("/usr/share/arp-scan/ieee-oui.csv");
        
        match file_result {
            Ok(file) => Vendor { reader: Some(Reader::from_reader(file)) },
            Err(_) => Vendor { reader: None }
        }
    }

    pub fn has_vendor_db(&self) -> bool {
        self.reader.is_some()
    }

    pub fn search_by_mac(&mut self, mac_address: &MacAddr) -> Option<String> {

        match &mut self.reader {
            Some(reader) => {

                let vendor_oui = format!("{:X}{:X}{:X}", mac_address.0, mac_address.1, mac_address.2);

                // Since we share a common instance of the CSV reader, it must be reset
                // before each read (internal buffers will be cleared).
                reader.seek(Position::new()).unwrap_or_else(|err| {
                    eprintln!("Could not reset the CSV reader ({})", err);
                    process::exit(1);
                });

                for vendor_result in reader.records() {
            
                    let record = vendor_result.unwrap_or_else(|err| {
                        eprintln!("Could not read CSV record ({})", err);
                        process::exit(1);
                    });
                    let potential_oui = record.get(1).unwrap_or(&"");
            
                    if vendor_oui.eq(potential_oui) {
                        return Some(record.get(2).unwrap_or(&"(no vendor)").to_string())
                    }
                }

                None
            }
            None => None
        }
    }
    
}
