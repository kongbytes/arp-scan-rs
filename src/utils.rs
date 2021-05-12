use std::net::Ipv4Addr;
use std::collections::HashMap;

use pnet::datalink::{MacAddr, NetworkInterface};

pub fn is_root_user() -> bool {
    std::env::var("USER").unwrap_or(String::from("")) == String::from("root")
}

pub fn show_interfaces(interfaces: &Vec<NetworkInterface>) {

    for interface in interfaces.iter() {
        let up_text = match interface.is_up() {
            true => "UP",
            false => "DOWN"
        };
        let mac_text = match interface.mac {
            Some(mac_address) => format!("{}", mac_address),
            None => "No MAC address".to_string()
        };
        println!("{: <12} {: <7} {}", interface.name, up_text, mac_text);
    }
}

pub fn display_scan_results(final_result: HashMap<Ipv4Addr, MacAddr>) {

    let mut sorted_map: Vec<(Ipv4Addr, MacAddr)> = final_result.into_iter().collect();
    sorted_map.sort_by_key(|x| x.0);
    println!("");
    println!("| IPv4            | MAC               |");
    println!("|-----------------|-------------------|");
    for (result_ipv4, result_mac) in sorted_map {
        println!("| {: <15} | {: <18} |", &result_ipv4, &result_mac);
    }
    println!("");
}