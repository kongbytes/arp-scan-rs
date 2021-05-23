use pnet::datalink::{self, NetworkInterface};

use crate::network::{ResponseSummary, TargetDetails};
use crate::args::ScanOptions;

/**
 * Based on the current UNIX environment, find if the process is run as root
 * user. This approach only supports Linux-like systems (Ubuntu, Fedore, ...).
 */
pub fn is_root_user() -> bool {
    std::env::var("USER").unwrap_or(String::from("")) == String::from("root")
}

/**
 * Prints on stdout a list of all available network interfaces with some
 * technical details. The goal is to present the most useful technical details
 * to pick the right network interface for scans.
 */
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
        println!("{: <17} {: <7} {}", interface.name, up_text, mac_text);
    }
}

/**
 * Find a default network interface for scans, based on the operating system
 * priority and some interface technical details.
 */
pub fn select_default_interface() -> Option<NetworkInterface> {

    let interfaces = datalink::interfaces();

    interfaces.into_iter().find(|interface| {

        if let None = interface.mac {
            return false;
        }

        if interface.ips.len() == 0 || !interface.is_up() || interface.is_loopback() {
            return false;
        }

        let potential_ipv4 = interface.ips.iter().find(|ip| ip.is_ipv4());
        if let None = potential_ipv4 {
            return false;
        }

        true
    })
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(response_summary: ResponseSummary, mut target_details: Vec<TargetDetails>, options: &ScanOptions) {

    target_details.sort_by_key(|item| item.ipv4);

    println!("");
    println!("| IPv4            | MAC               | Hostname              |");
    println!("|-----------------|-------------------|-----------------------|");

    for detail in target_details {

        let hostname = match detail.hostname {
            Some(hostname) => hostname,
            None if !options.resolve_hostname => String::from("(disabled)"),
            None => String::from("")
        };
        println!("| {: <15} | {: <18} | {: <21} |", detail.ipv4, detail.mac, hostname);
    }

    println!("");
    match response_summary.packet_count {
        0 => print!("No packets received, "),
        1 => print!("1 packet received, "),
        _ => print!("{} packets received, ", response_summary.packet_count)
    };
    match response_summary.arp_count {
        0 => println!("no ARP packets filtered"),
        1 => println!("1 ARP packet filtered"),
        _ => println!("{} ARP packets filtered", response_summary.arp_count)
    };
    println!("");
}
