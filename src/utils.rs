use pnet::datalink::NetworkInterface;

use crate::network::TargetDetails;

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
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(mut final_result: Vec<TargetDetails>, resolve_hostname: bool) {

    final_result.sort_by_key(|item| item.ipv4);

    println!("");
    println!("| IPv4            | MAC               | Hostname              |");
    println!("|-----------------|-------------------|-----------------------|");

    for result_item in final_result {

        let hostname = match result_item.hostname {
            Some(hostname) => hostname,
            None if !resolve_hostname => String::from("(disabled)"),
            None => String::from("")
        };
        println!("| {: <15} | {: <18} | {: <21} |", result_item.ipv4, result_item.mac, hostname);
    }

    println!("");
}
