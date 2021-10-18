use std::process;

use pnet::datalink::NetworkInterface;
use ipnetwork::{IpNetwork, NetworkSize};
use serde::Serialize;
use ansi_term::Color::{Green, Red};

use crate::network::{ResponseSummary, TargetDetails};
use crate::args::ScanOptions;

/**
 * Based on the current UNIX environment, find if the process is run as root
 * user. This approach only supports Linux-like systems (Ubuntu, Fedore, ...).
 */
pub fn is_root_user() -> bool {
    std::env::var("USER").unwrap_or_else(|_| String::from("")) == *"root"
}

/**
 * Prints on stdout a list of all available network interfaces with some
 * technical details. The goal is to present the most useful technical details
 * to pick the right network interface for scans.
 */
pub fn show_interfaces(interfaces: &[NetworkInterface]) {

    let mut interface_count = 0;
    let mut ready_count = 0;

    println!();
    for interface in interfaces.iter() {

        let up_text = match interface.is_up() {
            true => format!("{} UP", Green.paint("✔")),
            false => format!("{} DOWN", Red.paint("✖"))
        };
        let mac_text = match interface.mac {
            Some(mac_address) => format!("{}", mac_address),
            None => "No MAC address".to_string()
        };
        let first_ip = match interface.ips.get(0) {
            Some(ip_address) => format!("{}", ip_address),
            None => "".to_string()
        };

        println!("{: <20} {: <18} {: <20} {}", interface.name, up_text, mac_text, first_ip);

        interface_count += 1;
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            ready_count += 1;
        }
    }

    println!();
    println!("Found {} network interfaces, {} seems ready for ARP scans", interface_count, ready_count);
    if let Some(default_interface) = select_default_interface(interfaces) {
        println!("Default network interface will be {}", default_interface.name);
    }
    println!();
}

/**
 * Find a default network interface for scans, based on the operating system
 * priority and some interface technical details.
 */
pub fn select_default_interface(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {

    let default_interface = interfaces.iter().find(|interface| {

        if interface.mac.is_none() {
            return false;
        }

        if interface.ips.is_empty() || !interface.is_up() || interface.is_loopback() {
            return false;
        }

        let potential_ipv4 = interface.ips.iter().find(|ip| ip.is_ipv4());
        if potential_ipv4.is_none() {
            return false;
        }

        true
    });

    default_interface.cloned()
}

pub fn compute_network_size(ip_network: &IpNetwork) -> u128 {

    match ip_network.size() {
        NetworkSize::V4(ipv4_network_size) => ipv4_network_size.into(),
        NetworkSize::V6(_) => {
            eprintln!("IPv6 networks are not supported by the ARP protocol");
            process::exit(1);
        }
    }
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(response_summary: ResponseSummary, mut target_details: Vec<TargetDetails>, options: &ScanOptions) {

    target_details.sort_by_key(|item| item.ipv4);

    let mut hostname_len = 15;
    let mut vendor_len = 15;
    for detail in target_details.iter() {

        if let Some(hostname) = &detail.hostname {
            if hostname.len() > hostname_len {
                hostname_len = hostname.len();
            }
        }

        if let Some(vendor) = &detail.vendor {
            if vendor.len() > vendor_len {
                vendor_len = vendor.len();
            }
        }
    }

    println!();
    println!("| IPv4            | MAC               | {: <h_max$} | {: <v_max$} |", "Hostname", "Vendor", h_max=hostname_len, v_max=vendor_len);
    println!("|-----------------|-------------------|-{:-<h_max$}-|-{:-<v_max$}-|", "", "", h_max=hostname_len, v_max=vendor_len);

    for detail in target_details.iter() {

        let hostname: &str = match &detail.hostname {
            Some(hostname) => &hostname,
            None if !options.resolve_hostname => &"(disabled)",
            None => &""
        };
        let vendor: &str = match &detail.vendor {
            Some(vendor) => &vendor,
            None => &""
        };
        println!("| {: <15} | {: <18} | {: <h_max$} | {: <v_max$} |", detail.ipv4, detail.mac, hostname, vendor, h_max=hostname_len, v_max=vendor_len);
    }

    println!();
    print!("ARP scan finished, ");
    let target_count = target_details.len();
    match target_count {
        0 => print!("no hosts found"),
        1 => print!("1 host found"),
        _ => print!("{} hosts found", target_count)
    }
    let seconds_duration = (response_summary.duration_ms as f32) / (1000_f32);
    println!(" in {:.3} seconds", seconds_duration);

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
    println!();
}

#[derive(Serialize)]
struct SerializableResultItem {
    ipv4: String,
    mac: String,
    hostname: String,
    vendor: String
}

#[derive(Serialize)]
struct SerializableGlobalResult {
    packet_count: usize,
    arp_count: usize,
    duration_ms: u128,
    results: Vec<SerializableResultItem>
}

fn get_serializable_result(response_summary: ResponseSummary, target_details: Vec<TargetDetails>) -> SerializableGlobalResult {

    let exportable_results: Vec<SerializableResultItem> = target_details.into_iter()
        .map(|detail| {

            let hostname = match &detail.hostname {
                Some(hostname) => hostname.clone(),
                None => String::from("")
            };

            let vendor = match &detail.vendor {
                Some(vendor) => vendor.clone(),
                None => String::from("")
            };

            SerializableResultItem {
                ipv4: format!("{}", detail.ipv4),
                mac: format!("{}", detail.mac),
                hostname,
                vendor
            }
        })
        .collect();

    SerializableGlobalResult {
        packet_count: response_summary.packet_count,
        arp_count: response_summary.arp_count,
        duration_ms: response_summary.duration_ms,
        results: exportable_results
    }
}

/**
 * Export the scan results as a JSON string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_json(response_summary: ResponseSummary, mut target_details: Vec<TargetDetails>) -> String {

    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_json::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export JSON results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a YAML string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_yaml(response_summary: ResponseSummary, mut target_details: Vec<TargetDetails>) -> String {

    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_yaml::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export YAML results ({})", err);
        process::exit(1);
    })
}
