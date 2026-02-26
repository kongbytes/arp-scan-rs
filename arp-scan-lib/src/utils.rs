use std::process;
use std::sync::Arc;

use crate::scan_options::ScanOptions;
use ipnetwork::{IpNetwork, NetworkSize};
use pnet_datalink::NetworkInterface;

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

/**
 * Display scan settings before launching an ARP scan. This includes network
 * details (IP range, interface, ...) and timing information.
 */
pub fn display_prescan_details(
    ip_networks: &[&IpNetwork],
    selected_interface: &NetworkInterface,
    scan_options: Arc<ScanOptions>,
) {
    let mut network_list = ip_networks
        .iter()
        .take(5)
        .map(|network| network.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    if ip_networks.len() > 5 {
        let more_text = format!(" ({} more)", ip_networks.len() - 5);
        network_list.push_str(&more_text);
    }

    println!();
    println!(
        "Selected interface {} with IP {}",
        selected_interface.name, network_list
    );
    if let Some(forced_source_ipv4) = scan_options.source_ipv4 {
        println!(
            "The ARP source IPv4 will be forced to {}",
            forced_source_ipv4
        );
    }
    if let Some(forced_destination_mac) = scan_options.destination_mac {
        println!(
            "The ARP destination MAC will be forced to {}",
            forced_destination_mac
        );
    }
}

/**
 * Computes multiple IPv4 networks total size, IPv6 network are not being
 * supported by this function.
 */
pub fn compute_network_size(ip_networks: &[&IpNetwork]) -> u128 {
    ip_networks.iter().fold(0u128, |total_size, ip_network| {
        let network_size: u128 = match ip_network.size() {
            NetworkSize::V4(ipv4_network_size) => ipv4_network_size.into(),
            NetworkSize::V6(_) => {
                eprintln!("IPv6 networks are not supported by the ARP protocol");
                process::exit(1);
            }
        };
        total_size + network_size
    })
}
