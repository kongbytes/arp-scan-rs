mod network;
mod utils;

use std::net::{IpAddr};
use std::process;
use std::thread;

use ipnetwork::NetworkSize;
use pnet::datalink;
use clap::{Arg, App};

const FIVE_HOURS: u64 = 5 * 60 * 60; 
const TIMEOUT_DEFAULT: u64 = 5;

fn main() {

    let matches = App::new("arp-scan")
        .version("0.3.0")
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::with_name("interface").short("i").long("interface").takes_value(true).value_name("INTERFACE_NAME").help("Network interface")
        )
        .arg(
            Arg::with_name("timeout").short("t").long("timeout").takes_value(true).value_name("TIMEOUT_SECONDS").help("ARP response timeout")
        )
        .arg(
            Arg::with_name("numeric").short("n").long("numeric").takes_value(false).help("Numeric mode, no hostname resolution")
        )
        .arg(
            Arg::with_name("list").short("l").long("list").takes_value(false).help("List network interfaces")
        )
        .get_matches();

    // Find interfaces & list them if requested
    // ----------------------------------------
    // All network interfaces are retrieved and will be listed if the '--list'
    // flag has been given in the request. Note that this can be done without
    // using a root account (this will be verified later).

    let interfaces = datalink::interfaces();

    if matches.is_present("list") {
        utils::show_interfaces(&interfaces);
        process::exit(0);
    }

    // Assert requirements for a local network scan
    // --------------------------------------------
    // Ensure all requirements are met to perform an ARP scan on the local
    // network for the given interface. ARP scans require an active interface
    // with an IPv4 address and root permissions (for crafting ARP packets).

    let interface_name = match matches.value_of("interface") {
        Some(name) => name,
        None => {
            eprintln!("Network interface name required");
            eprintln!("Use 'arp scan -l' to list available interfaces");
            process::exit(1);
        }
    };

    let timeout_seconds: u64 = match matches.value_of("timeout").map(|seconds| seconds.parse::<u64>()) {
        Some(seconds) => seconds.unwrap_or(TIMEOUT_DEFAULT),
        None => TIMEOUT_DEFAULT
    };

    if timeout_seconds > FIVE_HOURS {
        eprintln!("The timeout exceeds the limit (maximum {} seconds allowed)", FIVE_HOURS);
        process::exit(1);
    }

    // Hostnames will not be resolved in numeric mode
    let resolve_hostname = !matches.is_present("numeric");
    
    if !utils::is_root_user() {
        eprintln!("Should run this binary as root");
        process::exit(1);
    }

    let selected_interface: &datalink::NetworkInterface = interfaces.iter()
        .find(|interface| { interface.name == interface_name && interface.is_up() && !interface.is_loopback() })
        .unwrap_or_else(|| {
            eprintln!("Could not find interface with name {}", interface_name);
            process::exit(1);
        });

    let ip_network = match selected_interface.ips.first() {
        Some(ip_network) => ip_network,
        None => {
            eprintln!("Expects a valid IP on the interface");
            process::exit(1);
        }
    };

    if !ip_network.is_ipv4() {
        eprintln!("Only IPv4 supported");
        process::exit(1);
    }
    
    println!("");
    println!("Selected interface {} with IP {}", selected_interface.name, ip_network);

    // Start ARP scan operation
    // ------------------------
    // ARP responses on the interface will be collected in a separate thread,
    // while the main thread sends a batch of ARP requests for each IP in the
    // local network.

    let (mut tx, mut rx) = match datalink::channel(selected_interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown interface type, expected Ethernet"),
        Err(error) => panic!(error)
    };

    let arp_responses = thread::spawn(move || network::receive_arp_responses(&mut rx, timeout_seconds, resolve_hostname));

    let network_size: u128 = match ip_network.size() {
        NetworkSize::V4(x) => x.into(),
        NetworkSize::V6(y) => y
    };
    println!("Sending {} ARP requests to network ({}s timeout)", network_size, timeout_seconds);

    for ip_address in ip_network.iter() {

        if let IpAddr::V4(ipv4_address) = ip_address {
            network::send_arp_request(&mut tx, selected_interface, ipv4_address);
        }
    }

    let final_result = arp_responses.join().unwrap_or_else(|error| {
        eprintln!("Failed to close receive thread ({:?})", error);
        process::exit(1);
    });

    utils::display_scan_results(final_result, resolve_hostname);
}
