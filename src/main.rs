mod args;
mod network;
mod utils;

use std::net::IpAddr;
use std::process;
use std::thread;
use std::sync::Arc;

use ipnetwork::NetworkSize;
use pnet::datalink;
use rand::prelude::*;

use args::{ScanOptions, OutputFormat};

fn main() {

    let matches = args::build_args().get_matches();

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

    let scan_options = ScanOptions::new(&matches);
    
    if !utils::is_root_user() {
        eprintln!("Should run this binary as root");
        process::exit(1);
    }

    let selected_interface: &datalink::NetworkInterface = interfaces.iter()
        .find(|interface| { interface.name == scan_options.interface_name && interface.is_up() && !interface.is_loopback() })
        .unwrap_or_else(|| {
            eprintln!("Could not find interface with name {}", scan_options.interface_name);
            process::exit(1);
        });

    let ip_network = match selected_interface.ips.first() {
        Some(ip_network) if ip_network.is_ipv4() => ip_network,
        Some(_) => {
            eprintln!("Only IPv4 networks supported");
            process::exit(1);
        },
        None => {
            eprintln!("Expects a valid IP on the interface, none found");
            process::exit(1);
        }
    };

    if scan_options.is_plain_output() {

        println!("");
        println!("Selected interface {} with IP {}", selected_interface.name, ip_network);
        if let Some(forced_source_ipv4) = scan_options.source_ipv4 {
            println!("The ARP source IPv4 will be forced to {}", forced_source_ipv4);
        }
        if let Some(forced_destination_mac) = scan_options.destination_mac {
            println!("The ARP destination MAC will be forced to {}", forced_destination_mac);
        }
    }

    // Start ARP scan operation
    // ------------------------
    // ARP responses on the interface will be collected in a separate thread,
    // while the main thread sends a batch of ARP requests for each IP in the
    // local network.

    let (mut tx, mut rx) = match datalink::channel(selected_interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Expected an Ethernet datalink channel");
            process::exit(1);
        },
        Err(error) => {
            eprintln!("Datalink channel creation failed ({})", error);
            process::exit(1);
        }
    };

    let cloned_options = Arc::clone(&scan_options);
    let arp_responses = thread::spawn(move || network::receive_arp_responses(&mut rx, cloned_options));

    let network_size: u128 = match ip_network.size() {
        NetworkSize::V4(ipv4_network_size) => ipv4_network_size.into(),
        NetworkSize::V6(_) => {
            eprintln!("IPv6 networks are not supported by the ARP protocol");
            process::exit(1);
        }
    };

    if scan_options.is_plain_output() {
        println!("Sending {} ARP requests to network (waiting at least {}s)", network_size, scan_options.timeout_seconds);
    }

    // The retry count does right now use a 'brute-force' strategy without
    // synchronization process with the already known hosts.
    for _ in 0..scan_options.retry_count {

        // The random approach has one major drawback, compared with the native
        // network iterator exposed by 'ipnetwork': memory usage. Instead of
        // using a small memory footprint iterator, we have to store all IP
        // addresses in memory at once. This can cause problems on large ranges.
        let ip_addresses: Vec<IpAddr> = match scan_options.randomize_targets {
            true => {
                let mut rng = rand::thread_rng();
                let mut shuffled_addresses: Vec<IpAddr> = ip_network.iter().collect();
                shuffled_addresses.shuffle(&mut rng);
                shuffled_addresses
            },
            false => ip_network.iter().collect()
        };

        for ip_address in ip_addresses {

            if let IpAddr::V4(ipv4_address) = ip_address {
                network::send_arp_request(&mut tx, selected_interface, &ip_network, ipv4_address, Arc::clone(&scan_options));
            }
        }
    }

    let (response_summary, target_details) = arp_responses.join().unwrap_or_else(|error| {
        eprintln!("Failed to close receive thread ({:?})", error);
        process::exit(1);
    });

    match &scan_options.output {
        OutputFormat::Plain => utils::display_scan_results(response_summary, target_details, &scan_options),
        OutputFormat::Json => println!("{}", utils::export_to_json(response_summary, target_details))
    }
}
