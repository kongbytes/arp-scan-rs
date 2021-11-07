mod args;
mod network;
mod time;
mod utils;
mod vendor;

use std::net::IpAddr;
use std::process;
use std::thread;
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};

use pnet::datalink;
use rand::prelude::*;

use crate::args::{ScanOptions, OutputFormat};
use crate::vendor::Vendor;

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

    let (selected_interface, ip_network) = network::compute_network_configuration(&interfaces, &scan_options);

    if scan_options.is_plain_output() {

        println!();
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

    let channel_config = datalink::Config {
        read_timeout: Some(Duration::from_millis(network::DATALINK_RCV_TIMEOUT)), 
        ..datalink::Config::default()
    };

    let (mut tx, mut rx) = match datalink::channel(selected_interface, channel_config) {
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

    // The 'timed_out' mutex is shared accross the main thread (which performs
    // ARP packet sending) and the response thread (which receives and stores
    // all ARP responses).
    let timed_out = Arc::new(AtomicBool::new(false));
    let cloned_timed_out = Arc::clone(&timed_out);

    let mut vendor_list = Vendor::new(&scan_options.oui_file);

    let cloned_options = Arc::clone(&scan_options);
    let arp_responses = thread::spawn(move || network::receive_arp_responses(&mut rx, cloned_options, cloned_timed_out, &mut vendor_list));

    let network_size = utils::compute_network_size(&ip_network);

    if scan_options.is_plain_output() {

        let estimations = network::compute_scan_estimation(network_size, &scan_options);
        let formatted_ms = time::format_milliseconds(estimations.duration_ms);
        println!("Estimated scan time {} ({} bytes, {} bytes/s)", formatted_ms, estimations.request_size, estimations.bandwidth);
        println!("Sending {} ARP requests (waiting at least {}ms, {}ms request interval)", network_size, scan_options.timeout_ms, scan_options.interval_ms);
    }

    let finish_sleep = Arc::new(AtomicBool::new(false));
    let cloned_finish_sleep = Arc::clone(&finish_sleep);

    ctrlc::set_handler(move || {
        eprintln!("[warn] Receiving halt signal, ending scan with partial results");
        cloned_finish_sleep.store(true, Ordering::Relaxed);
    }).unwrap_or_else(|err| {
        eprintln!("Could not set CTRL+C handler ({})", err);
        process::exit(1);
    });

    // The retry count does right now use a 'brute-force' strategy without
    // synchronization process with the already known hosts.
    for _ in 0..scan_options.retry_count {

        if finish_sleep.load(Ordering::Relaxed) {
            break;
        }

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

            if finish_sleep.load(Ordering::Relaxed) {
                break;
            }

            if let IpAddr::V4(ipv4_address) = ip_address {
                network::send_arp_request(&mut tx, selected_interface, &ip_network, ipv4_address, Arc::clone(&scan_options));
                thread::sleep(Duration::from_millis(scan_options.interval_ms));
            }
        }
    }

    // Once the ARP packets are sent, the main thread will sleep for T seconds
    // (where T is the timeout option). After the sleep phase, the response
    // thread will receive a stop request through the 'timed_out' mutex.
    let mut sleep_ms_mount: u64 = 0;
    while !finish_sleep.load(Ordering::Relaxed) && sleep_ms_mount < scan_options.timeout_ms {
        
        thread::sleep(Duration::from_millis(500));
        sleep_ms_mount += 500;
    }
    timed_out.store(true, Ordering::Relaxed);

    let (response_summary, target_details) = arp_responses.join().unwrap_or_else(|error| {
        eprintln!("Failed to close receive thread ({:?})", error);
        process::exit(1);
    });

    match &scan_options.output {
        OutputFormat::Plain => utils::display_scan_results(response_summary, target_details, &scan_options),
        OutputFormat::Json => println!("{}", utils::export_to_json(response_summary, target_details)),
        OutputFormat::Yaml => println!("{}", utils::export_to_yaml(response_summary, target_details))
    }
}
