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

use crate::args::{ScanOptions, OutputFormat};
use crate::network::NetworkIterator;
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
        eprintln!("Should run this binary as root or use --help for options");
        process::exit(1);
    }

    let (selected_interface, ip_networks) = network::compute_network_configuration(&interfaces, &scan_options);

    if scan_options.is_plain_output() {
        utils::display_prescan_details(&ip_networks, selected_interface, scan_options.clone());
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

    let network_size = utils::compute_network_size(&ip_networks);

    let estimations = network::compute_scan_estimation(network_size, &scan_options);
    let interval_ms = estimations.interval_ms;

    if scan_options.is_plain_output() {

        let formatted_ms = time::format_milliseconds(estimations.duration_ms);
        println!("Estimated scan time {} ({} bytes, {} bytes/s)", formatted_ms, estimations.request_size, estimations.bandwidth);
        println!("Sending {} ARP requests (waiting at least {}ms, {}ms request interval)", network_size, scan_options.timeout_ms, interval_ms);
    }

    let has_reached_timeout = Arc::new(AtomicBool::new(false));
    let cloned_reached_timeout = Arc::clone(&has_reached_timeout);

    ctrlc::set_handler(move || {
        eprintln!("[warn] Receiving halt signal, ending scan with partial results");
        cloned_reached_timeout.store(true, Ordering::Relaxed);
    }).unwrap_or_else(|err| {
        eprintln!("Could not set CTRL+C handler ({})", err);
        process::exit(1);
    });

    let source_ip = network::find_source_ip(selected_interface, scan_options.source_ipv4);

    // The retry count does right now use a 'brute-force' strategy without
    // synchronization process with the already known hosts.
    for _ in 0..scan_options.retry_count {

        if has_reached_timeout.load(Ordering::Relaxed) {
            break;
        }

        let ip_addresses = NetworkIterator::new(&ip_networks, scan_options.randomize_targets);

        for ip_address in ip_addresses {

            if has_reached_timeout.load(Ordering::Relaxed) {
                break;
            }

            if let IpAddr::V4(ipv4_address) = ip_address {
                network::send_arp_request(&mut tx, selected_interface, source_ip, ipv4_address, Arc::clone(&scan_options));
                thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }

    // Once the ARP packets are sent, the main thread will sleep for T seconds
    // (where T is the timeout option). After the sleep phase, the response
    // thread will receive a stop request through the 'timed_out' mutex.
    let mut sleep_ms_mount: u64 = 0;
    while !has_reached_timeout.load(Ordering::Relaxed) && sleep_ms_mount < scan_options.timeout_ms {
        
        thread::sleep(Duration::from_millis(100));
        sleep_ms_mount += 100;
    }
    timed_out.store(true, Ordering::Relaxed);

    let (response_summary, target_details) = arp_responses.join().unwrap_or_else(|error| {
        eprintln!("Failed to close receive thread ({:?})", error);
        process::exit(1);
    });

    match &scan_options.output {
        OutputFormat::Plain => utils::display_scan_results(response_summary, target_details, &scan_options),
        OutputFormat::Json => println!("{}", utils::export_to_json(response_summary, target_details)),
        OutputFormat::Yaml => println!("{}", utils::export_to_yaml(response_summary, target_details)),
        OutputFormat::Csv => print!("{}", utils::export_to_csv(response_summary, target_details))
    }
}
