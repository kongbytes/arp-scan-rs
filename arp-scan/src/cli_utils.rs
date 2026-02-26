use ansi_term::Color::{Green, Red};
use arp_scan_lib::network::{ResponseSummary, TargetDetails};
use arp_scan_lib::scan_options::ScanOptions;
use arp_scan_lib::utils::select_default_interface;
#[cfg(target_os = "linux")]
use caps::{CapSet, Capability, has_cap};
use pnet_datalink::NetworkInterface;
use serde::Serialize;
use std::process;

/**
 * Check if the current user has the CAP_NET_RAW capability.
 *
 * For network operations like ARP scanning, you don't necessarily need full
 * root - you just need CAP_NET_RAW capability to perform scans. This was before
 * implemented as a minimalistic check to see if the "USER" env was set to root,
 * but failed to work in containerized environments.
 *
 * On Linux, this checks for CAP_NET_RAW capability. On other Unix-like systems
 * (macOS, BSD, etc.), the capability check is not applicable - permissions must
 * be granted at runtime (e.g., via sudo).
 */
pub fn has_network_capability() -> bool {
    #[cfg(target_os = "linux")]
    {
        has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW).unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux systems (macOS, BSD, etc.), we can't check capabilities
        // at compile time. The user needs to run with appropriate privileges.
        // Return true here and let the actual network operations fail if
        // permissions are insufficient.
        true
    }
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
            false => format!("{} DOWN", Red.paint("✖")),
        };
        let mac_text = match interface.mac {
            Some(mac_address) => format!("{}", mac_address),
            None => "No MAC address".to_string(),
        };
        let first_ip = match interface.ips.first() {
            Some(ip_address) => format!("{}", ip_address),
            None => "".to_string(),
        };

        let index_text = format!("{} ", interface.index);
        println!(
            "{: <3} {: <20} {: <18} {: <20} {}",
            index_text, interface.name, up_text, mac_text, first_ip
        );

        interface_count += 1;
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            ready_count += 1;
        }
    }

    println!();
    println!(
        "Found {} network interfaces, {} seems ready for ARP scans",
        interface_count, ready_count
    );
    if let Some(default_interface) = select_default_interface(interfaces) {
        println!(
            "Default network interface will be {}",
            default_interface.name
        );
    }
    println!();
}

pub fn print_ascii_packet() {
    println!();
    println!(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 ");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|         Hardware type         |        Protocol type          |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|         Hlen  | Plen          |          Operation            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Sender HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|             Sender HA         |      Sender IP                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|             Sender IP         |      Target HA                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|                          Target HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Target IP                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!();
    println!(" - Hardware type (2 bytes), use --hw-type option to change");
    println!(" - Protocol type (2 bytes), use --proto-type option to change");
    println!();
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
    options: &ScanOptions,
) {
    target_details.sort_by_key(|item| item.ipv4);

    let mut hostname_len = 15;
    let mut vendor_len = 15;
    for detail in target_details.iter() {
        if let Some(hostname) = &detail.hostname
            && hostname.len() > hostname_len
        {
            hostname_len = hostname.len();
        }

        if let Some(vendor) = &detail.vendor
            && vendor.len() > vendor_len
        {
            vendor_len = vendor.len();
        }
    }

    if !target_details.is_empty() {
        println!();
        println!(
            "| IPv4            | MAC               | {: <h_max$} | {: <v_max$} |",
            "Hostname",
            "Vendor",
            h_max = hostname_len,
            v_max = vendor_len
        );
        println!(
            "|-----------------|-------------------|-{:-<h_max$}-|-{:-<v_max$}-|",
            "",
            "",
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    for detail in target_details.iter() {
        let hostname: &str = match &detail.hostname {
            Some(hostname) => hostname,
            None if !options.resolve_hostname => "(disabled)",
            None => "",
        };
        let vendor: &str = match &detail.vendor {
            Some(vendor) => vendor,
            None => "",
        };
        println!(
            "| {: <15} | {: <18} | {: <h_max$} | {: <v_max$} |",
            detail.ipv4,
            detail.mac,
            hostname,
            vendor,
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    println!();
    print!("ARP scan finished, ");
    let target_count = target_details.len();
    match target_count {
        0 => print!("{}", Red.paint("no hosts found")),
        1 => print!("1 host found"),
        _ => print!("{} hosts found", target_count),
    }
    let seconds_duration = (response_summary.duration_ms as f32) / (1000_f32);
    println!(" in {:.3} seconds", seconds_duration);

    match response_summary.packet_count {
        0 => print!("No packets received, "),
        1 => print!("1 packet received, "),
        _ => print!("{} packets received, ", response_summary.packet_count),
    };
    match response_summary.arp_count {
        0 => println!("no ARP packets filtered"),
        1 => println!("1 ARP packet filtered"),
        _ => println!("{} ARP packets filtered", response_summary.arp_count),
    };
    println!();
}

#[derive(Serialize)]
struct SerializableResultItem {
    ipv4: String,
    mac: String,
    hostname: String,
    vendor: String,
}

#[derive(Serialize)]
struct SerializableGlobalResult {
    packet_count: usize,
    arp_count: usize,
    duration_ms: u128,
    results: Vec<SerializableResultItem>,
}

/**
 * Transforms an ARP scan result (including KPI and target details) to a structure
 * that can be serialized for export (JSON, YAML, CSV, ...)
 */
fn get_serializable_result(
    response_summary: ResponseSummary,
    target_details: Vec<TargetDetails>,
) -> SerializableGlobalResult {
    let exportable_results: Vec<SerializableResultItem> = target_details
        .into_iter()
        .map(|detail| {
            let hostname = match &detail.hostname {
                Some(hostname) => hostname.clone(),
                None => String::from(""),
            };

            let vendor = match &detail.vendor {
                Some(vendor) => vendor.clone(),
                None => String::from(""),
            };

            SerializableResultItem {
                ipv4: format!("{}", detail.ipv4),
                mac: format!("{}", detail.mac),
                hostname,
                vendor,
            }
        })
        .collect();

    SerializableGlobalResult {
        packet_count: response_summary.packet_count,
        arp_count: response_summary.arp_count,
        duration_ms: response_summary.duration_ms,
        results: exportable_results,
    }
}

/**
 * Export the scan results as a JSON string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_json(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
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
pub fn export_to_yaml(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_yaml::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export YAML results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a CSV string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_csv(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    let mut wtr = csv::Writer::from_writer(vec![]);

    for result in global_result.results {
        wtr.serialize(result).unwrap_or_else(|err| {
            eprintln!("Could not serialize result to CSV ({})", err);
            process::exit(1);
        });
    }
    wtr.flush().unwrap_or_else(|err| {
        eprintln!("Could not flush CSV writer buffer ({})", err);
        process::exit(1);
    });

    let convert_writer = wtr.into_inner().unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result ({})", err);
        process::exit(1);
    });
    String::from_utf8(convert_writer).unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result to text ({})", err);
        process::exit(1);
    })
}
