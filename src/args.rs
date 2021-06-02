use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;

use clap::{Arg, ArgMatches, App};
use pnet::datalink::MacAddr;

const TIMEOUT_MS_DEFAULT: u64 = 2000;
const HOST_RETRY_DEFAULT: usize = 1;
const REQUEST_MS_INTERVAL: u64 = 10;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/**
 * This function groups together all exposed CLI arguments to the end-users
 * with clap. Other CLI details (version, ...) should be grouped there as well.
 */
pub fn build_args<'a, 'b>() -> App<'a, 'b> {

    App::new("arp-scan")
        .version(CLI_VERSION)
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::with_name("interface").short("i").long("interface").takes_value(true).value_name("INTERFACE_NAME").help("Network interface")
        )
        .arg(
            Arg::with_name("timeout").short("t").long("timeout").takes_value(true).value_name("TIMEOUT_DURATION").help("ARP response timeout")
        )
        .arg(
            Arg::with_name("source_ip").short("S").long("source-ip").takes_value(true).value_name("SOURCE_IPV4").help("Source IPv4 address for requests")
        )
        .arg(
            Arg::with_name("destination_mac").short("M").long("dest-mac").takes_value(true).value_name("DESTINATION_MAC").help("Destination MAC address for requests")
        )
        .arg(
            Arg::with_name("numeric").short("n").long("numeric").takes_value(false).help("Numeric mode, no hostname resolution")
        )
        .arg(
            Arg::with_name("vlan").short("Q").long("vlan").takes_value(true).value_name("VLAN_ID").help("Send using 802.1Q with VLAN ID")
        )
        .arg(
            Arg::with_name("retry_count").short("r").long("retry").takes_value(true).value_name("RETRY_COUNT").help("Host retry attempt count")
        )
        .arg(
            Arg::with_name("random").short("R").long("random").takes_value(false).help("Randomize the target list")
        )
        .arg(
            Arg::with_name("interval").short("I").long("interval").takes_value(true).value_name("INTERVAL_DURATION").help("Milliseconds between ARP requests")
        )
        .arg(
            Arg::with_name("list").short("l").long("list").takes_value(false).help("List network interfaces")
        )
        .arg(
            Arg::with_name("output").short("o").long("output").takes_value(true).value_name("FORMAT").help("Define output format")
        )
}

pub enum OutputFormat {
    Plain,
    Json,
    Yaml
}

pub struct ScanOptions {
    pub interface_name: String,
    pub timeout_ms: u64,
    pub resolve_hostname: bool,
    pub source_ipv4: Option<Ipv4Addr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>,
    pub retry_count: usize,
    pub interval_ms: u64,
    pub randomize_targets: bool,
    pub output: OutputFormat
}

impl ScanOptions {
    
    /**
     * Build a new 'ScanOptions' struct that will be used in the whole CLI such
     * as the network level, the display details and more. The scan options reflect
     * user requests for the CLI and should not be mutated.
     */
    pub fn new(matches: &ArgMatches) -> Arc<Self> {

        let interface_name = match matches.value_of("interface") {
            Some(name) => String::from(name),
            None => {
    
                match super::utils::select_default_interface() {
                    Some(default_interface) => {
                        default_interface.name
                    },
                    None => {
                        eprintln!("Network interface name required");
                        eprintln!("Use 'arp scan -l' to list available interfaces");
                        process::exit(1);
                    }
                }
            }
        };

        let timeout_ms: u64 = matches.value_of("timeout")
            .map(|timeout_text| parse_to_milliseconds(timeout_text))
            .unwrap_or(TIMEOUT_MS_DEFAULT);

        // Hostnames will not be resolved in numeric mode
        let resolve_hostname = !matches.is_present("numeric");

        let source_ipv4: Option<Ipv4Addr> = match matches.value_of("source_ip") {
            Some(source_ip) => {
                
                match source_ip.parse::<Ipv4Addr>() {
                    Ok(parsed_ipv4) => Some(parsed_ipv4),
                    Err(_) => {
                        eprintln!("Expected valid IPv4 as source IP");
                        process::exit(1);
                    }
                }
            }, 
            None => None
        };

        let destination_mac: Option<MacAddr> = match matches.value_of("destination_mac") {
            Some(mac_address) => {
                
                match mac_address.parse::<MacAddr>() {
                    Ok(parsed_mac) => Some(parsed_mac),
                    Err(_) => {
                        eprintln!("Expected valid MAC address as destination");
                        process::exit(1);
                    }
                }
            },
            None => None
        };
    
        let vlan_id: Option<u16> = match matches.value_of("vlan") {
            Some(vlan) => {
    
                match vlan.parse::<u16>() {
                    Ok(vlan_number) => Some(vlan_number),
                    Err(_) => {
                        eprintln!("Expected valid VLAN identifier");
                        process::exit(1);
                    }
                }
            },
            None => None
        };

        let retry_count = match matches.value_of("retry_count") {
            Some(retry_count) => {
    
                match retry_count.parse::<usize>() {
                    Ok(retry_number) => retry_number,
                    Err(_) => {
                        eprintln!("Expected positive number for host retry count");
                        process::exit(1);
                    }
                }
            },
            None => HOST_RETRY_DEFAULT
        };

        let interval_ms: u64 = matches.value_of("interval")
            .map(|interval_text| parse_to_milliseconds(interval_text))
            .unwrap_or(REQUEST_MS_INTERVAL);

        let output = match matches.value_of("output") {
            Some(output_request) => {

                match output_request {
                    "json" => OutputFormat::Json,
                    "yaml" => OutputFormat::Yaml,
                    "plain" | "text" => OutputFormat::Plain,
                    _ => {
                        eprintln!("Expected correct output format (json/yaml/plain)");
                        process::exit(1);
                    }
                }
            },
            None => OutputFormat::Plain
        };

        let randomize_targets = matches.is_present("random");
    
        Arc::new(ScanOptions {
            interface_name,
            timeout_ms,
            resolve_hostname,
            source_ipv4,
            destination_mac,
            vlan_id,
            retry_count,
            interval_ms,
            randomize_targets,
            output
        })
    }

    pub fn is_plain_output(&self) -> bool {

        matches!(&self.output, OutputFormat::Plain)
    }

}

/**
 * Parse a given time string into milliseconds. This can be used to convert a
 * string such as '20ms', '10s' or '1h' into adequate milliseconds. Without
 * suffix, the default behavior is to parse into milliseconds.
 */
fn parse_to_milliseconds(time_arg: &str) -> u64 {

    let len = time_arg.len();

    if time_arg.ends_with("ms") {
        let milliseconds_text = &time_arg[0..len-2];
        return milliseconds_text.parse::<u64>()
            .unwrap_or_else(|err| {
                eprintln!("Expected valid milliseconds ({})", err);
                process::exit(1);
            });
    }

    if time_arg.ends_with('s') {
        let seconds_text = &time_arg[0..len-1];
        return seconds_text.parse::<u64>()
            .map(|value| value * 1000)
            .unwrap_or_else(|err| {
                eprintln!("Expected valid seconds ({})", err);
                process::exit(1);
            });
    }

    if time_arg.ends_with('h') {
        let hour_text = &time_arg[0..len-1];
        return hour_text.parse::<u64>()
            .map(|value| value * 1000 * 60)
            .unwrap_or_else(|err| {
                eprintln!("Expected valid hours ({})", err);
                process::exit(1);
            });
    }

    time_arg.parse::<u64>()
        .unwrap_or_else(|err| {
            eprintln!("Expected valid milliseconds ({})", err);
            process::exit(1);
        })
}
