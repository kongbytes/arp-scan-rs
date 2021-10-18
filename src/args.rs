use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;

use clap::{Arg, ArgMatches, App};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;

const TIMEOUT_MS_FAST: u64 = 800;
const TIMEOUT_MS_DEFAULT: u64 = 2000;

const HOST_RETRY_DEFAULT: usize = 1;
const REQUEST_MS_INTERVAL: u64 = 10;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

const EXAMPLES_HELP: &str = "EXAMPLES:

    List network interfaces
    arp-scan -l

    Launch a scan on WiFi interface with fake IP and stealth profile
    arp-scan -i wlp1s0 --source-ip 192.168.0.42 --profile stealth

    Launch a scan on VLAN 45 with JSON output
    arp-scan -Q 45 -o json

";

/**
 * This function groups together all exposed CLI arguments to the end-users
 * with clap. Other CLI details (version, ...) should be grouped there as well.
 */
pub fn build_args<'a, 'b>() -> App<'a, 'b> {

    App::new("arp-scan")
        .version(CLI_VERSION)
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::with_name("profile").short("p").long("profile")
                .takes_value(true).value_name("PROFILE_NAME")
                .help("Scan profile")
        )
        .arg(
            Arg::with_name("interface").short("i").long("interface")
                .takes_value(true).value_name("INTERFACE_NAME")
                .help("Network interface")
        )
        .arg(
            Arg::with_name("timeout").short("t").long("timeout")
                .takes_value(true).value_name("TIMEOUT_DURATION")
                .help("ARP response timeout")
        )
        .arg(
            Arg::with_name("source_ip").short("S").long("source-ip")
                .takes_value(true).value_name("SOURCE_IPV4")
                .help("Source IPv4 address for requests")
        )
        .arg(
            Arg::with_name("destination_mac").short("M").long("dest-mac")
                .takes_value(true).value_name("DESTINATION_MAC")
                .help("Destination MAC address for requests")
        )
        .arg(
            Arg::with_name("source_mac").long("source-mac")
                .takes_value(true).value_name("SOURCE_MAC")
                .help("Source MAC address for requests")
        )
        .arg(
            Arg::with_name("numeric").short("n").long("numeric")
                .takes_value(false)
                .help("Numeric mode, no hostname resolution")
        )
        .arg(
            Arg::with_name("vlan").short("Q").long("vlan")
                .takes_value(true).value_name("VLAN_ID")
                .help("Send using 802.1Q with VLAN ID")
        )
        .arg(
            Arg::with_name("retry_count").short("r").long("retry")
                .takes_value(true).value_name("RETRY_COUNT")
                .help("Host retry attempt count")
        )
        .arg(
            Arg::with_name("random").short("R").long("random")
                .takes_value(false)
                .help("Randomize the target list")
        )
        .arg(
            Arg::with_name("interval").short("I").long("interval")
                .takes_value(true).value_name("INTERVAL_DURATION")
                .help("Milliseconds between ARP requests")
        )
        .arg(
            Arg::with_name("oui-file").long("oui-file")
                .takes_value(true).value_name("FILE_PATH")
                .help("Path to custom IEEE OUI CSV file")
        )
        .arg(
            Arg::with_name("list").short("l").long("list")
                .takes_value(false)
                .help("List network interfaces")
        )
        .arg(
            Arg::with_name("output").short("o").long("output")
                .takes_value(true).value_name("FORMAT")
                .help("Define output format")
        )
        .arg(
            Arg::with_name("hw_type").long("hw-type")
                .takes_value(true).value_name("HW_TYPE")
                .help("Custom ARP hardware field")
        )
        .arg(
            Arg::with_name("hw_addr").long("hw-addr")
                .takes_value(true).value_name("ADDRESS_LEN")
                .help("Custom ARP hardware address length")
        )
        .arg(
            Arg::with_name("proto_type").long("proto-type")
                .takes_value(true).value_name("PROTO_TYPE")
                .help("Custom ARP proto type")
        )
        .arg(
            Arg::with_name("proto_addr").long("proto-addr")
                .takes_value(true).value_name("ADDRESS_LEN")
                .help("Custom ARP proto address length")
        )
        .arg(
            Arg::with_name("arp_operation").long("arp-op")
                .takes_value(true).value_name("OPERATION_ID")
                .help("Custom ARP operation ID")
        )
        .after_help(EXAMPLES_HELP)
}

pub enum OutputFormat {
    Plain,
    Json,
    Yaml
}

pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos
}

pub struct ScanOptions {
    pub profile: ProfileType,
    pub interface_name: Option<String>,
    pub timeout_ms: u64,
    pub resolve_hostname: bool,
    pub source_ipv4: Option<Ipv4Addr>,
    pub source_mac: Option<MacAddr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>,
    pub retry_count: usize,
    pub interval_ms: u64,
    pub randomize_targets: bool,
    pub output: OutputFormat,
    pub oui_file: String,
    pub hw_type: Option<ArpHardwareType>,
    pub hw_addr: Option<u8>,
    pub proto_type: Option<EtherType>,
    pub proto_addr: Option<u8>,
    pub arp_operation: Option<ArpOperation>
}

impl ScanOptions {
    
    /**
     * Build a new 'ScanOptions' struct that will be used in the whole CLI such
     * as the network level, the display details and more. The scan options reflect
     * user requests for the CLI and should not be mutated.
     */
    pub fn new(matches: &ArgMatches) -> Arc<Self> {

        let profile = match matches.value_of("profile") {
            Some(output_request) => {

                match output_request {
                    "default" | "d" => ProfileType::Default,
                    "fast" | "f" => ProfileType::Fast,
                    "stealth" | "s" => ProfileType::Stealth,
                    "chaos" | "c" => ProfileType::Chaos,
                    _ => {
                        eprintln!("Expected correct profile name (default/fast/stealth/chaos)");
                        process::exit(1);
                    }
                }
            },
            None => ProfileType::Default
        };

        let interface_name = matches.value_of("interface").map(String::from);

        let timeout_ms: u64 = match matches.value_of("timeout") {
            Some(timeout_text) => parse_to_milliseconds(timeout_text).unwrap_or_else(|err| {
                eprintln!("Expected correct timeout, {}", err);
                process::exit(1);
            }),
            None => match profile {
                ProfileType::Fast => TIMEOUT_MS_FAST,
                _ => TIMEOUT_MS_DEFAULT
            }
        };

        // Hostnames will not be resolved in numeric mode or stealth profile
        let resolve_hostname = !matches.is_present("numeric") && !matches!(profile, ProfileType::Stealth);

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

        let source_mac: Option<MacAddr> = match matches.value_of("source_mac") {
            Some(mac_address) => {
                
                match mac_address.parse::<MacAddr>() {
                    Ok(parsed_mac) => Some(parsed_mac),
                    Err(_) => {
                        eprintln!("Expected valid MAC address as source");
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
            None => match profile {
                ProfileType::Chaos => HOST_RETRY_DEFAULT * 2,
                _ => HOST_RETRY_DEFAULT
            }
        };

        let interval_ms: u64 = match matches.value_of("interval") {
            Some(interval_text) => parse_to_milliseconds(interval_text).unwrap_or_else(|err| {
                eprintln!("Expected correct interval, {}", err);
                process::exit(1);
            }),
            None => match profile {
                ProfileType::Stealth => REQUEST_MS_INTERVAL * 2,
                ProfileType::Fast => 0,
                _ => REQUEST_MS_INTERVAL
            }
        };

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

        let randomize_targets = matches.is_present("random") || matches!(profile, ProfileType::Stealth | ProfileType::Chaos);

        let oui_file: String = match matches.value_of("oui-file") {
            Some(file) => file.to_string(),
            None => "/usr/share/arp-scan/ieee-oui.csv".to_string()
        };

        let hw_type = match matches.value_of("hw-type") {
            Some(hw_type_text) => {
    
                match hw_type_text.parse::<u16>() {
                    Ok(type_number) => Some(ArpHardwareType::new(type_number)),
                    Err(_) => {
                        eprintln!("Expected valid ARP hardware type number");
                        process::exit(1);
                    }
                }
            },
            None => None
        };
        
        let hw_addr = match matches.value_of("hw-addr") {
            Some(hw_addr_text) => {
    
                match hw_addr_text.parse::<u8>() {
                    Ok(addr_length) => Some(addr_length),
                    Err(_) => {
                        eprintln!("Expected valid ARP hardware address length");
                        process::exit(1);
                    }
                }
            },
            None => None
        };
        
        let proto_type = match matches.value_of("proto-type") {
            Some(proto_type_text) => {
    
                match proto_type_text.parse::<u16>() {
                    Ok(type_number) => Some(EtherType::new(type_number)),
                    Err(_) => {
                        eprintln!("Expected valid ARP proto type number");
                        process::exit(1);
                    }
                }
            },
            None => None
        };
        
        let proto_addr = match matches.value_of("proto-addr") {
            Some(proto_addr_text) => {
    
                match proto_addr_text.parse::<u8>() {
                    Ok(addr_length) => Some(addr_length),
                    Err(_) => {
                        eprintln!("Expected valid ARP hardware address length");
                        process::exit(1);
                    }
                }
            },
            None => None
        };

        let arp_operation = match matches.value_of("arp-op") {
            Some(arp_op_text) => {
    
                match arp_op_text.parse::<u16>() {
                    Ok(op_number) => Some(ArpOperation::new(op_number)),
                    Err(_) => {
                        eprintln!("Expected valid ARP operation number");
                        process::exit(1);
                    }
                }
            },
            None => None
        };
    
        Arc::new(ScanOptions {
            profile,
            interface_name,
            timeout_ms,
            resolve_hostname,
            source_ipv4,
            destination_mac,
            source_mac,
            vlan_id,
            retry_count,
            interval_ms,
            randomize_targets,
            output,
            oui_file,
            hw_type,
            hw_addr,
            proto_type,
            proto_addr,
            arp_operation
        })
    }

    pub fn is_plain_output(&self) -> bool {

        matches!(&self.output, OutputFormat::Plain)
    }

    pub fn has_vlan(&self) -> bool {

        matches!(&self.vlan_id, Some(_)) 
    }

}

/**
 * Parse a given time string into milliseconds. This can be used to convert a
 * string such as '20ms', '10s' or '1h' into adequate milliseconds. Without
 * suffix, the default behavior is to parse into milliseconds.
 */
fn parse_to_milliseconds(time_arg: &str) -> Result<u64, &str> {

    let len = time_arg.len();

    if time_arg.ends_with("ms") {
        let milliseconds_text = &time_arg[0..len-2];
        return match milliseconds_text.parse::<u64>() {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid milliseconds")
        };
    }

    if time_arg.ends_with('s') {
        let seconds_text = &time_arg[0..len-1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid seconds")
        };
    }

    if time_arg.ends_with('m') {
        let seconds_text = &time_arg[0..len-1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid minutes")
        };
    }

    if time_arg.ends_with('h') {
        let hour_text = &time_arg[0..len-1];
        return match hour_text.parse::<u64>().map(|value| value * 1000 * 60 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid hours")
        };
    }

    match time_arg.parse::<u64>() {
        Ok(ms_value) => Ok(ms_value),
        Err(_) => Err("invalid milliseconds")
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_milliseconds() {
        
        assert_eq!(parse_to_milliseconds("1000"), Ok(1000));
    }

    #[test]
    fn should_parse_seconds() {
        
        assert_eq!(parse_to_milliseconds("5s"), Ok(5000));
    }

    #[test]
    fn should_parse_minutes() {
        
        assert_eq!(parse_to_milliseconds("3m"), Ok(180_000));
    }

    #[test]
    fn should_parse_hours() {
        
        assert_eq!(parse_to_milliseconds("2h"), Ok(7_200_000));
    }

    #[test]
    fn should_deny_negative() {
        
        assert_eq!(parse_to_milliseconds("-45"), Err("invalid milliseconds"));
    }

    #[test]
    fn should_deny_floating_numbers() {
        
        assert_eq!(parse_to_milliseconds("3.235"), Err("invalid milliseconds"));
    }

    #[test]
    fn should_deny_invalid_characters() {
        
        assert_eq!(parse_to_milliseconds("3z"), Err("invalid milliseconds"));
    }

}
