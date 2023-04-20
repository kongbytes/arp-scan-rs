use std::str::FromStr;
use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;
use std::path::Path;
use std::fs;

use clap::{Arg, ArgMatches, Command, ArgAction};
use ipnetwork::IpNetwork;
use pnet_datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;

use crate::time::parse_to_milliseconds;

const TIMEOUT_MS_FAST: u64 = 800;
const TIMEOUT_MS_DEFAULT: u64 = 2000;

const HOST_RETRY_DEFAULT: usize = 1;
const REQUEST_MS_INTERVAL: u64 = 10;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

const EXAMPLES_HELP: &str = "EXAMPLES:

    # Launch a default scan with on the first working interface
    arp-scan

    # List network interfaces
    arp-scan -l

    # Launch a scan on a specific range
    arp-scan -i eth0 -n 10.37.3.1,10.37.4.55/24

    # Launch a scan on WiFi interface with fake IP and stealth profile
    arp-scan -i eth0 --source-ip 192.168.0.42 --profile stealth

    # Launch a scan on VLAN 45 with JSON output
    arp-scan -Q 45 -o json

";

/**
 * This function groups together all exposed CLI arguments to the end-users
 * with clap. Other CLI details (version, ...) should be grouped there as well.
 */
pub fn build_args() -> Command {

    Command::new("arp-scan")
        .version(CLI_VERSION)
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::new("profile").short('p').long("profile")
                .value_name("PROFILE_NAME")
                .help("Scan profile")
        )
        .arg(
            Arg::new("interface").short('i').long("interface")
                .value_name("INTERFACE_NAME")
                .help("Network interface")
        )
        .arg(
            Arg::new("network").short('n').long("network")
                .value_name("NETWORK_RANGE")
                .help("Network range to scan")
        )
        .arg(
            Arg::new("file").short('f').long("file")
                .value_name("FILE_PATH")
                .conflicts_with("network")
                .help("Read IPv4 addresses from a file")
        )
        .arg(
            Arg::new("timeout").short('t').long("timeout")
                .value_name("TIMEOUT_DURATION")
                .help("ARP response timeout")
        )
        .arg(
            Arg::new("source_ip").short('S').long("source-ip")
                .value_name("SOURCE_IPV4")
                .help("Source IPv4 address for requests")
        )
        .arg(
            Arg::new("destination_mac").short('M').long("dest-mac")
                .value_name("DESTINATION_MAC")
                .help("Destination MAC address for requests")
        )
        .arg(
            Arg::new("source_mac").long("source-mac")
                .value_name("SOURCE_MAC")
                .help("Source MAC address for requests")
        )
        .arg(
            Arg::new("numeric").long("numeric")
                .action(ArgAction::SetTrue)
                .help("Numeric mode, no hostname resolution")
        )
        .arg(
            Arg::new("vlan").short('Q').long("vlan")
                .value_name("VLAN_ID")
                .help("Send using 802.1Q with VLAN ID")
        )
        .arg(
            Arg::new("retry_count").short('r').long("retry")
                .value_name("RETRY_COUNT")
                .help("Host retry attempt count")
        )
        .arg(
            Arg::new("random").short('R').long("random")
                .action(ArgAction::SetTrue)
                .help("Randomize the target list")
        )
        .arg(
            Arg::new("interval").short('I').long("interval")
                .value_name("INTERVAL_DURATION")
                .help("Milliseconds between ARP requests")
        )
        .arg(
            Arg::new("bandwidth").short('B').long("bandwidth")
                .value_name("BITS")
                .conflicts_with("interval")
                .help("Limit scan bandwidth (bits/second)")
        )
        .arg(
            Arg::new("oui-file").long("oui-file")
                .value_name("FILE_PATH")
                .help("Path to custom IEEE OUI CSV file")
        )
        .arg(
            Arg::new("list").short('l').long("list")
                .action(ArgAction::SetTrue)
                .exclusive(true)
                .help("List network interfaces")
        )
        .arg(
            Arg::new("output").short('o').long("output")
                .value_name("FORMAT")
                .help("Define output format")
        )
        .arg(
            Arg::new("hw_type").long("hw-type")
                .value_name("HW_TYPE")
                .help("Custom ARP hardware field")
        )
        .arg(
            Arg::new("hw_addr").long("hw-addr")
                .value_name("ADDRESS_LEN")
                .help("Custom ARP hardware address length")
        )
        .arg(
            Arg::new("proto_type").long("proto-type")
                .value_name("PROTO_TYPE")
                .help("Custom ARP proto type")
        )
        .arg(
            Arg::new("proto_addr").long("proto-addr")
                .value_name("ADDRESS_LEN")
                .help("Custom ARP proto address length")
        )
        .arg(
            Arg::new("arp_operation").long("arp-op")
                .value_name("OPERATION_ID")
                .help("Custom ARP operation ID")
        )
        .arg(
            Arg::new("packet_help").long("packet-help")
                .action(ArgAction::SetTrue)
                .exclusive(true)
                .help("Print details about an ARP packet")
        )
        .after_help(EXAMPLES_HELP)
}

pub enum OutputFormat {
    Plain,
    Json,
    Yaml,
    Csv
}

pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos
}

pub enum ScanTiming {
    Interval(u64),
    Bandwidth(u64)
}

pub struct ScanOptions {
    pub profile: ProfileType,
    pub interface_name: Option<String>,
    pub network_range: Option<Vec<ipnetwork::IpNetwork>>,
    pub timeout_ms: u64,
    pub resolve_hostname: bool,
    pub source_ipv4: Option<Ipv4Addr>,
    pub source_mac: Option<MacAddr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>,
    pub retry_count: usize,
    pub scan_timing: ScanTiming,
    pub randomize_targets: bool,
    pub output: OutputFormat,
    pub oui_file: String,
    pub hw_type: Option<ArpHardwareType>,
    pub hw_addr: Option<u8>,
    pub proto_type: Option<EtherType>,
    pub proto_addr: Option<u8>,
    pub arp_operation: Option<ArpOperation>,
    pub packet_help: bool,
}

impl ScanOptions {

    fn list_required_networks(file_value: Option<&String>, network_value: Option<&String>) -> Result<Option<Vec<String>>, String> {

        let network_options = (file_value, network_value);
        match network_options {
            (Some(file_path), None) => {

                let path = Path::new(file_path);
                fs::read_to_string(path).map(|content| {
                    Some(content.lines().map(|line| line.to_string()).collect())
                }).map_err(|err| {
                    format!("Could not open file {} - {}", file_path, err)
                })

            },
            (None, Some(raw_ranges)) => {
                Ok(Some(raw_ranges.split(',').map(|line| line.to_string()).collect()))
            },
            _ => Ok(None)
        }
    }

    /**
     * Computes the whole network range requested by the user through CLI
     * arguments or files. This method will fail of a failure has been detected
     * (either on the IO level or the network syntax parsing)
     */
    fn compute_networks(file_value: Option<&String>, network_value: Option<&String>) -> Result<Option<Vec<IpNetwork>>, String> {

        let required_networks: Option<Vec<String>> = ScanOptions::list_required_networks(file_value, network_value)?;
        if required_networks.is_none() {
            return Ok(None);
        }

        let mut networks: Vec<IpNetwork> = vec![];
        for network_text in required_networks.unwrap() {

            match IpNetwork::from_str(&network_text) {
                Ok(parsed_network) => {
                    networks.push(parsed_network);
                    Ok(())
                },
                Err(err) => {
                    Err(format!("Expected valid IPv4 network range ({})", err))
                }
            }?;
        }
        Ok(Some(networks))
    }

    /**
     * Computes scan timing constraints, as requested by the user through CLI
     * arguments. The scan timing constraints will be either expressed in bandwidth
     * (bits per second) or interval between ARP requests (in milliseconds).
     */
    fn compute_scan_timing(matches: &ArgMatches, profile: &ProfileType) -> ScanTiming {

        match (matches.get_one::<String>("bandwidth"), matches.get_one::<String>("interval")) {
            (Some(bandwidth_text), None) => {
                let bits_second: u64 = bandwidth_text.parse().unwrap_or_else(|err| {
                    eprintln!("Expected positive number, {}", err);
                    process::exit(1);
                });
                ScanTiming::Bandwidth(bits_second)
            },
            (None, Some(interval_text)) => parse_to_milliseconds(interval_text).map(ScanTiming::Interval).unwrap_or_else(|err| {
                eprintln!("Expected correct interval, {}", err);
                process::exit(1);
            }),
            _ => match profile {
                ProfileType::Stealth => ScanTiming::Interval(REQUEST_MS_INTERVAL * 2),
                ProfileType::Fast => ScanTiming::Interval(0),
                _ => ScanTiming::Interval(REQUEST_MS_INTERVAL)
            }
        }
    }
    
    /**
     * Build a new 'ScanOptions' struct that will be used in the whole CLI such
     * as the network level, the display details and more. The scan options reflect
     * user requests for the CLI and should not be mutated.
     */
    pub fn new(matches: &ArgMatches) -> Arc<Self> {

        let profile = match matches.get_one::<String>("profile") {
            Some(output_request) => {

                match output_request.as_ref() {
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

        let interface_name = matches.get_one::<String>("interface").cloned();

        let file_option = matches.get_one::<String>("file");
        let network_option = matches.get_one::<String>("network");

        let network_range = ScanOptions::compute_networks(file_option, network_option).unwrap_or_else(|err| {
            eprintln!("Could not compute requested network range to scan");
            eprintln!("{}", err);
            process::exit(1);
        });

        let timeout_ms: u64 = match matches.get_one::<String>("timeout") {
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
        let resolve_hostname = !matches.get_flag("numeric") && !matches!(profile, ProfileType::Stealth);

        let source_ipv4: Option<Ipv4Addr> = match matches.get_one::<String>("source_ip") {
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

        let destination_mac: Option<MacAddr> = match matches.get_one::<String>("destination_mac") {
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

        let source_mac: Option<MacAddr> = match matches.get_one::<String>("source_mac") {
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
    
        let vlan_id: Option<u16> = match matches.get_one::<String>("vlan") {
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

        let retry_count = match matches.get_one::<String>("retry_count") {
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

        let scan_timing: ScanTiming = ScanOptions::compute_scan_timing(matches, &profile);

        let output = match matches.get_one::<String>("output") {
            Some(output_request) => {

                match output_request.as_ref() {
                    "json" => OutputFormat::Json,
                    "yaml" => OutputFormat::Yaml,
                    "plain" | "text" => OutputFormat::Plain,
                    "csv" => OutputFormat::Csv,
                    _ => {
                        eprintln!("Expected correct output format (json/yaml/plain)");
                        process::exit(1);
                    }
                }
            },
            None => OutputFormat::Plain
        };

        let randomize_targets = matches.get_flag("random") || matches!(profile, ProfileType::Stealth | ProfileType::Chaos);

        let oui_file: String = match matches.get_one::<String>("oui-file") {
            Some(file) => file.to_string(),
            None => "/usr/share/arp-scan/ieee-oui.csv".to_string()
        };

        let hw_type = match matches.get_one::<String>("hw_type") {
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
        
        let hw_addr = match matches.get_one::<String>("hw_addr") {
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
        
        let proto_type = match matches.get_one::<String>("proto_type") {
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
        
        let proto_addr = match matches.get_one::<String>("proto_addr") {
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

        let arp_operation = match matches.get_one::<String>("arp_operation") {
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

        let packet_help = matches.get_flag("packet_help");
    
        Arc::new(ScanOptions {
            profile,
            interface_name,
            network_range,
            timeout_ms,
            resolve_hostname,
            source_ipv4,
            destination_mac,
            source_mac,
            vlan_id,
            retry_count,
            scan_timing,
            randomize_targets,
            output,
            oui_file,
            hw_type,
            hw_addr,
            proto_type,
            proto_addr,
            arp_operation,
            packet_help,
        })
    }

    pub fn is_plain_output(&self) -> bool {

        matches!(&self.output, OutputFormat::Plain)
    }

    pub fn has_vlan(&self) -> bool {

        matches!(&self.vlan_id, Some(_)) 
    }

    pub fn request_protocol_print(&self) -> bool {
        self.packet_help
    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use ipnetwork::Ipv4Network;

    #[test]
    fn should_have_no_network_default() {
        
        let networks = ScanOptions::compute_networks(None, None);
        assert_eq!(networks, Ok(None));
    }

    #[test]
    fn should_handle_single_ipv4_arg() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"192.168.1.20".to_string()));

        let target_network: Vec<IpNetwork> = vec![
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 20), 32).unwrap()
            )
        ];

        assert_eq!(networks, Ok(Some(target_network)));
    }

    #[test]
    fn should_handle_multiple_ipv4_arg() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"192.168.1.20,192.168.1.50".to_string()));

        let target_network: Vec<IpNetwork> = vec![
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 20), 32).unwrap()
            ),
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 50), 32).unwrap()
            )
        ];

        assert_eq!(networks, Ok(Some(target_network)));
    }

    #[test]
    fn should_handle_single_network_arg() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"192.168.1.0/24".to_string()));

        let target_network: Vec<IpNetwork> = vec![
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
            )
        ];

        assert_eq!(networks, Ok(Some(target_network)));
    }

    #[test]
    fn should_handle_network_mix_arg() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"192.168.20.1,192.168.1.0/24,192.168.5.4/28".to_string()));

        let target_network: Vec<IpNetwork> = vec![
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 20, 1), 32).unwrap()
            ),
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
            ),
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 5, 4), 28).unwrap()
            )
        ];

        assert_eq!(networks, Ok(Some(target_network)));
    }

    #[test]
    fn should_handle_file_input() {
        
        let networks = ScanOptions::compute_networks(Some(&"./data/ip-list.txt".to_string()), None);

        let target_network: Vec<IpNetwork> = vec![
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()
            ),
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 2), 32).unwrap()
            ),
            IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 2, 0), 29).unwrap()
            )
        ];

        assert_eq!(networks, Ok(Some(target_network)));
    }

    #[test]
    fn should_fail_incorrect_network() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"500.10.10.10/24".to_string()));

        assert_eq!(networks, Err("Expected valid IPv4 network range (invalid address: 500.10.10.10/24)".to_string()));
    }

    #[test]
    fn should_fail_unreadable_network() {
        
        let networks = ScanOptions::compute_networks(None, Some(&"no-network".to_string()));

        assert_eq!(networks, Err("Expected valid IPv4 network range (invalid address: no-network)".to_string()));
    }

}
