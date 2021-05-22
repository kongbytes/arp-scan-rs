use std::net::Ipv4Addr;
use std::process;

use clap::{Arg, ArgMatches, App};
use pnet::datalink::MacAddr;

const FIVE_HOURS: u64 = 5 * 60 * 60; 
const TIMEOUT_DEFAULT: u64 = 2;

pub fn build_args<'a, 'b>() -> App<'a, 'b> {

    App::new("arp-scan")
        .version("0.5.0")
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::with_name("interface").short("i").long("interface").takes_value(true).value_name("INTERFACE_NAME").help("Network interface")
        )
        .arg(
            Arg::with_name("timeout").short("t").long("timeout").takes_value(true).value_name("TIMEOUT_SECONDS").help("ARP response timeout")
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
            Arg::with_name("list").short("l").long("list").takes_value(false).help("List network interfaces")
        )
}

#[derive(Clone)]
pub struct ScanOptions {
    pub interface_name: String,
    pub timeout_seconds: u64,
    pub resolve_hostname: bool,
    pub source_ipv4: Option<Ipv4Addr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>
}

impl ScanOptions {
    
    pub fn new(matches: &ArgMatches) -> Self {

        let interface_name = match matches.value_of("interface") {
            Some(name) => String::from(name),
            None => {
    
                match super::utils::select_default_interface() {
                    Some(default_interface) => {
                        String::from(default_interface.name)
                    },
                    None => {
                        eprintln!("Network interface name required");
                        eprintln!("Use 'arp scan -l' to list available interfaces");
                        process::exit(1);
                    }
                }
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
    
        ScanOptions {
            interface_name,
            timeout_seconds,
            resolve_hostname,
            source_ipv4,
            destination_mac,
            vlan_id
        }
    }

}
