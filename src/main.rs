use pnet::datalink;
use pnet::packet::arp::{MutableArpPacket, ArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use clap::{Arg, App};

use std::net::{IpAddr, Ipv4Addr};
use std::process;
use std::thread;
use std::time::Instant;
use std::collections::HashMap;

fn is_root_user() -> bool {
    std::env::var("USER").unwrap_or(String::from("")) == String::from("root")
}

fn main() {

    if !is_root_user() {
        eprintln!("Should run this binary as root");
        process::exit(1);
    }

    let matches = App::new("arp-scan")
        .version("0.1")
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(Arg::with_name("interface").short("i").long("interface").takes_value(true).value_name("INTERFACE_NAME").help("Network interface"))
        .arg(Arg::with_name("timeout").short("t").long("timeout").takes_value(true).value_name("TIMEOUT_SECONDS").help("ARP response timeout"))
        .get_matches();

    let interface_name = match matches.value_of("interface") {
        Some(name) => name,
        None => {
            eprintln!("Interface name required");
            process::exit(1);
        }
    };

    let timeout_seconds: u64 = match matches.value_of("timeout") {
        Some(seconds) => seconds.parse().unwrap_or(5),
        None => 5
    };

    // ----------------------

    let interfaces = datalink::interfaces();

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

    // -----------------------

    let (mut tx, mut rx) = match datalink::channel(selected_interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown type"),
        Err(error) => panic!(error)
    };

    let responses = thread::spawn(move || {

        let mut discover_map: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
        let start_recording = Instant::now();

        loop {

            if start_recording.elapsed().as_secs() > timeout_seconds {
                break;
            }
            
            let arp_buffer = rx.next().unwrap_or_else(|error| {
                eprintln!("Failed to receive ARP requests ({})", error);
                process::exit(1);
            });
            
            let ethernet_packet = match EthernetPacket::new(&arp_buffer[..]) {
                Some(packet) => packet,
                None => continue
            };

            let is_arp = match ethernet_packet.get_ethertype() {
                EtherTypes::Arp => true,
                _ => false
            };

            if !is_arp {
                continue;
            }

            let arp_packet = ArpPacket::new(&arp_buffer[MutableEthernetPacket::minimum_packet_size()..]);

            match arp_packet {
                Some(arp) => {

                    let sender_ipv4 = arp.get_sender_proto_addr();
                    let sender_mac = arp.get_sender_hw_addr();
            
                    discover_map.insert(sender_ipv4, sender_mac);

                },
                _ => ()
            }
        }

        return discover_map;

    });

    println!("Sending {:?} ARP requests to network ({}s timeout)", ip_network.size(), timeout_seconds);
    for ip_address in ip_network.iter() {

        if let IpAddr::V4(ipv4_address) = ip_address {
            send_arp_request(&mut tx, selected_interface, ipv4_address);
        }
    }

    // ------------------

    let final_result = responses.join().unwrap_or_else(|error| {
        eprintln!("Failed to close receive thread ({:?})", error);
        process::exit(1);
    });

    let mut sorted_map: Vec<(Ipv4Addr, MacAddr)> = final_result.into_iter().collect();
    sorted_map.sort_by_key(|x| x.0);
    println!("");
    println!("| IPv4            | MAC               |");
    println!("|-----------------|-------------------|");
    for (result_ipv4, result_mac) in sorted_map {
        println!("| {: <15} | {: <18} |", &result_ipv4, &result_mac);
    }
    println!("");
}

fn send_arp_request(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, interface: &datalink::NetworkInterface, target_ip: Ipv4Addr) {

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let target_mac = datalink::MacAddr::broadcast();
    let source_mac = interface.mac.unwrap_or_else(|| {
        eprintln!("Interface should have a MAC address");
        process::exit(1);
    });

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    let source_ip = interface.ips.first().unwrap_or_else(|| {
        eprintln!("Interface should have an IP address");
        process::exit(1);
    }).ip();

    let source_ipv4 = match source_ip {
        IpAddr::V4(ipv4_addr) => Some(ipv4_addr),
        IpAddr::V6(_ipv6_addr) => None
    };

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ipv4.unwrap());
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(&ethernet_packet.to_immutable().packet(), Some(interface.clone()));
}
