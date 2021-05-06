use pnet::datalink;
use pnet::packet::arp::{MutableArpPacket, ArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

use clap::{Arg, App};

use std::net::{IpAddr, Ipv4Addr};
use std::process;
use std::thread;
use std::time::Instant;

fn main() {

    let username = std::env::var("USER").unwrap_or(String::from(""));
    if username != String::from("root") {
        println!("Should run this binary as root");
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
            println!("Interface name required");
            process::exit(1);
        }
    };

    let timeout_seconds: u64 = match matches.value_of("timeout") {
        Some(seconds) => seconds.parse().unwrap_or(10),
        None => 10
    };

    // ----------------------

    let interfaces = datalink::interfaces();

    let selected_interface: &datalink::NetworkInterface = interfaces.iter()
        .find(|interface| { interface.name == interface_name && interface.is_up() && !interface.is_loopback() })
        .unwrap_or_else(|| {
            println!("Could not find interface with name {}", interface_name);
            process::exit(1);
        });

    let ip_network = match selected_interface.ips.first() {
        Some(ip_network) => ip_network,
        None => {
            println!("Expects a valid IP on the interface");
            process::exit(1);
        }
    };

    if !ip_network.is_ipv4() {
        println!("Only IPv4 supported");
        process::exit(1);
    }
    
    println!("Selected interface {} with IP {}", selected_interface.name, ip_network);

    // -----------------------

    let (mut tx, mut rx) = match datalink::channel(selected_interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown type"),
        Err(error) => panic!(error)
    };

    let responses = thread::spawn(move || {

        let start_recording = Instant::now();

        loop {

            if start_recording.elapsed().as_secs() > timeout_seconds {
                break;
            }
            
            let arp_buffer = rx.next().unwrap();
            
            let ethernet_packet = EthernetPacket::new(&arp_buffer[..]).unwrap();
            let is_arp = match ethernet_packet.get_ethertype() {
                EtherTypes::Arp => true,
                _ => false
            };

            if !is_arp {
                continue;
            }

            let arp_packet = ArpPacket::new(&arp_buffer[MutableEthernetPacket::minimum_packet_size()..]);

            match arp_packet {
                Some(arp) => println!("{} - {}", arp.get_sender_proto_addr(), arp.get_sender_hw_addr()),
                _ => ()
            }
        }

    });

    println!("Sending {:?} ARP requests to network", ip_network.size());
    for ip_address in ip_network.iter() {

        if let IpAddr::V4(ipv4_address) = ip_address {
            send_arp_request(&mut tx, selected_interface, ipv4_address);
        }
    }

    // ------------------

    responses.join().unwrap();
}

fn send_arp_request(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, interface: &datalink::NetworkInterface, target_ip: Ipv4Addr) {

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let target_mac = datalink::MacAddr::broadcast();
    let source_mac = interface.mac.unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    let source_ip = interface.ips.first().unwrap().ip();

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
