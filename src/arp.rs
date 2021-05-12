use std::process;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use std::collections::HashMap;

use pnet::datalink::{MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes, ArpPacket};

pub fn send_request(tx: &mut Box<dyn DataLinkSender>, interface: &NetworkInterface, target_ip: Ipv4Addr) {

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let target_mac = MacAddr::broadcast();
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

pub fn receive_responses(rx: &mut Box<dyn DataLinkReceiver>, timeout_seconds: u64) -> HashMap<Ipv4Addr, MacAddr> {

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
}