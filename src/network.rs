use std::process;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use std::collections::HashMap;
use dns_lookup::lookup_addr;

use pnet::datalink::{MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes, ArpPacket};

/**
 * A target detail represents a single host on the local network with an IPv4
 * address and a linked MAC address. Hostnames are optional since some hosts
 * does not respond to the resolve call (or the numeric mode may be enabled).
 */
pub struct TargetDetails {
    pub ipv4: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>
}

/**
 * Send a single ARP request - using a datalink-layer sender, a given network
 * interface and a target IPv4 address. The ARP request will be broadcasted to
 * the whole local network with the first valid IPv4 address on the interface.
 */
pub fn send_arp_request(tx: &mut Box<dyn DataLinkSender>, interface: &NetworkInterface, target_ip: Ipv4Addr, forced_source_ipv4: Option<Ipv4Addr>, forced_destination_mac: Option<MacAddr>) {

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let target_mac = match forced_destination_mac {
        Some(forced_mac) => forced_mac,
        None => MacAddr::broadcast()
    };
    let source_mac = interface.mac.unwrap_or_else(|| {
        eprintln!("Interface should have a MAC address");
        process::exit(1);
    });

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    let source_ipv4 = find_source_ip(interface, forced_source_ipv4);

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ipv4);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(&ethernet_packet.to_immutable().packet(), Some(interface.clone()));
}

/**
 * Find the most adequate IPv4 address on a given network interface for sending
 * ARP requests. If the 'forced_source_ipv4' parameter is set, it will take
 * the priority over the network interface address.
 */
fn find_source_ip(interface: &NetworkInterface, forced_source_ipv4: Option<Ipv4Addr>) -> Ipv4Addr {

    if let Some(forced_ipv4) = forced_source_ipv4 {
        return forced_ipv4;
    }

    let source_ip = interface.ips.first().unwrap_or_else(|| {
        eprintln!("Interface should have an IP address");
        process::exit(1);
    }).ip();

    let source_ipv4 = match source_ip {
        IpAddr::V4(ipv4_addr) => Some(ipv4_addr),
        IpAddr::V6(_ipv6_addr) => None
    };

    source_ipv4.unwrap()
}

/**
 * Wait at least N seconds and receive ARP network responses. The main
 * downside of this function is the blocking nature of the datalink receiver:
 * when the N seconds are elapsed, the receiver loop will therefore only stop
 * on the next received frame.
 */
pub fn receive_arp_responses(rx: &mut Box<dyn DataLinkReceiver>, timeout_seconds: u64, resolve_hostname: bool) -> Vec<TargetDetails> {

    let mut discover_map: HashMap<Ipv4Addr, TargetDetails> = HashMap::new();
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

        if let Some(arp) = arp_packet {

            let sender_ipv4 = arp.get_sender_proto_addr();
            let sender_mac = arp.get_sender_hw_addr();
    
            discover_map.insert(sender_ipv4, TargetDetails {
                ipv4: sender_ipv4,
                mac: sender_mac,
                hostname: None
            });
        }
    }

    discover_map.into_iter().map(|(_, mut target_details)| {

        if resolve_hostname {
            target_details.hostname = find_hostname(target_details.ipv4);
        }

        target_details

    }).collect()
}

/**
 * Find the local hostname linked to an IPv4 address. This will perform a
 * reverse DNS request in the local network to find the IPv4 hostname.
 */
fn find_hostname(ipv4: Ipv4Addr) -> Option<String> {

    let ip: IpAddr = ipv4.into();
    match lookup_addr(&ip) {
        Ok(hostname) => {

            // The 'lookup_addr' function returns an IP address if no hostname
            // was found. If this is the case, we prefer switching to None.
            if let Ok(_) = hostname.parse::<IpAddr>() {
                return None; 
            }

            Some(hostname)
        },
        Err(_) => None
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_resolve_public_ip() {

        let ipv4 = Ipv4Addr::new(1,1,1,1);

        assert_eq!(find_hostname(ipv4), Some("one.one.one.one".to_string()));
    }

    #[test]
    fn should_resolve_localhost() {

        let ipv4 = Ipv4Addr::new(127,0,0,1);

        assert_eq!(find_hostname(ipv4), Some("localhost".to_string()));
    }

    #[test]
    fn should_not_resolve_unknown_ip() {

        let ipv4 = Ipv4Addr::new(10,254,254,254);

        assert_eq!(find_hostname(ipv4), None);
    }

}
