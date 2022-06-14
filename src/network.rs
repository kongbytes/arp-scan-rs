use std::process;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::ErrorKind::TimedOut;
use std::convert::TryInto;

use dns_lookup::lookup_addr;
use ipnetwork::IpNetwork;
use pnet_datalink::{MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes, ArpPacket};
use pnet::packet::vlan::{ClassOfService, MutableVlanPacket};
use rand::prelude::*;

use crate::args::ScanOptions;
use crate::vendor::Vendor;
use crate::utils;
use crate::args::ScanTiming;

pub const DATALINK_RCV_TIMEOUT: u64 = 500;

const VLAN_QOS_DEFAULT: u8 = 1;
const ARP_PACKET_SIZE: usize = 28;
const VLAN_PACKET_SIZE: usize = 32;

const ETHERNET_STD_PACKET_SIZE: usize = 42;
const ETHERNET_VLAN_PACKET_SIZE: usize = 46;

/**
 * Contains scan estimation records. This will be computed before the scan
 * starts and should give insights about the scan.
 */
pub struct ScanEstimation {
    pub interval_ms: u64,
    pub duration_ms: u128,
    pub request_size: u128,
    pub bandwidth: u128
}

/**
 * Gives high-level details about the scan response. This may include Ethernet
 * details (packet count, size, ...) and other technical network aspects.
 */
pub struct ResponseSummary {
    pub packet_count: usize,
    pub arp_count: usize,
    pub duration_ms: u128
}

/**
 * A target detail represents a single host on the local network with an IPv4
 * address and a linked MAC address. Hostnames are optional since some hosts
 * does not respond to the resolve call (or the numeric mode may be enabled).
 */
pub struct TargetDetails {
    pub ipv4: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub vendor: Option<String>
}

/**
 * Compute a network configuration based on the scan options and available
 * interfaces. This configuration will be used in the scan process to target a
 * specific network on a network interfaces.
 */
pub fn compute_network_configuration<'a>(interfaces: &'a [NetworkInterface], scan_options: &'a Arc<ScanOptions>) -> (&'a NetworkInterface, Vec<&'a IpNetwork>) {

    let interface_name = match &scan_options.interface_name {
        Some(name) => String::from(name),
        None => {

            let name = utils::select_default_interface(interfaces).map(|interface| interface.name);

            match name {
                Some(name) => name,
                None => {
                    eprintln!("Could not find a default network interface");
                    eprintln!("Use 'arp scan -l' to list available interfaces");
                    process::exit(1);
                }
            }
        }
    };

    let selected_interface: &NetworkInterface = interfaces.iter()
        .find(|interface| { interface.name == interface_name && interface.is_up() && !interface.is_loopback() })
        .unwrap_or_else(|| {
            eprintln!("Could not find interface with name {}", interface_name);
            eprintln!("Make sure the interface is up, not loopback and has a valid IPv4");
            process::exit(1);
        });

    let ip_networks: Vec<&IpNetwork> = match &scan_options.network_range {
        Some(network_range) => network_range.iter().collect(),
        None => selected_interface.ips.iter()
            .filter(|ip_network| ip_network.is_ipv4())
            .collect()
    };

    (selected_interface, ip_networks)
}

/**
 * Based on the network size and given scan options, this function performs an
 * estimation of the scan impact (timing, bandwidth, ...). Keep in mind that
 * this is only an estimation, real results may vary based on the network.
 */
pub fn compute_scan_estimation(host_count: u128, options: &Arc<ScanOptions>) -> ScanEstimation {

    let timeout: u128 = options.timeout_ms.into();
    let packet_size: u128 = match options.has_vlan() {
        true => ETHERNET_VLAN_PACKET_SIZE.try_into().expect("Internal number conversion failed for VLAN packet size"),
        false => ETHERNET_STD_PACKET_SIZE.try_into().expect("Internal number conversion failed for Ethernet packet size")
    };
    let retry_count: u128 = options.retry_count.try_into().unwrap_or_else(|err| {
        eprintln!("[warn] Could not cast retry count, defaults to 1 - {}", err);
        1
    });

    // The values below are averages based on an amount of performed network
    // scans. This may of course vary based on network configurations.
    let avg_arp_request_ms: u128 = 3;
    let avg_resolve_ms = 500;

    let request_size: u128 = host_count * packet_size;

    // Either the user provides an interval (expressed in milliseconds), either
    // he provides a bandwidth (in bits per second) or either we are using the
    // default interval. The goal of the code below is to compute the interval
    // & bandwidth, based on the given inputs. Note that the computations in
    // each match arm are therefore linked (but rewritten, based on the inputs).
    let (interval_ms, bandwidth, request_phase_ms): (u64, u128, u128) = match options.scan_timing {
        ScanTiming::Bandwidth(bandwidth) => {

            let bandwidth_lg: u128 = bandwidth.into();
            let request_phase_ms: u128 = (request_size * 1000) as u128 / bandwidth_lg;
            let interval_ms: u128 = (request_phase_ms/retry_count/host_count) - avg_arp_request_ms;
            
            (interval_ms.try_into().unwrap(), bandwidth_lg, request_phase_ms)

        },
        ScanTiming::Interval(interval) => {

            let interval_ms_lg: u128 = interval.into();
            let request_phase_ms: u128 = (host_count * (avg_arp_request_ms + interval_ms_lg)) * retry_count;
            let bandwidth = (request_size * 1000) / request_phase_ms;

            (interval, bandwidth, request_phase_ms)
        }
    };
    
    let duration_ms = request_phase_ms + timeout + avg_resolve_ms;

    ScanEstimation {
        interval_ms,
        duration_ms,
        request_size,
        bandwidth
    }
}

/**
 * Send a single ARP request - using a datalink-layer sender, a given network
 * interface and a target IPv4 address. The ARP request will be broadcasted to
 * the whole local network with the first valid IPv4 address on the interface.
 */
pub fn send_arp_request(tx: &mut Box<dyn DataLinkSender>, interface: &NetworkInterface, source_ip: Ipv4Addr, target_ip: Ipv4Addr, options: Arc<ScanOptions>) {

    let mut ethernet_buffer = match options.has_vlan() {
        true => vec![0u8; ETHERNET_VLAN_PACKET_SIZE],
        false => vec![0u8; ETHERNET_STD_PACKET_SIZE]
    };
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap_or_else(|| {
        eprintln!("Could not build Ethernet packet");
        process::exit(1);
    });

    let target_mac = match options.destination_mac {
        Some(forced_mac) => forced_mac,
        None => MacAddr::broadcast()
    };
    let source_mac = match options.source_mac {
        Some(forced_source_mac) => forced_source_mac,
        None => interface.mac.unwrap_or_else(|| {
            eprintln!("Interface should have a MAC address");
            process::exit(1);
        })
    };

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);

    let selected_ethertype = match options.vlan_id {
        Some(_) => EtherTypes::Vlan,
        None => EtherTypes::Arp
    };
    ethernet_packet.set_ethertype(selected_ethertype);

    let mut arp_buffer = [0u8; ARP_PACKET_SIZE];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap_or_else(|| {
        eprintln!("Could not build ARP packet");
        process::exit(1);
    });

    arp_packet.set_hardware_type(options.hw_type.unwrap_or(ArpHardwareTypes::Ethernet));
    arp_packet.set_protocol_type(options.proto_type.unwrap_or(EtherTypes::Ipv4));
    arp_packet.set_hw_addr_len(options.hw_addr.unwrap_or(6));
    arp_packet.set_proto_addr_len(options.proto_addr.unwrap_or(4));
    arp_packet.set_operation(options.arp_operation.unwrap_or(ArpOperations::Request));
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    if let Some(vlan_id) = options.vlan_id {

        let mut vlan_buffer = [0u8; VLAN_PACKET_SIZE];
        let mut vlan_packet = MutableVlanPacket::new(&mut vlan_buffer).unwrap_or_else(|| {
            eprintln!("Could not build VLAN packet");
            process::exit(1);
        });
        vlan_packet.set_vlan_identifier(vlan_id);
        vlan_packet.set_priority_code_point(ClassOfService::new(VLAN_QOS_DEFAULT));
        vlan_packet.set_drop_eligible_indicator(0);
        vlan_packet.set_ethertype(EtherTypes::Arp);

        vlan_packet.set_payload(arp_packet.packet_mut());

        ethernet_packet.set_payload(vlan_packet.packet_mut());
    }
    else {
        ethernet_packet.set_payload(arp_packet.packet_mut());
    }

    tx.send_to(ethernet_packet.to_immutable().packet(), Some(interface.clone()));
}

/**
 * A network iterator for iterating over multiple network ranges in with a
 * low-memory approach. This iterator was crafted to allow iteration over huge
 * network ranges (192.168.0.0/16) without consuming excessive memory.
 */
pub struct NetworkIterator {
    current_iterator: Option<ipnetwork::IpNetworkIterator>,
    networks: Vec<IpNetwork>,
    is_random: bool,
    random_pool: Vec<IpAddr>
}

impl NetworkIterator {

    pub fn new(networks_ref: &[&IpNetwork], is_random: bool) -> NetworkIterator {

        // The IpNetwork struct implements the Clone trait, which means that a simple
        // dereference will clone the struct in the new vector
        let mut networks: Vec<IpNetwork> = networks_ref.iter().map(|network| *(*network)).collect();

        if is_random {
            let mut rng = rand::thread_rng();
            networks.shuffle(&mut rng);
        }

        NetworkIterator {
            current_iterator: None,
            networks,
            is_random,
            random_pool: vec![]
        }
    }

    /**
     * The functions below are not public and only used by the Iterator trait
     * to help keep the next() code clean.
     */

    fn has_no_items_left(&self) -> bool {
        self.current_iterator.is_none() && self.networks.is_empty() && self.random_pool.is_empty()
    }

    fn fill_random_pool(&mut self) {

        for _ in 0..1000 {

            let next_ip = self.current_iterator.as_mut().unwrap().next();
            if next_ip.is_none() {
                break;
            }

            self.random_pool.push(next_ip.unwrap());
        }

        let mut rng = rand::thread_rng();
        self.random_pool.shuffle(&mut rng);
    }

    fn select_new_iterator(&mut self) {

        self.current_iterator = Some(self.networks.remove(0).iter());
    }

    fn pop_next_iterator_address(&mut self) -> Option<IpAddr> {

        self.current_iterator.as_mut().map(|iterator| iterator.next()).unwrap_or(None)
    }

}

impl Iterator for NetworkIterator {

    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {

        if self.has_no_items_left() {
            return None;
        }

        if self.current_iterator.is_none() && !self.networks.is_empty() {
            self.select_new_iterator();
        }

        if self.is_random && self.random_pool.is_empty() {
            self.fill_random_pool();
        }

        let next_ip = match self.is_random {
            true => self.random_pool.pop(),
            false => self.pop_next_iterator_address()
        };

        if next_ip.is_none() && !self.networks.is_empty() {
            self.select_new_iterator();
            return self.pop_next_iterator_address();
        }

        next_ip
    }
}

/**
 * Find the most adequate IPv4 address on a given network interface for sending
 * ARP requests. If the 'forced_source_ipv4' parameter is set, it will take
 * the priority over the network interface address.
 */
pub fn find_source_ip(network_interface: &NetworkInterface, forced_source_ipv4: Option<Ipv4Addr>) -> Ipv4Addr {

    if let Some(forced_ipv4) = forced_source_ipv4 {
        return forced_ipv4;
    }

    let potential_network = network_interface.ips.iter().find(|network| network.is_ipv4());
    match potential_network.map(|network| network.ip()) {
        Some(IpAddr::V4(ipv4_addr)) => ipv4_addr,
        _ => {
            eprintln!("Expected IPv4 address on network interface");
            process::exit(1);
        }
    }
}

/**
 * Wait at least N seconds and receive ARP network responses. The main
 * downside of this function is the blocking nature of the datalink receiver:
 * when the N seconds are elapsed, the receiver loop will therefore only stop
 * on the next received frame. Therefore, the receiver should have been
 * configured to stop at certain intervals (500ms for example).
 */
pub fn receive_arp_responses(rx: &mut Box<dyn DataLinkReceiver>, options: Arc<ScanOptions>, timed_out: Arc<AtomicBool>, vendor_list: &mut Vendor) -> (ResponseSummary, Vec<TargetDetails>) {

    let mut discover_map: HashMap<Ipv4Addr, TargetDetails> = HashMap::new();
    let start_recording = Instant::now();

    let mut packet_count = 0;
    let mut arp_count = 0;

    loop {

        if timed_out.load(Ordering::Relaxed) {
            break;
        }

        let arp_buffer = match rx.next() {
            Ok(buffer) => buffer,
            Err(error) => {
                match error.kind() {
                    // The 'next' call will only block the thread for a given
                    // amount of microseconds. The goal is to avoid long blocks
                    // due to the lack of packets received.
                    TimedOut => continue,
                    _ => {
                        eprintln!("Failed to receive ARP requests ({})", error);
                        process::exit(1);
                    }
                };
            }
        };
        packet_count += 1;
        
        let ethernet_packet = match EthernetPacket::new(arp_buffer) {
            Some(packet) => packet,
            None => continue
        };

        let is_arp_type = matches!(ethernet_packet.get_ethertype(), EtherTypes::Arp);
        if !is_arp_type {
            continue;
        }

        let arp_packet = ArpPacket::new(&arp_buffer[MutableEthernetPacket::minimum_packet_size()..]);
        arp_count += 1;

        // If we found an ARP packet, extract the details and add the essential
        // fields in the discover map. Please note that results are grouped by
        // IPv4 address - which means that a MAC change will appear as two
        // separete records in the result table.
        if let Some(arp) = arp_packet {

            let sender_ipv4 = arp.get_sender_proto_addr();
            let sender_mac = arp.get_sender_hw_addr();
    
            discover_map.insert(sender_ipv4, TargetDetails {
                ipv4: sender_ipv4,
                mac: sender_mac,
                hostname: None,
                vendor: None
            });
        }
    }

    // For each target found, enhance each item with additional results
    // results such as the hostname & MAC vendor.
    let target_details = discover_map.into_iter().map(|(_, mut target_detail)| {

        if options.resolve_hostname {
            target_detail.hostname = find_hostname(target_detail.ipv4);
        }

        if vendor_list.has_vendor_db() {
            target_detail.vendor = vendor_list.search_by_mac(&target_detail.mac);
        }

        target_detail

    }).collect();

    // The response summary can be used to display analytics related to the
    // performed ARP scans (packet counts, timings, ...)
    let response_summary = ResponseSummary {
        packet_count,
        arp_count,
        duration_ms: start_recording.elapsed().as_millis()
    };
    (response_summary, target_details)
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
            if hostname.parse::<IpAddr>().is_ok() {
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

    use ipnetwork::Ipv4Network;
    use std::env;

    #[test]
    fn should_resolve_public_ip() {

        // Sometimes, we do not have access to public networks in the test
        // environment and can pass the OFFLINE environment variable.
        if env::var("OFFLINE").is_ok() {
            assert_eq!(true, true);
        }
        else {
            let ipv4 = Ipv4Addr::new(1,1,1,1);
            assert_eq!(find_hostname(ipv4), Some("one.one.one.one".to_string()));
        }
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

    #[test]
    fn should_iterate_over_empty_networks() {

        let mut iterator = NetworkIterator::new(&vec![], false);

        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn should_iterate_over_single_address() {

        let network_a = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()
        );
        let target_network: Vec<&IpNetwork> = vec![
            &network_a
        ];

        let mut iterator = NetworkIterator::new(&target_network, false);

        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn should_iterate_over_multiple_address() {

        let network_a = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()
        );
        let target_network: Vec<&IpNetwork> = vec![
            &network_a
        ];

        let mut iterator = NetworkIterator::new(&target_network, false);

        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));
        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn should_iterate_over_multiple_networks() {

        let network_a = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()
        );
        let network_b = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 20, 20), 32).unwrap()
        );
        let target_network: Vec<&IpNetwork> = vec![
            &network_a,
            &network_b
        ];

        let mut iterator = NetworkIterator::new(&target_network, false);

        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(iterator.next(), Some(IpAddr::V4(Ipv4Addr::new(10, 10, 20, 20))));
        assert_eq!(iterator.next(), None);
    }

    #[test]
    fn should_iterate_with_random() {

        let network_a = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()
        );
        let network_b = IpNetwork::V4(
            Ipv4Network::new(Ipv4Addr::new(10, 10, 20, 20), 32).unwrap()
        );
        let target_network: Vec<&IpNetwork> = vec![
            &network_a,
            &network_b
        ];

        let mut iterator = NetworkIterator::new(&target_network, true);

        assert_eq!(iterator.next().is_some(), true);
        assert_eq!(iterator.next().is_some(), true);
        assert_eq!(iterator.next(), None);
    }

}
