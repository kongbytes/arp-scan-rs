use ipnetwork::IpNetwork;
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use std::net::Ipv4Addr;

pub enum OutputFormat {
    Plain,
    Json,
    Yaml,
    Csv,
}

pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos,
}

pub enum ScanTiming {
    Interval(u64),
    Bandwidth(u64),
}

pub struct ScanOptions {
    pub interface_name: Option<String>,
    pub interface_index: Option<u32>,
    pub network_range: Option<Vec<IpNetwork>>,
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
    pub fn is_plain_output(&self) -> bool {
        matches!(&self.output, OutputFormat::Plain)
    }

    pub fn has_vlan(&self) -> bool {
        self.vlan_id.is_some()
    }

    pub fn request_protocol_print(&self) -> bool {
        self.packet_help
    }
}
