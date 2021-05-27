# ARP scanner CLI

[![Build Status](https://saluki.semaphoreci.com/badges/arp-scan-rs/branches/master.svg?style=shields)](https://saluki.semaphoreci.com/projects/arp-scan-rs)
[![dependency status](https://deps.rs/repo/github/Saluki/arp-scan-rs/status.svg)](https://deps.rs/repo/github/Saluki/arp-scan-rs)

Find all hosts in your local network using this fast ARP scanner. The CLI is written in Rust and provides a minimal scanner that finds all hosts using the ARP protocol. Inspired by the awesome [arp-scan project](https://github.com/royhills/arp-scan).

:heavy_check_mark: Minimal Rust binary

:heavy_check_mark: Fast ARP scans

:heavy_check_mark: Scan customization (timeout, interface, DNS, ...)

:heavy_check_mark: Force ARP source IP

## Getting started

Download the `arp-scan` binary for Linux (Ubuntu, Fedora, Debian, ...). See the [releases page](https://github.com/Saluki/arp-scan-rs/releases) for other binaries.

```bash
wget -O arp-scan https://github.com/Saluki/arp-scan-rs/releases/download/v0.7.0/arp-scan-v0.7.0-x86_64-unknown-linux-musl && chmod +x ./arp-scan
```

List all available network interfaces.

```bash
./arp-scan -l
```

Launch a scan on interface `wlp1s0`.

```bash
./arp-scan -i wlp1s0
```

Enhance the minimum scan timeout to 5 seconds (by default, 2 seconds).

```bash
./arp-scan -i wlp1s0 -t 5
```

Perform an ARP scan on the default network interface, VLAN 45 and JSON output.

```bash
./arp-scan -Q 45 -o json
```

## Options

#### Get help `-h`

Display the main help message with all commands and available ARP scan options.

#### List interfaces `-l`

List all available network interfaces. Using this option will only print a list of interfaces and exit the process.

#### Select interface `-i eth0`

Perform a scan on the network interface `eth0`. The first valid IPv4 network on this interface will be used as scan target. By default, the first network interface with an `up` status and a valid IPv4 will be selected.

#### Set global scan timeout `-t 15`

Enforce a timeout of at least 15 seconds. This timeout is a minimum value (scans may take a little more time). Default value is `2`.

#### Numeric mode `-n`

Switch to numeric mode. This will skip the local hostname resolution process and will only display IP addresses.

#### Host retry count `-r 3`

Send 3 ARP requests to the targets (retry count). By default, a single ARP request will be sent to each host.

#### Change source IPv4 `-S 192.168.1.130`

Change or force the IPv4 address sent as source in the broadcasted ARP packets. By default, a valid IPv4 address on the network interface will be used. This option may be useful for isolated hosts and security checks.

#### Change destination MAC `-M 55:44:33:22:11:00`

Change or force the MAC address sent as destination ARP request. By default, a broadcast destination (`00:00:00:00:00:00`) will be set.

#### Randomize target list `-R`

Randomize the IPv4 target list before sending ARP requests. By default, all ARP requests are sent in ascending order by IPv4 address.

#### Set VLAN ID `-Q 540`

Add a 802.1Q field in the Ethernet frame. This fields contains the given VLAN ID for outgoing ARP requests. By default, the Ethernet frame is sent without 802.1Q fields (no VLAN).

#### Set output format `-o json`

Set the output format to either `plain` (a full-text output with tables), `json` or `yaml`.

#### Show version `--version`

Display the ARP scan CLI version and exits the process.

## Roadmap

The features below will be shipped in the next releases of the project.

- Make ARP scans faster
    - with a per-host retry approach
    - by closing the response thread faster
- Scan profiles (standard, attacker, light, ...)
- Complete VLAN support
- ~~Exports (JSON & YAML)~~ - released in 0.7.0
- Full ARP packet customization (Ethernet protocol, ARP operation, ...)
- MAC vendor lookup in the results
- Fine-grained scan timings (interval, ...)
- Wide network range support

## Contributing

Feel free to suggest an improvement, report a bug, or ask something: https://github.com/saluki/arp-scan-rs/issues
