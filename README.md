# ARP scanner CLI

[![Build Status](https://saluki.semaphoreci.com/badges/arp-scan-rs/branches/master.svg?style=shields)](https://saluki.semaphoreci.com/projects/arp-scan-rs)
[![dependency status](https://deps.rs/repo/github/Saluki/arp-scan-rs/status.svg)](https://deps.rs/repo/github/Saluki/arp-scan-rs)
![crates.io](https://img.shields.io/crates/v/arp-scan.svg)

Find all hosts in your local network using this fast ARP scanner. The CLI is written in Rust and provides a minimal scanner that finds all hosts using the ARP protocol. Inspired by the awesome [arp-scan project](https://github.com/royhills/arp-scan).

✔ Minimal Rust binary & fast ARP scans

✔ Scan customization (ARP, timings, interface, DNS, ...)

✔ MAC vendor search

✔ JSON, YAML & CSV exports

✔ Pre-defined scan profiles (default, fast, stealth & chaos)

## Examples

Start by listing all network interfaces on the host.

```bash
# List all network interfaces
$ arp-scan -l

lo                   ✔ UP      00:00:00:00:00:00    127.0.0.1/8
enp3s0f0             ✔ UP      4f:6e:cd:78:bb:5a    
enp4s0               ✖ DOWN    d0:c5:e9:40:00:4a    
wlp1s0               ✔ UP      d2:71:d8:29:a8:72    192.168.1.21/24
docker0              ✔ UP      49:fd:cd:60:73:77    172.17.0.1/16
br-fa6dc54a91ee      ✔ UP      61:ab:c1:a7:50:79    172.18.0.1/16

Found 6 network interfaces, 5 seems up for ARP scan
Default network interface will be wlp1s0

```

Perform a default ARP scan on the local network with safe defaults.

```bash
# Perform a scan on the default network interface
$ arp-scan

Selected interface wlp1s0 with IP 192.168.1.21/24
Estimated scan time 2068ms (10752 bytes, 14000 bytes/s)
Sending 256 ARP requests (waiting at least 800ms, 0ms request interval)

| IPv4            | MAC               | Hostname     | Vendor       |
|-----------------|-------------------|--------------|--------------|
| 192.168.1.1     | 91:10:fb:30:06:04 | router.home  | Vendor, Inc. |
| 192.168.1.11    | 45:2e:99:bc:22:b6 | host-a.home  |              |
| 192.168.1.15    | bc:03:c2:92:47:df | host-b.home  | Vendor, Inc. |
| 192.168.1.18    | 8d:eb:56:17:b8:e1 | host-c.home  | Vendor, Inc. |
| 192.168.1.34    | 35:e0:6c:1e:e3:fe |              | Vendor, Inc. |

ARP scan finished, 5 hosts found in 1.623 seconds
7 packets received, 5 ARP packets filtered

```

## Getting started

Download the `arp-scan` binary for Linux (Ubuntu, Fedora, Debian, ...). See the [releases page](https://github.com/Saluki/arp-scan-rs/releases) for other binaries.

```bash
wget -O arp-scan https://github.com/Saluki/arp-scan-rs/releases/download/v0.13.0/arp-scan-v0.13.0-x86_64-unknown-linux-musl && chmod +x ./arp-scan
```

Optionnaly, fetch the IEEE OUI reference file (CSV format) that contains all MAC address vendors.

```bash
wget -O /usr/share/arp-scan/ieee-oui.csv http://standards-oui.ieee.org/oui/oui.csv
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
./arp-scan -i wlp1s0 -t 5s
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

#### Select scan profile `-p stealth`

A scan profile groups together a set of ARP scan options to perform a specific scan. The scan profiles are listed below:

- `default` : default option, this is enabled if the `-p` option is not used
- `fast` : fast ARP scans, the results may be less accurate
- `stealth` : slower scans that minimize the network impact
- `chaos` : randomly-selected values for the ARP scan

#### Select interface `-i eth0`

Perform a scan on the network interface `eth0`. The first valid IPv4 network on this interface will be used as scan target. By default, the first network interface with an `up` status and a valid IPv4 will be selected.

#### Set IPv4 network range `-n 172.17.0.0/24`

By default, the scan process will select the first IPv4 network on the interface and start a scan on the whole range. With the `--network` option, an IPv4 network can be defined _(this may be used for specific scans on a subset of network targets)_.

#### Set global scan timeout `-t 15s`

Enforce a timeout of at least 15 seconds. This timeout is a minimum value (scans may take a little more time). Default value is `2000ms`.

#### Change ARP request interval `-I 39ms`

By default, a `10ms` gap will be set between ARP requests to avoid an ARP storm on the network. This value can be changed to reduce or increase the milliseconds between each ARP request.

#### Enforce scan bandwidth limit `-B 1000`

Enforce a bandwidth limit (expressed in bits per second) on ARP scans. The `--bandwidth` option conflicts with `--interval` since these 2 arguments change the same parameter underneath.

#### Numeric mode `--numeric`

Switch to numeric mode. This will skip the local hostname resolution process and will only display IP addresses.

#### Host retry count `-r 3`

Send 3 ARP requests to the targets (retry count). By default, a single ARP request will be sent to each host.

#### Change source IPv4 `-S 192.168.1.130`

Change or force the IPv4 address sent as source in the broadcasted ARP packets. By default, a valid IPv4 address on the network interface will be used. This option may be useful for isolated hosts and security checks.

#### Change destination MAC `-M 55:44:33:22:11:00`

Change or force the MAC address sent as destination ARP request. By default, a broadcast destination (`00:00:00:00:00:00`) will be set.

#### Change source MAC `-M 11:24:71:29:21:76`

Change or force the MAC address sent as source in the ARP request. By default, the network interface MAC will be used.

#### Randomize target list `-R`

Randomize the IPv4 target list before sending ARP requests. By default, all ARP requests are sent in ascending order by IPv4 address.

#### Use custom MAC OUI file `--oui-file ./my-file.csv`

Use a [custom OUI MAC file](http://standards-oui.ieee.org/oui/oui.csv), the default path will be set to `/usr/share/arp-scan/ieee-oui.csv"`.

#### Set VLAN ID `-Q 42`

Add a 802.1Q field in the Ethernet frame. This fields contains the given VLAN ID for outgoing ARP requests. By default, the Ethernet frame is sent without 802.1Q fields (no VLAN).

#### Customize ARP operation ID `--arp-op 1`

Change the ARP protocol operation field, this can cause scan failure.

#### Customize ARP hardware type `--hw-type 1`

Change the ARP hardware type field, this can cause scan failure.

#### Customize ARP hardware address length `--hw-addr 6`

Change the ARP hardware address length field, this can cause scan failure.

#### Customize ARP protocol type `--proto-type 2048`

Change the ARP protocol type field, this can cause scan failure.

#### Customize ARP protocol adress length `--proto-addr 4`

Change the ARP protocol address length field, this can cause scan failure.

#### Set output format `-o json`

Set the output format to either `plain` (a full-text output with tables), `json`, `yaml` or `csv`.

#### Show version `--version`

Display the ARP scan CLI version and exits the process.

## Roadmap & features

The features below will be shipped in the next releases of the project.

- Make ARP scans faster
    - with a per-host retry approach
    - add a back-off factor for retries
    - ~~by closing the response thread faster~~  - released in 0.8.0
- ~~Scan profiles (standard, attacker, light, ...)~~ - released in 0.10.0
- Complete VLAN support
- ~~Exports (JSON & YAML)~~ - released in 0.7.0
- ~~Full ARP packet customization (Ethernet protocol, ARP operation, ...)~~ - released in 0.10.0
- ~~Time estimations & bandwidth~~ - released in 0.10.0
- ~~MAC vendor lookup in the results~~ - released in 0.9.0
- ~~Fine-grained scan timings (interval)~~ - released in 0.8.0
- ~~Wide network range support~~ - released in 0.13.0
- ~~Partial results on SIGINT~~ - released in 0.11.0
- ~~Read network targets from file~~ - released in 0.12.0
- Adding advanced packet options (padding, LLC, ...)
    - add padding bits after ARP payload
    - support RFC 1042 LLC framing with SNAP
- ~~Enable bandwith control (exclusive with interval)~~ - released in 0.12.0
- Stronger profile defaults (chaos & stealth)
- Other platforms (Windows, ...)
- Read targets from *stdout*
- Change verbose options (for debug, network details, quiet mode, ...)
- Avoid packet copy in userspace for faster scans (BPF filtering)

## Contributing

Feel free to suggest an improvement, report a bug, or ask something: https://github.com/saluki/arp-scan-rs/issues
