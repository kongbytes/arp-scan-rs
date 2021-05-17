# ARP scanner CLI

[![Build Status](https://saluki.semaphoreci.com/badges/arp-scan-rs/branches/master.svg?style=shields)](https://saluki.semaphoreci.com/projects/arp-scan-rs)
[![dependency status](https://deps.rs/repo/github/Saluki/arp-scan-rs/status.svg)](https://deps.rs/repo/github/Saluki/arp-scan-rs)

Find all hosts in your local network using this fast ARP scanner. The CLI is written in Rust and provides a minimal scanner that finds all hosts using the ARP protocol. Inspired by the awesome [arp-scan project](https://github.com/royhills/arp-scan).

## Gettings started

Download the `arp-scan` binary for Linux.

```bash
wget -O arp-scan https://github.com/Saluki/arp-scan-rs/releases/download/v0.2.0/arp-scan-v0.2.0-x86_64-unknown-linux-musl

chmod +x arp-scan
```

List all available network interfaces.

```bash
./arp-scan -l
```

Launch a scan on interface `wlp1s0`.

```bash
./arp-scan -i wlp1s0
```

Enhance the scan timeout to 15 seconds (by default, 5 seconds).

```bash
./arp-scan -i wlp1s0 -t 15
```

## Options

### Get help `-h`

Display the main help message with all commands and available ARP scan options.

### List interfaces `-l`

List all available network interfaces. Using this option will only print a list of interfaces and exit the process.

### Select interface `-i eth0`

Perform a scan on the network interface `eth0`. The first valid IPv4 network on this interface will be used as scan target.

### Set timeout `-t 15`

Enforce a timeout of at least 15 seconds. This timeout is a minimum value (scans may take a little more time). Default value is `5`.

### Numeric mode `-n`

Switch to numeric mode. This will skip the local hostname resolution process and will only display IP addresses.

### Show version `-n`

Display the ARP scan CLI version and exits the process.

## Contributing

Feel free to suggest an improvement, report a bug, or ask something: https://github.com/saluki/arp-scan-rs/issues
