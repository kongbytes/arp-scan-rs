# ARP scanner CLI

[![Build Status](https://saluki.semaphoreci.com/badges/arp-scan-rs/branches/master.svg?style=shields)](https://saluki.semaphoreci.com/projects/arp-scan-rs)
[![dependency status](https://deps.rs/repo/github/Saluki/arp-scan-rs/status.svg)](https://deps.rs/repo/github/Saluki/arp-scan-rs)

Find all hosts in your local network using this fast ARP scanner. The CLI is written in Rust and provides a minimal scanner that finds all hosts using the ARP protocol. Inspired by the awesome [arp-scan project](https://github.com/royhills/arp-scan).

## Gettings started

List all available network interfaces.

```
arp-scan -l
```

Launch a scan on interface `wlp1s0`.

```
arp-scan -i wlp1s0
```

Enhance the scan timeout to 15 seconds (by default, 5 seconds).

```
arp-scan -i wlp1s0 -t 15
```