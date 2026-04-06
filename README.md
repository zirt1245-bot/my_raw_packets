# raw-sniffer

A lightweight network packet sniffer written in Rust. Captures raw Ethernet frames directly from a network interface, decodes headers, and prints a structured, colorized summary to stdout.

## Features

- **Raw socket capture** — opens an `AF_PACKET` socket to intercept every Ethernet frame on the wire.
- **Promiscuous mode** — receives traffic not addressed to the host interface.
- **Advanced Filtering** — filter **in** or **out** (exclude) traffic by protocol, port, or IP address.
- **Organization Detection** — automatically identifies traffic from known services like **Google**, **Telegram**, **YouTube**, and **Local Networks**.
- **Visual Feedback** — colorized output for better readability:
    - **Green**: Local IP addresses.
    - **Red**: External (Internet) IP addresses.
    - **Blue/Cyan/Purple**: Different transport protocols and TCP flags.
- **TCP State Analysis** — displays flags (SYN, ACK, FIN, RST) to monitor connection states.
- **Service Recognition** — identifies common UDP services like DNS, NTP, DHCP, and mDNS.

## How it works



The program opens a raw `AF_PACKET / SOCK_RAW` socket and enables promiscuous mode via `setsockopt`. It then enters a loop where:
1. `recvfrom` captures the raw byte stream.
2. `parse_ethernet` extracts MAC addresses.
3. `parse_ipv4` (if applicable) decodes IPs, ports, and detects the organization based on IP ranges.
4. User-defined filters are applied to decide whether to print the packet summary.

## Requirements

| Requirement | Notes |
|---|---|
| OS | Linux only (uses `AF_PACKET`) |
| Privileges | Must run as `root` or with `CAP_NET_RAW` |
| Dependencies | `libc`, `ctrlc`, `clap`, `colored` |

## Usage

```bash
sudo ./target/release/raw-sniffer <INTERFACE> [OPTIONS]
```

### Filtering Options

You can now use multiple filters and exclusions simultaneously.

| Option | Description |
|---|---|
| `--proto <PROTO>` | Include specific protocols (tcp, udp, icmp, arp, ipv6) |
| `--exc-proto <PROTO>`| **Exclude** specific protocols |
| `--port <PORT>` | Include specific port numbers |
| `--exc-port <PORT>` | **Exclude** specific port numbers |
| `--ip <IP>` | Include specific IP addresses |
| `--exc-ip <IP>` | **Exclude** specific IP addresses |
| `--no-mac` | Hide MAC addresses for a cleaner view |

### Examples

```bash
# Capture everything except local network noise (IGMP)
sudo ./target/release/raw-sniffer eth0 --exc-proto igmp

# Monitor only HTTPS traffic but ignore a specific local IP
sudo ./target/release/raw-sniffer eth0 --port 443 --exc-ip 192.168.1.10

# Hide MAC addresses and focus on Telegram traffic
sudo ./target/release/raw-sniffer eth0 --ip 149.154. --no-mac
```

## Example output

```text
DST: ff:ff:ff:ff:ff:ff -> SRC: 00:1a:2b:3c:4d:5e | IPv4: 192.168.1.5:56891 [Local Network] -> 8.8.8.8:53 [Google] | UDP: [DNS]
DST: 00:1a:2b:3c:4d:5e -> SRC: 00:aa:bb:cc:dd:ee | IPv4: 149.154.167.51:443 [Telegram] -> 192.168.1.5:51200 [Local Network] | TCP: ACK
```

## Project structure

```text
src/
├── main.rs               # Entry point, CLI parsing, and main capture loop
├── filters.rs            # Data structures for packet filtering logic
├── parser.rs             # Protocol decoding (Ethernet, IPv4, TCP, UDP, ARP)
└── promiscuous_mode.rs   # Low-level Linux socket configuration
```