# raw-sniffer

A lightweight network packet sniffer written in Rust. Captures raw Ethernet frames directly from a network interface, decodes their headers, and prints a structured summary to stdout.

## Features

- **Raw socket capture** — opens an `AF_PACKET` socket to intercept every Ethernet frame on the wire
- **Promiscuous mode** — receives traffic not addressed to the host interface
- **Ethernet header parsing** — extracts source/destination MAC addresses and EtherType
- **IPv4 decoding** — resolves source/destination IP addresses and detects the transport protocol
- **Transport layer detection** — identifies TCP, UDP, ICMP, IGMP, and other IP protocols
- **Port extraction** — shows source/destination ports for TCP and UDP packets
- **Graceful shutdown** — catches `Ctrl+C` and closes the socket cleanly

## How it works

```
Ethernet frame
└── MAC src / MAC dst / EtherType
    └── IPv4 (0x0800)
        ├── src IP : src port → dst IP : dst port
        └── Protocol: TCP / UDP / ICMP / IGMP / ...
    └── ARP  (0x0806)
    └── IPv6 (0x86DD)
```

The program opens a raw `AF_PACKET / SOCK_RAW` socket, enables promiscuous mode via `setsockopt`, then enters a receive loop. Each captured packet is passed through `parse_ethernet` → `parse_ipv4`, and a one-line summary is printed per packet.

## Requirements

| Requirement | Notes |
|---|---|
| OS | Linux only (raw `AF_PACKET` sockets are Linux-specific) |
| Privileges | Must run as `root` or with `CAP_NET_RAW` |
| Rust toolchain | Install via [rustup](https://rustup.rs) |

## Dependencies

```toml
[dependencies]
libc  = "0.2"
ctrlc = "3"
```

## Configuration

You can list available interfaces with:

```bash
ip link show
```

## Build & run

```bash
cargo build --release
sudo ./target/release/raw-sniffer <network interface>

# Example:
sudo ./target/release/raw-sniffer eth0
```

## Example output

```
DST: ff:ff:ff:ff:ff:ff -> SRC: 00:1a:2b:3c:4d:5e | IPv4: 192.168.1.5:56891 -> 192.168.1.1:53 | UDP
DST: 00:1a:2b:3c:4d:5e -> SRC: 00:aa:bb:cc:dd:ee | IPv4: 93.184.216.34:443 -> 192.168.1.5:51200 | TCP
DST: ff:ff:ff:ff:ff:ff -> SRC: 00:11:22:33:44:55 | ARP
```

Each line represents one captured frame:
- **DST / SRC** — destination and source MAC addresses
- **EtherType payload** — IPv4 with IPs and ports, ARP, IPv6, or unknown type
- **Protocol** — TCP, UDP, ICMP, IGMP, etc. (for IPv4 frames)

## Stop

Press `Ctrl+C`. The program prints `Completing work...` and exits, closing the socket cleanly.

## Project structure

```
src/
├── main.rs               # Socket setup, receive loop, Ethernet/IPv4 parsing
└── promiscuous_mode.rs   # setsockopt wrapper for PACKET_MR_PROMISC
```

## Limitations

- IPv6 frames are detected but not decoded
- No BPF filtering — captures all traffic on the interface
- Linux only; does not work on macOS or Windows