# raw-sniffer

A simple network packet sniffer written in Rust. Captures raw Ethernet frames and prints their bytes in hexadecimal to stdout.

## How it works

Opens a raw `AF_PACKET` socket that receives every Ethernet frame passing through the network interface. Each captured packet is printed as a line of hex bytes. Press `Ctrl+C` to stop.

## Requirements

- Linux (raw sockets are Linux-only)
- Root privileges (`sudo`)
- Rust toolchain ([install via rustup](https://rustup.rs))

## Dependencies

```toml
[dependencies]
libc = "0.2"
ctrlc = "3"
```

## Build & run

```bash
cargo build --release
sudo ./target/release/raw-sniffer
```

You must run with `sudo` because opening a raw socket requires root.

## Example output

```
ff ff ff ff ff ff 00 1a 2b 3c 4d 5e 08 00 45 00 ...
00 50 00 01 40 00 40 06 ...
```

Each line is one packet. Bytes are space-separated hex values.

## Stop

```
Ctrl+C
```

The program catches the signal, prints `Завершение работы...` ("Shutting down..."), and closes the socket cleanly.

## Limitations

- Prints raw bytes only — no protocol parsing (no Ethernet/IP/TCP headers decoded)
- Captures all traffic on all interfaces (no filter)
- Requires Linux; does not work on macOS or Windows
