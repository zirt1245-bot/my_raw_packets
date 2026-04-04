use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, if_nametoindex, recvfrom, socket};
use promiscuous_mode::enable_promiscuous;
use std::{
    io::Error,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    ffi::CString,
};
use clap::Parser;

#[derive(Parser)]
#[command(name = "raw-sniffer", about = "Raw packet sniffer")]
struct Cli {
    /// Network interface to listen on (e.g. eth0, wlp0s20f3)
    interface: String,
    
    /// Filter by protocol: tcp, udp, icmp
    #[arg(long)]
    proto: Option<String>,
    
    /// Filter by port number
    #[arg(long)]
    port: Option<u16>,
}

mod promiscuous_mode;

fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_ethernet(buf: &[u8], proto_filter: &Option<String>, port_filter: &Option<u16>) {
    if buf.len() < 14 {
        println!("Invalid Ethernet");
    } else {
        let mac_dst = &buf[0..=5]; // собираем MAC получателя
        let mac_src = &buf[6..=11]; // собираем MAC отпавителя
        // MAC это адрес нашей физического интерфейса

        let str_dst_src = format!(
            "DST: {} -> SRC: {}",
            format_mac(mac_dst),
            format_mac(mac_src)
        );

        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        // тип вложенного протокола/распаковка пакета (для обработки интернета и других задач)

        let ethertype_name = match ethertype {
            0x0800 => {
                let ip_header = &buf[14..];
                let proto_code = ip_header[9];

                let proto_name = match proto_code {
                    6 => String::from("TCP"),
                    17 => String::from("UDP"),
                    1 => String::from("ICMP"),
                    2 => String::from("IGMP"),
                    _ => String::from("Other IP protocol"),
                };
                
                if let Some(filter) = proto_filter {
                    if filter.to_uppercase() != proto_name {
                        return;
                    }
                }
                
                if let Some(port) = port_filter {
                    let ipv4_info = parse_ipv4(ip_header);
                    if !ipv4_info.contains(&format!(":{}", port)) {
                        return;
                    }
                }

                format!("{} | {}", parse_ipv4(ip_header), proto_name)
            }
            0x86DD => {
                if proto_filter.is_some() {
                    return;
                }
                
                String::from("IPv6")
            },
            0x0806 => {
                if proto_filter.is_some() {
                    return;
                }
                
                String::from("ARP")
            }, // ищет MAC какого-то IP
            _ => String::from("Неизвестный EtherType"),
            // базовые вложенные протоколы
        };

        println!("{} | {}", str_dst_src, ethertype_name);
    }
}

fn parse_ipv4(buf: &[u8]) -> String {
    if buf.len() < 20 {
        return String::from("Invalid IPv4");
    }

    let protocol = buf[9];

    let ihl = buf[0] & 0x0F;
    let ip_header_len = (ihl * 4) as usize;

    let src = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);
    let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

    let mut ports_scr = String::new();
    let mut ports_dst = String::new();

    if protocol == 6 || protocol == 17 {
        let transport = &buf[ip_header_len..];

        if transport.len() >= 4 {
            let src_port = u16::from_be_bytes([transport[0], transport[1]]);
            let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

            ports_scr = format!(":{}", src_port);
            ports_dst = format!(":{}", dst_port);
        }
    }

    format!("IPv4: {}{} -> {}{}", src, ports_scr, dst, ports_dst)
}

fn main() {
    let cli = Cli::parse();
    let iface_cstr = CString::new(cli.interface).expect("Invalid interface name");
    
    let running = Arc::new(AtomicBool::new(true)); // flag

    let protocol = (ETH_P_ALL as u16).to_be() as i32;
    let fd = unsafe { socket(AF_PACKET, SOCK_RAW, protocol) };
    
    if fd < 0 {
        panic!("\nОШИБКА СОКЕТА: {}", Error::last_os_error());
    }

    let if_index = unsafe { if_nametoindex(iface_cstr.as_ptr() as *const i8) };

    if if_index == 0 {
        panic!("No interface, error: {}", Error::last_os_error());
    }

    enable_promiscuous(fd, if_index as i32);

    let mut buf = [0u8; 65535];

    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ОШИБКА НАСТРОЙКИ CTRL+C");

    loop {
        let n = unsafe {
            recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            eprintln!("\nОШИБКА ЧТЕНИЯ ПАКЕТА: {}", Error::last_os_error());
            continue;
        }

        let n = n as usize;

        parse_ethernet(&buf[0..n], &cli.proto, &cli.port);

        if !running.load(Ordering::SeqCst) {
            println!("Завершение работы...");
            break;
        }
    }
    unsafe { libc::close(fd) };
}
