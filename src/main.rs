use clap::Parser;
use colored::Colorize;
use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, if_nametoindex, recvfrom, socket};
use promiscuous_mode::enable_promiscuous;
use std::{
    ffi::CString,
    io::Error,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Parser)] // будем урпавлять прогрраммой командами из терминала
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

    /// Filter by IP address
    #[arg(long)]
    ip: Option<String>,
}

mod promiscuous_mode;

fn format_mac(mac: &[u8]) -> String {
    // крассивый вывод MAC адресса
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_ethernet(
    buf: &[u8],
    proto_filter: &Option<String>,
    port_filter: &Option<u16>,
    ip_filter: &Option<String>,
) {
    if buf.len() < 14 {
        println!("Invalid Ethernet");
    } else {
        let mac_dst = &buf[0..=5]; // собираем MAC получателя
        let mac_src = &buf[6..=11]; // собираем MAC отпавителя
        // MAC это адрес нашего физического интерфейса

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

                let ihl = ip_header[0] & 0x0F;
                let ip_header_len = (ihl * 4) as usize;

                let transport = &ip_header[ip_header_len..];

                let proto_name = match proto_code {
                    6 => {
                        if transport.len() < 14 {
                            return println!("TCP (invalid)");
                        }

                        let flags = transport[13];

                        let syn = flags & 0b00000010 != 0;
                        let ack = flags & 0b00010000 != 0;
                        let fin = flags & 0b00000001 != 0;
                        let rst = flags & 0b00000100 != 0;

                        let mut flag_list = Vec::new();

                        if syn { flag_list.push("SYN".green().to_string()); }
                        if ack { flag_list.push("ACK".yellow().to_string()); }
                        if fin { flag_list.push("FIN".red().to_string()); }
                        if rst { flag_list.push("RST".red().to_string()); }
                        /* SYN: первый пакет, хочу подключится
                        ACK: получил пакет, установка соединения
                        FIN: все пакеты отправили, закрытие соединения
                        RST: ошибка покета */
                        
                        if flag_list.is_empty() {
                            format!("TCP: no flags")
                        } else {
                            format!("TCP: {}", flag_list.join(", "))
                        }
                    },
                    17 => "UDP".blue().to_string(),
                    1 => "ICMP".cyan().to_string(),
                    2 => "IGMP".purple().to_string(),
                    _ => String::from("Other IP protocol"),
                };

                if let Some(filter) = proto_filter {
                    if !proto_name.to_uppercase().starts_with(&filter.to_uppercase()) {
                        return;
                    }
                }

                let (ipv4_info, src_port, dst_port) = parse_ipv4(ip_header);

                if let Some(port) = port_filter {
                    if src_port != Some(*port) && dst_port != Some(*port) {
                        return;
                    }
                }

                if let Some(ip) = ip_filter {
                    if !ipv4_info.contains(ip.as_str()) {
                        return;
                    }
                }

                format!("{} | {}", ipv4_info, proto_name)
            }
            0x86DD => {
                if proto_filter.is_some() {
                    return;
                }

                String::from("IPv6")
            }
            0x0806 => {
                if proto_filter.is_some() {
                    return;
                }

                String::from("ARP")
            } // ищет MAC какого-то IP
            _ => String::from("Неизвестный EtherType"),
            // базовые вложенные протоколы
        }; 

        println!("{} | {}", str_dst_src, ethertype_name);
    }
}

fn parse_ipv4(buf: &[u8]) -> (String, Option<u16>, Option<u16>) {
    if buf.len() < 20 {
        return (String::from("Invalid IPv4"), None, None);
    }

    let protocol = buf[9];

    let ihl = buf[0] & 0x0F;
    let ip_header_len = (ihl * 4) as usize;

    let src = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);
    let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

    let mut ports_src_str = String::new();
    let mut ports_dst_str = String::new();
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;

    if protocol == 6 || protocol == 17 {
        let transport = &buf[ip_header_len..];

        if transport.len() >= 4 {
            let sp = u16::from_be_bytes([transport[0], transport[1]]);
            let dp = u16::from_be_bytes([transport[2], transport[3]]);

            src_port = Some(sp);
            dst_port = Some(dp);

            ports_src_str = format!(":{}", sp);
            ports_dst_str = format!(":{}", dp);
        }
    }

    (
        format!("IPv4: {}{} -> {}{}", src, ports_src_str, dst, ports_dst_str),
        src_port,
        dst_port,
    )
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

        parse_ethernet(&buf[0..n], &cli.proto, &cli.port, &cli.ip);

        if !running.load(Ordering::SeqCst) {
            println!("Завершение работы...");
            break;
        }
    }
    unsafe { libc::close(fd) };
}