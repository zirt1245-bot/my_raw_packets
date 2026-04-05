use colored::Colorize;

fn known_org(ip: &str) -> &str {
    // name ip
    if ip.starts_with("142.250.") || ip.starts_with("142.251.") || ip.starts_with("172.217.") {
        "[Google]"
    } else if ip.starts_with("192.168.") || ip.starts_with("10.") {
        "[Your IP]"
    } else if ip.starts_with("91.108.") || ip.starts_with("149.154.") {
        "[Telegram]"
    } else {
        ""
    }
}

fn colorize_ip(ip: &str) -> String {
    // проверяем локальный адрес или нет
    if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
        ip.green().to_string() // зеленный локальный
    } else {
        ip.red().to_string() // красный извне, то-есть интернет
    }
}

fn format_mac(mac: &[u8]) -> String {
    // крассивый вывод MAC адресса
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse_ethernet(
    buf: &[u8],
    proto_filter: &Vec<String>,
    port_filter: &Vec<u16>,
    ip_filter: &Vec<String>,
    exc_proto_filter: &Vec<String>,
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
            0x0800 => { // IPv4
                let ip_header = &buf[14..];
                let proto_code = ip_header[9];

                let ihl = ip_header[0] & 0x0F;
                let ip_header_len = (ihl * 4) as usize;

                let transport = &ip_header[ip_header_len..];

                let proto_name_plain = match proto_code {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    2 => "IGMP",
                    _ => "OTHER",
                };

                if proto_filter.iter().any(|filter| {
                    // фильтр протокола
                    !proto_name_plain
                        .to_uppercase()
                        .starts_with(&filter.to_uppercase())
                }) {
                    return;
                }

                if exc_proto_filter.iter().any(|exc| {
                    proto_name_plain
                        .to_uppercase()
                        .starts_with(&exc.to_uppercase())
                }) {
                    return;
                }
                
                if ip_filter.iter().any(|ip| {
                    // фильтр IP
                    !proto_name_plain
                        .to_uppercase()
                        .starts_with(&ip.to_uppercase())
                }) {
                    return;
                }

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

                        if syn {
                            flag_list.push("SYN".green().to_string());
                        }
                        if ack {
                            flag_list.push("ACK".yellow().to_string());
                        }
                        if fin {
                            flag_list.push("FIN".red().to_string());
                        }
                        if rst {
                            flag_list.push("RST".red().to_string());
                        }
                        /* SYN: первый пакет, хочу подключится
                        ACK: получил пакет, установка соединения
                        FIN: все пакеты отправили, закрытие соединения
                        RST: ошибка пакета */

                        if flag_list.is_empty() {
                            "TCP: no flags".to_string()
                        } else {
                            format!("{} {}", "TCP:".blue(), flag_list.join(", "))
                        }
                    }
                    17 => "UDP".blue().to_string(),
                    1 => "ICMP".cyan().to_string(),
                    2 => "IGMP".purple().to_string(),
                    _ => "Other IP protocol".black().to_string(),
                    // IGMP: сетевой шум
                };

                let (ipv4_info, src_port, dst_port) = parse_ipv4(ip_header);

                if !port_filter.is_empty() {
                    // фильтр порта
                    if !port_filter.iter().any(|port| {
                        src_port == Some(*port) || dst_port == Some(*port)
                    }) {
                        return
                    }
                }

                format!("{} | {}", ipv4_info, proto_name)
            }
            0x86DD => {
                if proto_filter.iter().any(|filter| {
                    !"IPv6"
                        .to_uppercase()
                        .starts_with(&filter.to_uppercase())
                }) {
                    return;
                }

                if exc_proto_filter.iter().any(|filter| {
                    "IPv6"
                        .to_uppercase()
                        .starts_with(&filter.to_uppercase())
                }) {
                    return;
                }

                "IPv6".to_string()
            }
            0x0806 => {
                if proto_filter.iter().any(|filter| {
                    !"ARP"
                        .to_uppercase()
                        .starts_with(&filter.to_uppercase())
                }) {
                    return;
                }
                
                if proto_filter.iter().any(|filter| {
                    "ARP"
                        .to_uppercase()
                        .starts_with(&filter.to_uppercase())
                }) {
                    return;
                }

                "ARP".to_string()
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

    let src_ip = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);
    let dst_ip = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

    let src_org = known_org(&src_ip);
    let dst_org = known_org(&dst_ip);

    let src = colorize_ip(&src_ip);
    let dst = colorize_ip(&dst_ip);

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
        format!(
            "IPv4: {}{} {} -> {}{} {}",
            src, ports_src_str, src_org, dst, ports_dst_str, dst_org
        ),
        src_port,
        dst_port,
    )
}
