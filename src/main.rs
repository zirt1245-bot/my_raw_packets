mod parser;
use clap::Parser;
use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, if_nametoindex, recvfrom, socket};
use std::{
    ffi::CString,
    io::Error,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
};
mod promiscuous_mode;
use promiscuous_mode::enable_promiscuous;

#[derive(Parser)] // будем управлять программой командами из терминала
#[command(name = "raw-sniffer", about = "Raw packet sniffer")]
struct Cli {
    /// Network interface to listen on (e.g. eth0, wlp0s20f3)
    interface: String,

    /// Filter by protocol: tcp, udp, icmp
    #[arg(long)]
    proto: Vec<String>,

    /// Filter by port number
    #[arg(long)]
    port: Vec<u16>,

    /// Filter by IP address
    #[arg(long)]
    ip: Vec<String>,

    /// Exclude by protocol: tcp, udp, icmp
    #[arg(long)]
    exc_proto: Vec<String>,
}
use crate::parser::parse_ethernet;

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

        parse_ethernet(&buf[0..n], &cli.proto, &cli.port, &cli.ip, &cli.exc_proto);

        if !running.load(Ordering::SeqCst) {
            println!("Завершение работы...");
            break;
        }
    }
    unsafe { libc::close(fd) };
}
