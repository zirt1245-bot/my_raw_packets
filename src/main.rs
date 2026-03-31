use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, recvfrom, socket};
use std::{
    io::Error,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
};

fn main() {
    let running = Arc::new(AtomicBool::new(true)); // flag
    
    let protocol = (ETH_P_ALL as u16).to_be() as i32;
    let fd = unsafe { socket(AF_PACKET, SOCK_RAW, protocol) };

    if fd < 0 {
        panic!("\nОШИБКА СОКЕТА: {}", Error::last_os_error());
    }

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

        for b in &buf[0..n] {
            print!("{:02x} ", b); // hexadecimal system (hex)
        }
        println!();
        
        if !running.load(Ordering::SeqCst) {
            println!("Завершение работы...");
            break;
        }        
    }
    unsafe {libc::close(fd)};
}
