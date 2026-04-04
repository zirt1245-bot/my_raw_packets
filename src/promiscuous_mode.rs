use libc::{PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC, SOL_PACKET, packet_mreq, setsockopt};
use std::{io::Error, mem::size_of};

pub fn enable_promiscuous(fd: i32, if_index: i32) {
    let mreq = packet_mreq {
        mr_ifindex: if_index,
        mr_type: PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };

    let ret = unsafe {
        setsockopt(
            fd,
            SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            size_of::<packet_mreq>() as u32,
        )
    };

    if ret != 0 {
        panic!("ОШИБКА: {}", Error::last_os_error());
    }
}