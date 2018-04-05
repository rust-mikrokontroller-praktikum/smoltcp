#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, Ipv4Address, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::SocketSet;
use smoltcp::time::Instant;
use smoltcp::dhcp::Dhcpv4Client;

fn main() {
    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)];
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .ipv4_gateway(Ipv4Address::UNSPECIFIED)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let mut dhcp = Dhcpv4Client::new(&mut sockets, Instant::now());
    let mut prev_ip_addr = iface.ipv4_addr().unwrap();
    loop {
        let timestamp = Instant::now();
        iface.poll(&mut sockets, timestamp)
            .map(|_| ())
            .unwrap_or_else(|e| println!("Poll: {:?}", e));
        dhcp.poll(&mut iface, &mut sockets, timestamp)
            .unwrap_or_else(|e| println!("DHCP: {:?}", e));;
        let ip_addr = iface.ipv4_addr().unwrap();
        if ip_addr != prev_ip_addr {
            println!("Assigned a new IPv4 address: {}", ip_addr);
            prev_ip_addr = ip_addr;
        }

        let mut timeout = dhcp.next_poll(timestamp);
        iface.poll_delay(&sockets, timestamp)
            .map(|sockets_timeout| timeout = sockets_timeout);
        phy_wait(fd, Some(timeout))
            .unwrap_or_else(|e| println!("Wait: {:?}", e));;
    }
}
