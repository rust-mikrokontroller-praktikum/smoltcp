use {Result, Error};
use wire::{UdpPacket, UdpRepr,
           DhcpPacket, DhcpRepr, DhcpMessageType};
use wire::{IpVersion, IpProtocol, IpCidr, Ipv4Cidr, IpEndpoint, IpAddress,
           Ipv4Address, Ipv4Packet, Ipv4Repr};
use socket::{SocketSet, SocketHandle};
use socket::{RawSocket, RawSocketBuffer};
use phy::{Device, ChecksumCapabilities};
use iface::EthernetInterface as Interface;
use time::{Instant, Duration};
use super::{UDP_SERVER_PORT, UDP_CLIENT_PORT};

const DISCOVER_TIMEOUT: u64 = 10;
const REQUEST_TIMEOUT: u64 = 1;
const REQUEST_RETRIES: u16 = 15;
const RENEW_TIMEOUT: u64 = 60;
const RENEW_RETRIES: u16 = 3;

#[derive(Debug)]
struct RequestState {
    retry: u16,
    server: Ipv4Address,
}

#[derive(Debug)]
struct RenewState {
    retry: u16,
    server: Ipv4Address,
}

#[derive(Debug)]
enum ClientState {
    /// Discovering the DHCP server
    Discovering,
    /// Requesting an address
    Requesting(RequestState),
    /// Having an address, refresh it renewally
    Renew(RenewState),
}

pub struct Client {
    state: ClientState,
    raw_handle: SocketHandle,
    /// When to send next request
    next_egress: Instant,
    transaction_id: u32,
    // TODO: dns_servers: [Ipv4Address; 3]
}

/// DHCP client with a RawSocket.
///
/// To provide memory for the dynamic IP address, configure your
/// `Interface` with one of `ip_addrs` and the `ipv4_gateway` being
/// `Ipv4Address::UNSPECIFIED`.
///
/// You must call `poll()` after `iface.poll()` to send and receive
/// DHCP packets.
impl Client {
    /// TODO
    pub fn new<'a, 'b, 'c>(sockets: &mut SocketSet<'a, 'b, 'c>, rx_buffer: RawSocketBuffer<'b, 'c>, tx_buffer: RawSocketBuffer<'b, 'c>, now: Instant) -> Self
    where 'b: 'c,
    {
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        let raw_handle = sockets.add(raw_socket);

        Client {
            state: ClientState::Discovering,
            raw_handle,
            next_egress: now,
            transaction_id: 1,
        }
    }

    /// When to send next packet
    ///
    /// Useful for suspending execution after polling.
    pub fn next_poll(&self, now: Instant) -> Duration {
        self.next_egress - now
    }

    /// Process incoming packets on the contained RawSocket, and send
    /// DHCP requests when timeouts are ready.
    pub fn poll<DeviceT: for<'d> Device<'d>>(&mut self, iface: &mut Interface<DeviceT>, sockets: &mut SocketSet, now: Instant) -> Result<()> {
        let checksum_caps = ChecksumCapabilities::default();
        let mut raw_socket = sockets.get::<RawSocket>(self.raw_handle);

        // Process incoming
        {
            match raw_socket.recv()
                .and_then(|packet| parse_udp(packet, &checksum_caps)) {
                    Ok((src, dst, payload)) =>
                        self.ingress(iface, now, payload, &src, &dst),
                    Err(Error::Exhausted) =>
                        (),
                    Err(e) =>
                        return Err(e),
                }
        }

        // Send requests
        if raw_socket.can_send() && now >= self.next_egress {
            self.egress(iface, &mut *raw_socket, &checksum_caps, now)?;
        }

        Ok(())
    }

    fn ingress<DeviceT: for<'d> Device<'d>>(&mut self, iface: &mut Interface<DeviceT>, now: Instant, data: &[u8], src: &IpEndpoint, dst: &IpEndpoint) {
        if src.port != UDP_SERVER_PORT ||
           dst.port != UDP_CLIENT_PORT { return }

        let dhcp_packet = match DhcpPacket::new_checked(data) {
            Ok(dhcp_packet) => dhcp_packet,
            Err(_) => return,
        };
        let dhcp_repr = match DhcpRepr::parse(&dhcp_packet) {
            Ok(dhcp_repr) => dhcp_repr,
            Err(_) => return,
        };
        let mac = iface.ethernet_addr();
        if dhcp_repr.client_hardware_address != mac { return }
        if dhcp_repr.transaction_id != self.transaction_id { return }

        if (dhcp_repr.message_type == DhcpMessageType::Offer ||
            dhcp_repr.message_type == DhcpMessageType::Ack) &&
           dhcp_repr.your_ip != Ipv4Address::UNSPECIFIED {
               let prefix_len = dhcp_repr.subnet_mask
                   .map(|mask| IpAddress::Ipv4(mask).to_prefix_len())
                   .unwrap_or(0);
               // Replace the first IP address
               iface.update_ip_addrs(|addrs| {
                   for cidr in addrs.iter_mut() {
                       match cidr.address() {
                           IpAddress::Ipv4(_) => {
                               // TODO: prefix_len
                               let ipv4_cidr = Ipv4Cidr::new(dhcp_repr.your_ip, prefix_len);
                               *cidr = IpCidr::Ipv4(ipv4_cidr);
                               break
                           }
                           _ => ()
                       }
                   }
               });
               // Set gateway
               match dhcp_repr.router {
                   Some(router) if iface.in_same_network(&router.into()) => {
                       iface.set_ipv4_gateway(router);
                   }
                   _ => ()
               }
               // TODO: dns servers
        }

        match self.state {
            ClientState::Discovering
                if dhcp_repr.message_type == DhcpMessageType::Offer =>
            {
                let r_state = RequestState {
                    retry: 0,
                    server: dhcp_repr.server_ip,
                };
                Some(ClientState::Requesting(r_state))
            }
            ClientState::Requesting(ref r_state)
                if dhcp_repr.message_type == DhcpMessageType::Ack &&
                dhcp_repr.server_ip == r_state.server =>
            {
                let p_state = RenewState {
                    retry: 0,
                    server: dhcp_repr.server_ip,
                };
                Some(ClientState::Renew(p_state))
            }
            ClientState::Renew(ref mut p_state)
                if dhcp_repr.message_type == DhcpMessageType::Ack &&
                dhcp_repr.server_ip == p_state.server =>
            {
                self.next_egress = now + Duration::from_secs(60);
                p_state.retry = 0;
                None
            }
            _ => None
        }.map(|new_state| self.state = new_state);
    }

    fn egress<DeviceT: for<'d> Device<'d>>(&mut self, iface: &mut Interface<DeviceT>, raw_socket: &mut RawSocket, checksum_caps: &ChecksumCapabilities, now: Instant) -> Result<()> {
        self.transaction_id += 1;
        let mac = iface.ethernet_addr();
        let addr = iface.ipv4_addr();
        let requested_ip = addr.and_then(|addr|
            if !addr.is_unspecified() {
                Some(addr)
            } else {
                None
            }
        );
        let your_ip = addr.unwrap_or(Ipv4Address::UNSPECIFIED);

        match self.state {
            ClientState::Discovering => {
                let endpoint = IpEndpoint {
                    addr: Ipv4Address::BROADCAST.into(),
                    port: UDP_SERVER_PORT,
                };
                let dhcp_repr = DhcpRepr {
                    message_type: DhcpMessageType::Discover,
                    transaction_id: self.transaction_id,
                    client_hardware_address: mac,
                    client_ip: Ipv4Address::UNSPECIFIED,
                    your_ip,
                    server_ip: Ipv4Address::UNSPECIFIED,
                    router: None,
                    subnet_mask: None,
                    relay_agent_ip: Ipv4Address::UNSPECIFIED,
                    broadcast: true,
                    requested_ip,
                    client_identifier: Some(mac),
                    server_identifier: None,
                    parameter_request_list: None, //Some(&[1, 3, 6, 42]),
                };
                send_packet(iface, raw_socket, &endpoint, &dhcp_repr, checksum_caps)?;

                self.next_egress = now + Duration::from_secs(DISCOVER_TIMEOUT);
                Ok(())
            }
            ClientState::Requesting(ref mut r_state) if r_state.retry < REQUEST_RETRIES => {
                let endpoint = IpEndpoint {
                    addr: Ipv4Address::BROADCAST.into(),
                    port: UDP_SERVER_PORT,
                };
                let dhcp_repr = DhcpRepr {
                    message_type: DhcpMessageType::Request,
                    transaction_id: self.transaction_id,
                    client_hardware_address: mac,
                    client_ip: Ipv4Address::UNSPECIFIED,
                    your_ip,
                    server_ip: r_state.server,
                    router: None,
                    subnet_mask: None,
                    relay_agent_ip: Ipv4Address::UNSPECIFIED,
                    broadcast: false,
                    requested_ip,
                    client_identifier: Some(mac),
                    server_identifier: None,
                    parameter_request_list: None, //Some(&[1, 3, 6, 42]),
                };
                send_packet(iface, raw_socket, &endpoint, &dhcp_repr, checksum_caps)?;

                r_state.retry += 1;
                self.next_egress = now + Duration::from_secs(REQUEST_TIMEOUT);
                Ok(())
            }
            ClientState::Requesting(_) => {
                // Timeout, restart discovery
                self.state = ClientState::Discovering;
                // Recurse to send discovery packet
                self.egress(iface, raw_socket, checksum_caps, now)
            }
            ClientState::Renew(ref mut p_state) if p_state.retry < RENEW_RETRIES => {
                let endpoint = IpEndpoint {
                    addr: p_state.server.into(),
                    port: UDP_SERVER_PORT,
                };
                let dhcp_repr = DhcpRepr {
                    message_type: DhcpMessageType::Request,
                    transaction_id: self.transaction_id,
                    client_hardware_address: mac,
                    client_ip: your_ip,
                    your_ip,
                    server_ip: p_state.server,
                    router: None,
                    subnet_mask: None,
                    relay_agent_ip: Ipv4Address::UNSPECIFIED,
                    broadcast: false,
                    requested_ip,
                    client_identifier: Some(mac),
                    server_identifier: None,
                    parameter_request_list: None, //Some(&[1, 3, 6, 42]),
                };
                send_packet(iface, raw_socket, &endpoint, &dhcp_repr, checksum_caps)?;

                p_state.retry += 1;
                self.next_egress = now + Duration::from_secs(RENEW_TIMEOUT);
                Ok(())
            }
            ClientState::Renew(_) => {
                // Timeout, restart discovery
                self.state = ClientState::Discovering;
                // Recurse to send discovery packet
                self.egress(iface, raw_socket, checksum_caps, now)
            }
        }
    }

    /// Reset state and restart discovery phase.
    ///
    /// Use this to speed up acquisition of an address in a new
    /// network if a link was down and it is now back up.
    pub fn reset(&mut self, now: Instant) {
        self.state = ClientState::Discovering;
        self.next_egress = now;
    }
}

fn send_packet<DeviceT: for<'d> Device<'d>>(iface: &mut Interface<DeviceT>, raw_socket: &mut RawSocket, endpoint: &IpEndpoint, dhcp_repr: &DhcpRepr, checksum_caps: &ChecksumCapabilities) -> Result<()> {
    let mut dhcp_payload_buf = [0; 320];
    assert!(dhcp_repr.buffer_len() <= dhcp_payload_buf.len());
    let dhcp_payload = &mut dhcp_payload_buf[0..dhcp_repr.buffer_len()];
    {
        let mut dhcp_packet = DhcpPacket::new(&mut dhcp_payload[..]);
        dhcp_repr.emit(&mut dhcp_packet)?;
    }

    let udp_repr = UdpRepr {
        src_port: UDP_CLIENT_PORT,
        dst_port: endpoint.port,
        payload: dhcp_payload,
    };

    let src_addr = iface.ipv4_addr().unwrap();
    let dst_addr = match endpoint.addr {
        IpAddress::Ipv4(addr) => addr,
        _ => return Err(Error::Illegal),
    };
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        protocol: IpProtocol::Udp,
        payload_len: udp_repr.buffer_len(),
        hop_limit: 64,
    };

    let mut packet = raw_socket.send(
        ipv4_repr.buffer_len() + udp_repr.buffer_len()
    )?;
    {
        let mut ipv4_packet = Ipv4Packet::new(&mut packet);
        ipv4_repr.emit(&mut ipv4_packet, &checksum_caps);
    }
    {
        let mut udp_packet = UdpPacket::new(
            &mut packet[ipv4_repr.buffer_len()..]
        );
        udp_repr.emit(&mut udp_packet,
                      &src_addr.into(), &dst_addr.into(),
                      checksum_caps);
    }
    Ok(())
}

fn parse_udp<'a>(data: &'a [u8], checksum_caps: &ChecksumCapabilities) -> Result<(IpEndpoint, IpEndpoint, &'a [u8])> {
    let ipv4_packet = Ipv4Packet::new_checked(data)?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
    let udp_packet = UdpPacket::new_checked(ipv4_packet.payload())?;
    let udp_repr = UdpRepr::parse(
        &udp_packet,
        &ipv4_repr.src_addr.into(), &ipv4_repr.dst_addr.into(),
        checksum_caps
    )?;
    let src = IpEndpoint {
        addr: ipv4_repr.src_addr.into(),
        port: udp_repr.src_port,
    };
    let dst = IpEndpoint {
        addr: ipv4_repr.dst_addr.into(),
        port: udp_repr.dst_port,
    };
    let data = udp_repr.payload;
    Ok((src, dst, data))
}
