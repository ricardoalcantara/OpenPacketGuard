use crate::error::OPGError;
use pcap::Device;
use pnet::packet::Packet;
use pnet::packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket,
    udp::UdpPacket,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

pub enum XPacket {
    TCP(XPacketHeader),
    UDP(XPacketHeader),
}

pub struct XPacketHeader {
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    size: usize,
}

#[derive(Default)]
pub struct SnifferEngine {
    packets: Arc<RwLock<Vec<XPacket>>>,
    capturing: Option<JoinHandle<Result<(), OPGError>>>,
}

impl SnifferEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list_interface(&self) -> Result<Vec<Device>, OPGError> {
        let devices = pcap::Device::list()?;
        Ok(devices)
    }

    pub fn get_interface(&self, interface: &str) -> Result<Option<Device>, OPGError> {
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == interface);

        Ok(device)
    }

    pub fn lookup(&self) -> Result<Option<Device>, OPGError> {
        let device = pcap::Device::lookup()?;
        Ok(device)
    }

    pub fn start_capture(&mut self, device: Device) -> Result<(), OPGError> {
        println!("Using device {}", device.name);

        // Setup Capture
        let mut cap = pcap::Capture::from_device(device)?
            .immediate_mode(true)
            .open()?;

        let packets = self.packets.clone();

        let capturing: JoinHandle<Result<(), OPGError>> = tokio::spawn(async move {
            loop {
                let mut packets = packets.write().await;
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(eth_packet) = EthernetPacket::new(packet.data) {
                            if eth_packet.get_ethertype()
                                == pnet::packet::ethernet::EtherTypes::Ipv4
                            {
                                if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                                    let size = ip_packet.packet().len();
                                    let src_ip = ip_packet.get_source();
                                    let dst_ip = ip_packet.get_destination();

                                    match ip_packet.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp_packet) =
                                                TcpPacket::new(ip_packet.payload())
                                            {
                                                let src_port = tcp_packet.get_source();
                                                let dst_port = tcp_packet.get_destination();

                                                packets.push(XPacket::TCP(XPacketHeader {
                                                    source: std::net::SocketAddr::V4(
                                                        std::net::SocketAddrV4::new(
                                                            src_ip, src_port,
                                                        ),
                                                    ),
                                                    destination: std::net::SocketAddr::V4(
                                                        std::net::SocketAddrV4::new(
                                                            dst_ip, dst_port,
                                                        ),
                                                    ),
                                                    size,
                                                }))
                                            }
                                        }
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp_packet) =
                                                UdpPacket::new(ip_packet.payload())
                                            {
                                                let src_port = udp_packet.get_source();
                                                let dst_port = udp_packet.get_destination();

                                                packets.push(XPacket::UDP(XPacketHeader {
                                                    source: std::net::SocketAddr::V4(
                                                        std::net::SocketAddrV4::new(
                                                            src_ip, src_port,
                                                        ),
                                                    ),
                                                    destination: std::net::SocketAddr::V4(
                                                        std::net::SocketAddrV4::new(
                                                            dst_ip, dst_port,
                                                        ),
                                                    ),
                                                    size,
                                                }))
                                            }
                                        }
                                        x => {
                                            println!("Other protocol {:?}", x);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("{}", e);
                    }
                }
            }
        });

        self.capturing = Some(capturing);

        Ok(())
    }

    pub fn apply_filter(&mut self, filter: &str) -> Result<(), OPGError> {
        // Logic to apply filters (e.g., BPF filter)
        todo!()
    }

    pub fn stop_capture(&self) -> Result<(), OPGError> {
        // Logic to stop capture
        todo!()
    }

    pub async fn get_statistics(&self) -> Result<(usize, usize), OPGError> {
        let read = self.packets.read().await;
        let len = read.len();
        let mut sum = 0;
        for p in read.iter() {
            match p {
                XPacket::TCP(tcp) => {
                    sum += tcp.size;
                }
                XPacket::UDP(udp) => {
                    sum += udp.size;
                }
            }
        }
        Ok((len, sum))
    }

    pub fn save_capture(&self, filepath: &str) -> Result<(), OPGError> {
        // Logic to save captured packets to a file
        todo!()
    }
}
