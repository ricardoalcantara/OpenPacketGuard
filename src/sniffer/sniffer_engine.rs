use super::{sniffer_packet::SnifferPacket, SnifferProcessor};
use crate::{error::OPGError, sniffer::sniffer_packet::SnifferPacketType};
use anyhow::anyhow;
use pcap::Device;
use pnet::packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket,
    udp::UdpPacket, Packet,
};

pub struct SnifferEngine {
    device: Option<Device>,
    filter: Option<String>,
    processor: Option<Box<dyn SnifferProcessor>>,
}

impl SnifferEngine {
    pub fn new() -> Self {
        SnifferEngine {
            device: None,
            filter: None,
            processor: None,
        }
    }

    pub fn with_device(mut self, device: Device) -> Self {
        self.device = Some(device);
        self
    }

    pub fn with_interface(mut self, interface: &str) -> Result<Self, pcap::Error> {
        self.device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == interface);
        Ok(self)
    }

    pub fn with_device_lookup(mut self) -> Result<Self, pcap::Error> {
        self.device = pcap::Device::lookup()?;
        Ok(self)
    }

    pub fn with_filter<S: AsRef<str>>(mut self, filter: S) -> Self {
        self.filter = Some(filter.as_ref().to_string());
        self
    }

    pub fn with_processor<T: SnifferProcessor + 'static>(mut self, processor: T) -> Self {
        self.processor = Some(Box::new(processor));
        self
    }

    pub fn run(self) -> Result<(), OPGError> {
        let device = self.device.ok_or(anyhow!("No device found"))?;
        log::debug!("Using device {:?}", device);

        let mut processor = self.processor.ok_or(anyhow!("No processor found"))?;

        log::debug!("Initializing processor");
        processor.init(&device);

        // Setup Capture
        let mut cap = pcap::Capture::from_device(device)?
            .immediate_mode(true)
            .open()?;

        if let Some(filter) = self.filter {
            // TODO: check if optimization is needed
            cap.filter(&filter, true)?;
        }

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(eth_packet) = EthernetPacket::new(packet.data) {
                        if eth_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
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
                                            tcp_packet.get_flags();
                                            processor.process(SnifferPacket {
                                                source: std::net::SocketAddr::V4(
                                                    std::net::SocketAddrV4::new(src_ip, src_port),
                                                ),
                                                destination: std::net::SocketAddr::V4(
                                                    std::net::SocketAddrV4::new(dst_ip, dst_port),
                                                ),
                                                size,
                                                packet_type: SnifferPacketType::TCP(
                                                    tcp_packet.get_flags(),
                                                ),
                                            })
                                        }
                                    }
                                    IpNextHeaderProtocols::Udp => {
                                        if let Some(udp_packet) =
                                            UdpPacket::new(ip_packet.payload())
                                        {
                                            let src_port = udp_packet.get_source();
                                            let dst_port = udp_packet.get_destination();

                                            processor.process(SnifferPacket {
                                                source: std::net::SocketAddr::V4(
                                                    std::net::SocketAddrV4::new(src_ip, src_port),
                                                ),
                                                destination: std::net::SocketAddr::V4(
                                                    std::net::SocketAddrV4::new(dst_ip, dst_port),
                                                ),
                                                size,
                                                packet_type: SnifferPacketType::UDP,
                                            })
                                        }
                                    }
                                    x => {
                                        log::debug!("Other protocol {:?}", x);
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
    }
}
