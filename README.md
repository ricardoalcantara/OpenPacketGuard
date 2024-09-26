# OpenPacketGuard

use pnet::datalink;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, Packet};
use std::vec;

fn main() {
    // Get the list of network interfaces
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No suitable interface found");

    // Create a channel for capturing packets
    let channel =
        datalink::channel(&interface, Default::default()).expect("Error creating channel");

    println!("Listening on interface: {}", interface.name);

    if let datalink::Channel::Ethernet(_, mut rx) = channel {
        loop {
            // Capture packets
            match rx.next() {
                Ok(packet) => {
                    // Parse the Ethernet frame
                    let eth_packet =
                        EthernetPacket::new(packet).expect("Failed to parse Ethernet packet");
                    let ip_packet =
                        Ipv4Packet::new(eth_packet.payload()).expect("Failed to parse IP packet");

                    let src_ip = ip_packet.get_source();
                    let dst_ip = ip_packet.get_destination();

                    match ip_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            let tcp_packet = TcpPacket::new(ip_packet.payload())
                                .expect("Failed to parse TCP packet");
                            let src_port = tcp_packet.get_source();
                            let dst_port = tcp_packet.get_destination();
                            let flags = tcp_packet.get_flags_string();

                            println!(
                            "SRC IP: {}, SRC PORT: {}, DST IP: {}, DST PORT: {}, TYPE: TCP, FLAGS: {:?}",
                            src_ip, src_port, dst_ip, dst_port, flags
                        );
                        }
                        IpNextHeaderProtocols::Udp => {
                            let udp_packet = UdpPacket::new(ip_packet.payload())
                                .expect("Failed to parse UDP packet");
                            let src_port = udp_packet.get_source();
                            let dst_port = udp_packet.get_destination();

                            println!(
                                "SRC IP: {}, SRC PORT: {}, DST IP: {}, DST PORT: {}, TYPE: UDP",
                                src_ip, src_port, dst_ip, dst_port
                            );
                        }
                        _ => {
                            println!("SRC IP: {}, DST IP: {}, TYPE: OTHER", src_ip, dst_ip);
                        }
                    }
                }
                Err(e) => println!("Error: {}", e),
            }
        }
    }
}

trait TcpPacketExt<'a> {
    fn get_flags_string(&self) -> String;
}

impl TcpPacketExt<'_> for TcpPacket<'_> {
    fn get_flags_string(&self) -> String {
        let mut flags = vec![];

        if self.get_flags() & TcpFlags::FIN != 0 {
            flags.push("FIN".to_string());
        }
        if self.get_flags() & TcpFlags::SYN != 0 {
            flags.push("SYN".to_string());
        }
        if self.get_flags() & TcpFlags::RST != 0 {
            flags.push("RST".to_string());
        }
        if self.get_flags() & TcpFlags::PSH != 0 {
            flags.push("PSH".to_string());
        }
        if self.get_flags() & TcpFlags::ACK != 0 {
            flags.push("ACK".to_string());
        }
        if self.get_flags() & TcpFlags::URG != 0 {
            flags.push("URG".to_string());
        }
        if self.get_flags() & TcpFlags::ECE != 0 {
            flags.push("ECE".to_string());
        }
        if self.get_flags() & TcpFlags::CWR != 0 {
            flags.push("CWR".to_string());
        }
        return flags.join(" ");
    }
}
