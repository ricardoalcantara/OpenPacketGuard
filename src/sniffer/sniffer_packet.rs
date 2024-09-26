use std::fmt::Debug;

use pcap::Device;

use crate::utils;

#[derive(Debug)]
pub enum SnifferPacketType {
    TCP(u8),
    UDP,
}

pub struct SnifferPacket {
    pub source: std::net::SocketAddr,
    pub destination: std::net::SocketAddr,
    pub size: usize,
    pub packet_type: SnifferPacketType,
}

impl Debug for SnifferPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {} -> {} {}",
            self.packet_type,
            self.source,
            self.destination,
            utils::format_size(self.size)
        )
    }
}

impl SnifferPacket {
    pub fn is_incoming_packet(&self, device: &Device) -> bool {
        for address in device.addresses.iter() {
            if address.addr == self.destination.ip() {
                return true;
            }
        }
        false
    }
    pub fn is_outgoing_packet(&self, device: &Device) -> bool {
        for address in device.addresses.iter() {
            if address.addr == self.source.ip() {
                return true;
            }
        }
        false
    }
}
