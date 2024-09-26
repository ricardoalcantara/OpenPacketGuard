use pcap::Device;
use sniffer_packet::SnifferPacket;

pub mod sniffer_engine;
pub mod sniffer_packet;

pub trait SnifferProcessor {
    fn init(&mut self, _: &Device);
    fn process(&mut self, _: SnifferPacket);
}
