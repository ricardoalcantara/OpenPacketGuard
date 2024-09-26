use pcap::Device;
use tokio::task::JoinHandle;

use crate::{
    sniffer::{sniffer_packet::SnifferPacket, SnifferProcessor},
    utils,
};

#[derive(Default)]
pub struct DebugProcessor {
    device: Option<Device>,
    server: Option<DebugUdpSocket>,
}

impl SnifferProcessor for DebugProcessor {
    fn init(&mut self, device: &Device) {
        self.device = Some(device.clone());
        log::info!("Device initialized: {}", device.name);

        self.server = Some(DebugUdpSocket::new());
    }

    fn process(&mut self, packet: SnifferPacket) {
        let device = self.device.as_ref().unwrap();
        if packet.is_incoming_packet(device) {
            log::debug!("in  {:?}", packet);
        } else {
            log::debug!("out {:?}", packet);
        }
    }
}
struct DebugUdpSocket {
    server: JoinHandle<()>,
}

impl DebugUdpSocket {
    fn new() -> Self {
        let server = tokio::spawn(async {
            log::debug!("Starting debug server");
            let socket = std::net::UdpSocket::bind("0.0.0.0:7001").unwrap(); // Bind to any address on port 8080
            let mut buf = [0; 1024]; // Buffer for incoming data

            loop {
                match socket.recv_from(&mut buf) {
                    Ok((number_of_bytes, src_addr)) => {
                        log::debug!(
                            "Received {} bytes from {}: {}",
                            number_of_bytes,
                            src_addr,
                            utils::format_size(buf.len()),
                        );
                    }
                    Err(e) => {
                        log::error!("Error: {}", e);
                    }
                }
            }
        });

        DebugUdpSocket { server }
    }
}
