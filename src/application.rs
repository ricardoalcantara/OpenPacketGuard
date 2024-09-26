use anyhow::anyhow;
use log::info;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use procfs::process::{FDTarget, Stat};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::database::SharedDatabase;
use crate::error::OPGError;

enum EntryType {
    Tcp(procfs::net::TcpNetEntry),
    Udp(procfs::net::UdpNetEntry),
}

struct Entity {
    entry: EntryType,
    stat: Option<Stat>,
    up: usize,
    down: usize,
}

fn get_entities() -> Result<HashMap<SocketAddrV4, Entity>, OPGError> {
    let mut entities: HashMap<SocketAddrV4, Entity> = HashMap::new();
    let mut processes = get_processes()?;
    let tcp = procfs::net::tcp()?;
    for entry in tcp {
        if entry.state == procfs::net::TcpState::Listen {
            let inode = entry.inode;
            let SocketAddr::V4(mut addr) = entry.local_address else {
                continue;
            };
            addr.set_ip(Ipv4Addr::new(192, 168, 1, 107));
            let entity = Entity {
                entry: EntryType::Tcp(entry),
                stat: processes.remove(&inode),
                up: 0,
                down: 0,
            };
            entities.insert(addr, entity);
        }
    }

    let udp = procfs::net::udp()?;
    for entry in udp {
        let inode = entry.inode;
        let SocketAddr::V4(addr) = entry.local_address else {
            continue;
        };
        let entity = Entity {
            entry: EntryType::Udp(entry),
            stat: processes.remove(&inode),
            up: 0,
            down: 0,
        };
        entities.insert(addr, entity);
    }

    Ok(entities)
}

pub fn run(_db: SharedDatabase) -> Result<(), OPGError> {
    let mut entities = get_entities()?;
    let device = pcap::Device::lookup()?.ok_or(anyhow!("no device available"))?;
    println!("Using device {}", device.name);

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)?
        .immediate_mode(true)
        .open()?;

    let mut dt = chrono::Utc::now();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // if let Ok(packet) = cap.next_packet() {
                if let Some(eth_packet) = EthernetPacket::new(packet.data) {
                    // Check if it's an IPv4 packet
                    if eth_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                            let size = ip_packet.packet().len();
                            let src_ip: Ipv4Addr = ip_packet.get_source();
                            let dst_ip: Ipv4Addr = ip_packet.get_destination();

                            // println!("Captured packet: {} -> {}", src_ip, dst_ip);

                            match ip_packet.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                        let src_port = tcp_packet.get_source();
                                        let dst_port = tcp_packet.get_destination();

                                        let src = SocketAddrV4::new(src_ip, src_port);
                                        let dst = SocketAddrV4::new(dst_ip, dst_port);

                                        if let Some(entity) = entities.get_mut(&src) {
                                            entity.up += size;
                                        } else if let Some(entity) = entities.get_mut(&dst) {
                                            entity.down += size;
                                        } else {
                                            // println!(
                                            //     "TCP Packet: {}:{} -> {}:{}",
                                            //     src_ip, src_port, dst_ip, dst_port
                                            // );
                                        }
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(_udp_packet) = UdpPacket::new(ip_packet.payload()) {
                                        // let src_port = udp_packet.get_source();
                                        // let dst_port = udp_packet.get_destination();
                                        // println!(
                                        //     "UDP Packet: {}:{} -> {}:{}",
                                        //     src_ip, src_port, dst_ip, dst_port
                                        // );
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
        if chrono::Utc::now().signed_duration_since(dt) > chrono::Duration::seconds(1) {
            for (_, entity) in &entities {
                let app = if let Some(stat) = &entity.stat {
                    format!("{:?}", stat.comm)
                } else {
                    "None".to_string()
                };
                info!(
                    "{} - up: {}, down: {}",
                    app,
                    format_size(entity.up),
                    format_size(entity.down)
                );
            }
            dt = chrono::Utc::now();
        }
    }
}

fn format_size(size: usize) -> String {
    let mut s = String::new();
    if size > 1024 * 1024 {
        s.push_str(&format!("{:.2}", size as f64 / 1024.0 / 1024.0));
        s.push_str("MB");
    } else if size > 1024 {
        s.push_str(&format!("{:.2}", size as f64 / 1024.0));
        s.push_str("KB");
    } else {
        s.push_str(&format!("{}B", size));
    }
    s
}

fn get_processes() -> Result<HashMap<u64, Stat>, OPGError> {
    let all_procs = procfs::process::all_processes()?;

    let mut map: HashMap<u64, Stat> = HashMap::new();
    for p in all_procs {
        let process = p?;
        if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd?.target {
                    map.insert(inode, stat.clone());
                }
            }
        }
    }
    Ok(map)
}
