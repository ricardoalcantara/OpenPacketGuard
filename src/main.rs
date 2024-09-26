use error::OPGError;
use log::{error, info};
use std::{
    env,
    time::{Duration, Instant},
};

mod error;
mod firewall;
mod monitor;
mod sniffer;

#[tokio::main]
async fn main() -> Result<(), OPGError> {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let monitor = monitor::Monitor::new();
    // monitor.start();
    // monitor.wait().await.unwrap();

    // let firewall = firewall::Firewall::new();

    let mut sniffer = sniffer::SnifferEngine::new();
    let Some(device) = sniffer.lookup()? else {
        panic!("No device found");
    };

    // sniffer.apply_filter("")?;
    sniffer.start_capture(device)?;

    loop {
        std::thread::sleep(Duration::from_secs(2));
        let start = Instant::now();

        let (len, size) = sniffer.get_statistics().await?;
        let stats = monitor.get_stats()?;

        let duration = start.elapsed();

        println!(
            "Cpu {} Mem {} Mb Packets {} Total {} - {:?}",
            stats.0,
            format_size(stats.1 as usize),
            len,
            format_size(size),
            duration
        );
    }

    Ok(())
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
