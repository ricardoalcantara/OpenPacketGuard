#![cfg_attr(debug_assertions, allow(dead_code))]

use error::OPGError;
use processor::debug_processor::DebugProcessor;
use sniffer::sniffer_engine::SnifferEngine;
use std::env;

mod error;
mod firewall;
mod processor;
mod sniffer;
mod utils;

#[tokio::main]
async fn main() -> Result<(), OPGError> {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    SnifferEngine::new()
        .with_device_lookup()?
        .with_filter("udp port 7001")
        .with_processor(DebugProcessor::default())
        .run()?;

    Ok(())
}
