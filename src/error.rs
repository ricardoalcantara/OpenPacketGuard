use anyhow::anyhow;
use std::panic::Location;
use thiserror::Error;

// #[macro_export]
// macro_rules! UnknownError {
//     () => {
//         Err(error::OPGError::UnknownError(std::panic::Location::caller()))
//     };
// }

#[macro_export]
macro_rules! here {
    () => {
        concat!(file!(), ":", line!())
    };
}

#[derive(Error, Debug)]
pub enum OPGError {
    #[error("procfs error: {0}, location: {1}")]
    ProcfsError(procfs::ProcError, &'static Location<'static>),
    #[error("pcap error: {0}, location: {1}")]
    PcapError(pcap::Error, &'static Location<'static>),
    #[error("io error: {0}, location: {1}")]
    IoError(std::io::Error, &'static Location<'static>),
    #[error("anyhow error: {0}, location: {1}")]
    AnyhowError(anyhow::Error, &'static Location<'static>),
    #[error("Box error: {0}, location: {1}")]
    BoxError(anyhow::Error, &'static Location<'static>),
    // #[error("unknown error: {0}")]
    // #[error("unknown error: {0}")]
    // UnknownError(&'static Location<'static>),
}

impl From<procfs::ProcError> for OPGError {
    fn from(e: procfs::ProcError) -> Self {
        OPGError::ProcfsError(e, Location::caller())
    }
}

impl From<pcap::Error> for OPGError {
    fn from(e: pcap::Error) -> Self {
        OPGError::PcapError(e, Location::caller())
    }
}

impl From<std::io::Error> for OPGError {
    fn from(e: std::io::Error) -> Self {
        OPGError::IoError(e, Location::caller())
    }
}

impl From<anyhow::Error> for OPGError {
    fn from(e: anyhow::Error) -> Self {
        OPGError::AnyhowError(e, Location::caller())
    }
}

impl From<Box<dyn std::error::Error>> for OPGError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        OPGError::BoxError(anyhow!(e.to_string()), Location::caller())
    }
}
