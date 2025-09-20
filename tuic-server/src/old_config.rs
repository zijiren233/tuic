use std::{
    collections::HashMap, fmt::Display, io::Error as IoError, net::SocketAddr, path::PathBuf,
    str::FromStr, time::Duration,
};

use humantime::Duration as HumanDuration;
use lexopt::Error as ArgumentError;
use serde::{Deserialize, Deserializer, de::Error as DeError};
use serde_json::Error as SerdeError;
use thiserror::Error;
use uuid::Uuid;

use crate::{config::LogLevel, utils::CongestionController};

pub const HELP_MSG: &str = r#"
Usage tuic-server [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
    -i, --init              Generate a example configuration (config.toml)
"#;

mod default {
    use std::{path::PathBuf, time::Duration};

    use crate::utils::CongestionController;

    pub fn congestion_control() -> CongestionController {
        CongestionController::Cubic
    }

    pub fn udp_relay_ipv6() -> bool {
        true
    }

    pub fn zero_rtt_handshake() -> bool {
        false
    }

    pub fn auth_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn task_negotiation_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn max_idle_time() -> Duration {
        Duration::from_secs(10)
    }

    pub fn max_external_packet_size() -> usize {
        1500
    }

    pub fn initial_window() -> Option<u64> {
        None
    }

    pub fn send_window() -> u64 {
        8 * 1024 * 1024 * 2
    }

    pub fn receive_window() -> u32 {
        8 * 1024 * 1024
    }

    // struct.TransportConfig#method.initial_mtu
    pub fn initial_mtu() -> u16 {
        1200
    }

    // struct.TransportConfig#method.min_mtu
    pub fn min_mtu() -> u16 {
        1200
    }

    // struct.TransportConfig#method.enable_segmentation_offload
    // aka. Generic Segmentation Offload
    pub fn gso() -> bool {
        true
    }

    // struct.TransportConfig#method.mtu_discovery_config
    // if not pmtu() -> mtu_discovery_config(None)
    pub fn pmtu() -> bool {
        true
    }

    pub fn gc_interval() -> Duration {
        Duration::from_secs(3)
    }

    pub fn gc_lifetime() -> Duration {
        Duration::from_secs(15)
    }

    pub fn certificate() -> PathBuf {
        PathBuf::new()
    }

    pub fn private_key() -> PathBuf {
        PathBuf::new()
    }

    pub fn auto_ssl() -> bool {
        false
    }

    pub fn hostname() -> String {
        "localhost".to_string()
    }

    pub fn self_sign() -> bool {
        false
    }

    pub fn alpn() -> Vec<String> {
        Vec::new()
    }
}

pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(DeError::custom)
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    s.parse::<HumanDuration>()
        .map(|d| *d)
        .map_err(DeError::custom)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0}")]
    Argument(#[from] ArgumentError),
    #[error("no config file specified or file doesn't exist")]
    NoConfig,
    #[error("{0}")]
    Version(&'static str),
    #[error("{0}")]
    Help(&'static str),
    #[error("{0}")]
    Io(#[from] IoError),
    #[error("{0}")]
    Serde(#[from] SerdeError),
}
