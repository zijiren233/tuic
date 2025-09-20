use std::{net::SocketAddr, path::PathBuf, time::Duration};

use educe::Educe;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use lexopt::{Arg, Parser};
use serde::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, warn};

use crate::{
    old_config::{ConfigError, OldConfig},
    utils::CongestionController,
    v2board::V2BoardConfig,
};

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub log_level: LogLevel,
    #[educe(Default(expression = "[::]:443".parse().unwrap()))]
    pub server: SocketAddr,

    // V2Board configuration (required for authentication)
    pub v2board: V2BoardApiConfig,

    pub tls: TlsConfig,

    #[educe(Default = "")]
    pub data_dir: PathBuf,

    pub quic: QuicConfig,

    #[educe(Default = true)]
    pub udp_relay_ipv6: bool,

    #[educe(Default = false)]
    pub zero_rtt_handshake: bool,

    #[educe(Default = true)]
    pub dual_stack: bool,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(3)))]
    pub auth_timeout: Duration,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(3)))]
    pub task_negotiation_timeout: Duration,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(10)))]
    pub gc_interval: Duration,

    #[serde(alias = "gc_lifetime", with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(30)))]
    pub gc_lifetime: Duration,

    #[educe(Default = 1500)]
    pub max_external_packet_size: usize,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(60)))]
    pub stream_timeout: Duration,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub self_sign: bool,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    #[educe(Default(expression = Vec::new()))]
    pub alpn: Vec<String>,
    #[educe(Default(expression = "localhost"))]
    pub hostname: String,
    #[educe(Default(expression = false))]
    pub auto_ssl: bool,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    pub congestion_control: CongestionControlConfig,

    #[educe(Default = 1200)]
    pub initial_mtu: u16,

    #[educe(Default = 1200)]
    pub min_mtu: u16,

    #[educe(Default = true)]
    pub gso: bool,

    #[educe(Default = true)]
    pub pmtu: bool,

    #[educe(Default = 16777216)]
    pub send_window: u64,

    #[educe(Default = 8388608)]
    pub receive_window: u32,

    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(30)))]
    pub max_idle_time: Duration,
}
#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct CongestionControlConfig {
    pub controller: CongestionController,
    #[educe(Default = 1048576)]
    pub initial_window: u64,
}


#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct V2BoardApiConfig {
    #[educe(Default = "https://your-v2board-api.com")]
    pub api_host: String,
    #[educe(Default = "YOUR_API_KEY")]
    pub api_key: String,
    #[educe(Default = 1)]
    pub node_id: u32,
    #[educe(Default = 1024)] // 1MB threshold
    pub traffic_threshold: u64,
    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(60)))]
    pub update_interval: Duration,
    #[serde(with = "humantime_serde")]
    #[educe(Default(expression = Duration::from_secs(120)))]
    pub push_interval: Duration,
}

impl From<V2BoardApiConfig> for V2BoardConfig {
    fn from(config: V2BoardApiConfig) -> Self {
        Self {
            api_host: config.api_host,
            api_key: config.api_key,
            node_id: config.node_id,
            traffic_threshold: config.traffic_threshold,
            update_interval: config.update_interval,
            push_interval: config.push_interval,
        }
    }
}

impl Config {
    pub fn full_example() -> Self {
        Self {
            v2board: V2BoardApiConfig::default(),
            ..Default::default()
        }
    }
}

/// TODO remove in 2.0.0 - Old config no longer supported with V2Board
impl From<OldConfig> for Config {
    fn from(_value: OldConfig) -> Self {
        panic!("Old configuration format is no longer supported. Please configure V2Board authentication.")
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[educe(Default)]
    Info,
    Warn,
    Error,
    Off,
}
impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Off => LevelFilter::OFF,
        }
    }
}

pub async fn parse_config(mut parser: Parser) -> Result<Config, ConfigError> {
    let mut cfg_path = None;

    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('c') | Arg::Long("config") => {
                if cfg_path.is_none() {
                    cfg_path = Some(PathBuf::from(parser.value()?));
                } else {
                    return Err(ConfigError::Argument(arg.unexpected()));
                }
            }
            Arg::Short('v') | Arg::Long("version") => {
                return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
            }
            Arg::Short('h') | Arg::Long("help") => {
                return Err(ConfigError::Help(crate::old_config::HELP_MSG));
            }
            Arg::Short('i') | Arg::Long("init") => {
                warn!("Generating a example configuration to config.toml......");
                let example = Config::full_example();
                let example = toml::to_string_pretty(&example).unwrap();
                tokio::fs::write("config.toml", example).await?;
                return Err(ConfigError::Help("Done")); // TODO refactor
            }
            _ => return Err(ConfigError::Argument(arg.unexpected())),
        }
    }

    if cfg_path.is_none() || !cfg_path.as_ref().unwrap().exists() {
        return Err(ConfigError::NoConfig);
    }
    let cfg_path = cfg_path.unwrap();

    let mut config: Config = if cfg_path.extension().is_some_and(|v| v == "toml")
        || std::env::var("TUIC_FORCE_TOML").is_ok()
    {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(&cfg_path))
            .extract()
            .map_err(std::io::Error::other)?
    } else {
        let config_text = tokio::fs::read(&cfg_path).await?;
        let config: OldConfig = serde_json::from_slice(&config_text)?;
        config.into()
    };

    if config.data_dir.to_str() == Some("") {
        config.data_dir = std::env::current_dir()?
    } else if config.data_dir.is_relative() {
        config.data_dir = std::env::current_dir()?.join(config.data_dir);
        tokio::fs::create_dir_all(&config.data_dir).await?;
    } else {
        tokio::fs::create_dir_all(&config.data_dir).await?;
    };

    // Determine certificate and key paths
    let base_dir = config.data_dir.clone();
    config.tls.certificate = if config.tls.auto_ssl && config.tls.certificate.to_str() == Some("") {
        config
            .data_dir
            .join(format!("{}.cer.pem", config.tls.hostname))
    } else if config.tls.certificate.is_relative() {
        config.data_dir.join(&config.tls.certificate)
    } else {
        config.tls.certificate.clone()
    };

    config.tls.private_key = if config.tls.auto_ssl && config.tls.private_key.to_str() == Some("") {
        config
            .data_dir
            .join(format!("{}.key.pem", config.tls.hostname))
    } else if config.tls.private_key.is_relative() {
        base_dir.join(&config.tls.private_key)
    } else {
        config.tls.private_key.clone()
    };
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        net::{Ipv6Addr, SocketAddrV6},
    };

    use tempfile::tempdir;

    use super::*;

    async fn test_parse_config(
        config_content: &str,
        extension: &str,
        args: &[&str],
    ) -> Result<Config, ConfigError> {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join(format!("config{}", extension));
        let config_content: Vec<String> = config_content
            .lines()
            .map(|line| line.trim().to_string())
            .collect();
        let config = config_content.join("\n");
        fs::write(&config_path, &config).unwrap();

        std::fs::write("dbg.toml", config).unwrap();
        let mut os_args = vec!["test_binary".to_owned()];
        os_args.extend(args.iter().map(|s| s.to_string()));
        os_args.push("--config".to_owned());
        os_args.push(config_path.to_string_lossy().into_owned());

        parse_config(Parser::from_iter(os_args.into_iter())).await
    }

    #[tokio::test]
    async fn test_valid_toml_config() -> eyre::Result<()> {
        let config = r#"
            log_level = "warn"
            server = "127.0.0.1:8080"
            data_dir = "__test__custom_data"
            udp_relay_ipv6 = false
            zero_rtt_handshake = true

            [tls]
            self_sign = true
            auto_ssl = true
            hostname = "testhost"

            [quic]
            initial_mtu = 1400
            min_mtu = 1300
            send_window = 10000000

            [quic.congestion_control]
            controller = "bbr"
            initial_window = 2000000

            [restful]
            addr = "192.168.1.100:8081"
            secret = "test_secret"
            maximum_clients_per_user = 5

            [users]
            "123e4567-e89b-12d3-a456-426614174000" = "password1"
            "123e4567-e89b-12d3-a456-426614174001" = "password2"
        "#;

        let result = test_parse_config(config, ".toml", &[]).await.unwrap();

        assert_eq!(result.log_level, LogLevel::Warn);
        assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(result.udp_relay_ipv6, false);
        assert_eq!(result.zero_rtt_handshake, true);

        assert_eq!(result.tls.self_sign, true);
        assert_eq!(result.tls.auto_ssl, true);
        assert_eq!(result.tls.hostname, "testhost");

        assert_eq!(result.quic.initial_mtu, 1400);
        assert_eq!(result.quic.min_mtu, 1300);
        assert_eq!(result.quic.send_window, 10000000);
        assert_eq!(
            result.quic.congestion_control.controller,
            CongestionController::Bbr
        );
        assert_eq!(result.quic.congestion_control.initial_window, 2000000);

        let restful = result.restful.unwrap();
        assert_eq!(restful.addr, "192.168.1.100:8081".parse().unwrap());
        assert_eq!(restful.secret, "test_secret");
        assert_eq!(restful.maximum_clients_per_user, 5);

        let uuid1 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let uuid2 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").unwrap();
        assert_eq!(result.users.get(&uuid1), Some(&"password1".to_string()));
        assert_eq!(result.users.get(&uuid2), Some(&"password2".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn test_old_json_config() {
        let config = r#"{
            "log_level": "error",
            "server": "[::1]:8443",
            "users": {
                "123e4567-e89b-12d3-a456-426614174002": "old_password"
            },
            "tls": {
                "self_sign": false,
                "certificate": "old_cert.pem",
                "private_key": "old_key.pem"
            },
            "data_dir": "__test__legacy_data"
        }"#;

        let result = test_parse_config(config, ".json", &[]).await.unwrap();

        assert_eq!(result.log_level, LogLevel::Error);
        assert_eq!(
            result.server,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
        );

        let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174002").unwrap();
        assert_eq!(result.users.get(&uuid), Some(&"old_password".to_string()));

        assert_eq!(result.tls.self_sign, false);
        assert!(result.data_dir.ends_with("__test__legacy_data"));
    }

    #[tokio::test]
    async fn test_path_handling() {
        let config = r#"
            data_dir = "__test__relative_path"

            [tls]
            certificate = "certs/server.crt"
            private_key = "certs/server.key"
        "#;

        let result = test_parse_config(config, ".toml", &[]).await.unwrap();

        let current_dir = env::current_dir().unwrap();

        assert_eq!(result.data_dir, current_dir.join("__test__relative_path"));

        assert_eq!(
            result.tls.certificate,
            current_dir
                .join("__test__relative_path")
                .join("certs/server.crt")
        );
        assert_eq!(
            result.tls.private_key,
            current_dir
                .join("__test__relative_path")
                .join("certs/server.key")
        );
    }

    #[tokio::test]
    async fn test_auto_ssl_path_generation() {
        let config = r#"
            data_dir = "__test__ssl_data"
            [tls]
            auto_ssl = true
            hostname = "example.com"
        "#;

        let result = test_parse_config(config, ".toml", &[]).await.unwrap();

        let expected_cert = env::current_dir()
            .unwrap()
            .join("__test__ssl_data")
            .join("example.com.cer.pem");

        let expected_key = env::current_dir()
            .unwrap()
            .join("__test__ssl_data")
            .join("example.com.key.pem");

        assert_eq!(result.tls.certificate, expected_cert);
        assert_eq!(result.tls.private_key, expected_key);
    }

    #[tokio::test]
    async fn test_error_handling() {
        // Test Invalid TOML
        let config = "invalid toml content";
        let result = test_parse_config(config, ".toml", &[]).await;
        assert!(result.is_err());

        // Test Invalid JSON
        let config = "{ invalid json }";
        let result = test_parse_config(config, ".json", &[]).await;
        assert!(result.is_err());

        // Test non-existent configuration files
        let args = vec![
            "test_binary".to_owned(),
            "--config".to_owned(),
            "non_existent.toml".to_owned(),
        ];
        let result = parse_config(Parser::from_iter(args.into_iter())).await;
        assert!(matches!(result, Err(ConfigError::NoConfig)));

        // Test missing configuration file parameters
        let args = vec!["test_binary".to_owned()];
        let result = parse_config(Parser::from_iter(args.into_iter())).await;
        assert!(matches!(result, Err(ConfigError::NoConfig)));
    }
}
