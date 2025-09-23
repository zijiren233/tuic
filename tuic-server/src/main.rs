use std::{
    collections::{HashMap, HashSet},
    process,
    sync::{Arc, atomic::AtomicUsize},
};

use chashmap::CHashMap;
use config::{Config, parse_config};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::{old_config::ConfigError, server::Server, v2board::V2BoardProvider};

mod acl;
mod compat;
mod config;
mod connection;
mod error;
mod io;
mod old_config;
mod server;
mod tls;
mod utils;
mod v2board;

#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

struct AppContext {
    pub cfg: Config,
    pub v2board: Option<V2BoardProvider>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg = match parse_config(lexopt::Parser::from_env()).await {
        Ok(cfg) => cfg,
        Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
            println!("{msg}");
            process::exit(0);
        },
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        },
    };

    // Initialize V2Board provider (now required)
    let provider = V2BoardProvider::new(cfg.v2board.clone().into());
    provider.start_user_sync().await;
    provider.start_traffic_push().await;

    let ctx = Arc::new(AppContext {
        cfg,
        v2board: Some(provider),
    });

    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("tuic", ctx.cfg.log_level),
            ("tuic_quinn", ctx.cfg.log_level),
            ("tuic_server", ctx.cfg.log_level),
        ])
        .with_default(LevelFilter::INFO);
    let registry = tracing_subscriber::registry();
    registry
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_timer(LocalTime::new(time::macros::format_description!(
                    "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
                ))),
        )
        .try_init()?;
    tokio::spawn(async move {
        match Server::init(ctx.clone()).await {
            Ok(server) => server.start().await,
            Err(err) => {
                eprintln!("{err}");
                process::exit(1);
            },
        }
    });
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");
    Ok(())
}
