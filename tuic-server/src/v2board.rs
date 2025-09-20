use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use reqwest::Client;
use serde::Deserialize;
use tokio::time;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct V2BoardConfig {
    pub api_host: String,
    pub api_key: String,
    pub node_id: u32,
    pub traffic_threshold: u64, // KB
    pub update_interval: Duration,
    pub push_interval: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: u32,
    pub uuid: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub users: Vec<User>,
}

#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub tx: u64, // bytes
    pub rx: u64, // bytes
}


pub struct V2BoardProvider {
    config: V2BoardConfig,
    client: Client,
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    traffic_stats: Arc<RwLock<HashMap<u32, TrafficStats>>>, // user_id -> stats
}

impl V2BoardProvider {
    pub fn new(config: V2BoardConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            users: Arc::new(RwLock::new(HashMap::new())),
            traffic_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn fetch_users(&self) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/api/v1/server/UniProxy/user?token={}&node_id={}&node_type=tuic",
            self.config.api_host, self.config.api_key, self.config.node_id
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()).into());
        }

        let api_response: ApiResponse = response.json().await?;
        Ok(api_response.users)
    }

    pub async fn start_user_sync(&self) {
        let provider = self.clone();
        tokio::spawn(async move {
            info!("Starting user synchronization with interval: {:?}", provider.config.update_interval);

            let mut interval = time::interval(provider.config.update_interval);

            loop {
                interval.tick().await;

                match provider.fetch_users().await {
                    Ok(users) => {
                        let mut user_map = HashMap::new();
                        for user in users {
                            if let Ok(uuid) = Uuid::parse_str(&user.uuid) {
                                user_map.insert(uuid, user);
                            } else {
                                warn!("Invalid UUID format: {}", user.uuid);
                            }
                        }

                        {
                            let mut users_lock = provider.users.write().unwrap();
                            *users_lock = user_map;
                        }

                        debug!("Updated user list with {} users", provider.users.read().unwrap().len());
                    }
                    Err(e) => {
                        error!("Failed to fetch users: {}", e);
                    }
                }
            }
        });
    }

    pub async fn start_traffic_push(&self) {
        let provider = self.clone();
        tokio::spawn(async move {
            info!("Starting traffic push with interval: {:?}", provider.config.push_interval);

            let mut interval = time::interval(provider.config.push_interval);

            loop {
                interval.tick().await;

                if let Err(e) = provider.push_traffic().await {
                    error!("Failed to push traffic data: {}", e);
                }
            }
        });
    }

    async fn push_traffic(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut push_data = HashMap::new();

        // Collect traffic data to push
        {
            let mut stats_lock = self.traffic_stats.write().unwrap();
            for (user_id, stats) in stats_lock.iter() {
                let total_bytes = stats.tx + stats.rx;
                let total_kb = total_bytes / 1024;

                if total_kb >= self.config.traffic_threshold {
                    push_data.insert(user_id.to_string(), [stats.tx / 1024, stats.rx / 1024]);
                }
            }

            // Clear pushed stats
            for user_id in push_data.keys() {
                if let Ok(id) = user_id.parse::<u32>() {
                    stats_lock.remove(&id);
                }
            }
        }

        if push_data.is_empty() {
            return Ok(());
        }

        let url = format!(
            "{}/api/v1/server/UniProxy/push?token={}&node_id={}&node_type=tuic",
            self.config.api_host, self.config.api_key, self.config.node_id
        );

        let response = self.client
            .post(&url)
            .json(&push_data)
            .send()
            .await?;

        if !response.status().is_success() {
            // Restore stats on failure
            let mut stats_lock = self.traffic_stats.write().unwrap();
            for (user_id, traffic) in push_data {
                if let Ok(id) = user_id.parse::<u32>() {
                    let stats = stats_lock.entry(id).or_insert(TrafficStats { tx: 0, rx: 0 });
                    stats.tx += traffic[0] * 1024;
                    stats.rx += traffic[1] * 1024;
                }
            }
            return Err(format!("HTTP error: {}", response.status()).into());
        }

        debug!("Successfully pushed traffic data for {} users", push_data.len());
        Ok(())
    }


    pub fn authenticate(&self, uuid: &Uuid) -> bool {
        let users = self.users.read().unwrap();
        users.contains_key(uuid)
    }

    pub fn get_user(&self, uuid: &Uuid) -> Option<User> {
        let users = self.users.read().unwrap();
        users.get(uuid).cloned()
    }

    pub fn log_traffic(&self, uuid: &Uuid, tx: u64, rx: u64) -> bool {
        if let Some(user) = self.get_user(uuid) {
            let mut stats_lock = self.traffic_stats.write().unwrap();
            let stats = stats_lock.entry(user.id).or_insert(TrafficStats { tx: 0, rx: 0 });
            stats.tx += tx;
            stats.rx += rx;
            true
        } else {
            false
        }
    }
}

impl Clone for V2BoardProvider {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            users: Arc::clone(&self.users),
            traffic_stats: Arc::clone(&self.traffic_stats),
        }
    }
}