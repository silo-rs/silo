use std::path::PathBuf;

use serde::Deserialize;
use tracing::debug;

const DEFAULT_RANGE: &str = "127.1.0.0/16";

#[derive(Debug, Deserialize)]
pub struct SiloConfig {
    #[serde(default)]
    pub network: NetworkConfig,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_range")]
    pub range: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            range: default_range(),
        }
    }
}

fn default_range() -> String {
    DEFAULT_RANGE.to_string()
}

pub fn load_config() -> SiloConfig {
    if let Ok(val) = std::env::var("SILO_IP_RANGE") {
        debug!(range = %val, "using SILO_IP_RANGE from environment");
        return SiloConfig {
            network: NetworkConfig { range: val },
        };
    }

    if let Some(path) = config_path()
        && path.exists()
    {
        debug!(path = %path.display(), "loading config file");
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(config) = toml::from_str::<SiloConfig>(&content)
        {
            return config;
        }
    }

    SiloConfig {
        network: NetworkConfig::default(),
    }
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("silo").join("config.toml"))
}
