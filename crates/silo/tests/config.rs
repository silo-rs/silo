use silo::config::{NetworkConfig, SiloConfig};

#[test]
fn parse_minimal_config() {
    let content = r#"
[network]
range = "127.2.0.0/16"
"#;
    let config: SiloConfig = toml::from_str(content).unwrap();
    assert_eq!(config.network.range, "127.2.0.0/16");
}

#[test]
fn parse_empty_config_uses_defaults() {
    let content = "";
    let config: SiloConfig = toml::from_str(content).unwrap();
    assert_eq!(config.network.range, "127.1.0.0/16");
}

#[test]
fn parse_config_without_network_section() {
    let content = "# empty config file\n";
    let config: SiloConfig = toml::from_str(content).unwrap();
    assert_eq!(config.network.range, "127.1.0.0/16");
}

#[test]
fn default_network_config() {
    let config = NetworkConfig::default();
    assert_eq!(config.range, "127.1.0.0/16");
}
