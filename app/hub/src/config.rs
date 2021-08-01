//! # Config
//!
//! Config module handling config options from file and env

use super::Result;

use config_rs::{Config as ConfigRs, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;
extern crate lazy_static;
use lazy_static::lazy_static; // 1.4.0
use uuid::Uuid;
use url::Url;

lazy_static! {
    static ref CONFIG: Config = Config::load().unwrap();
}

pub fn get_config() -> Config {
    (*CONFIG).clone()
}

lazy_static! {
    static ref TEST_CONFIG: Config = Config::test_config();
}

pub fn get_test_config() -> Config {
    (*TEST_CONFIG).clone()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Storage specific config
pub struct StorageConfig {
    pub db_path: String,
    pub key_db_path: String,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
	    db_path: String::from(""),
        key_db_path: String::from(""),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Client specific config
pub struct ClientConfig {
    pub lockbox_urls: String,
}

impl Default for ClientConfig {
    fn default() -> ClientConfig {
        ClientConfig {
	        lockbox_urls: String::from(""),
        }
    }
}

impl ClientConfig {
    pub fn get_urls(&self) -> Result<Vec::<Url>> {
        let mut urls = Vec::<Url>::new();
        
        for url in self.lockbox_urls.split(","){
            let url = url.replace(" ", "");
            urls.push(Url::parse(&url).expect(&format!("ClientConfig - error parsing url: {}", &url)));
        }
        Ok(urls)
    }
}

/// Enclave specific config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnclaveConfig {
    pub index: u32,
}

impl Default for EnclaveConfig {
    fn default() -> EnclaveConfig {
        EnclaveConfig {
	    index: 0,
        }
    }
}

/// Config struct storing all StataChain Entity config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Log file location. If not present print to stdout
    pub log_file: String,
    /// Testing mode
    pub testing_mode: bool,
    /// Storage config
    pub storage: StorageConfig,
    /// Enclave config
    pub enclave: EnclaveConfig,
    /// Client config
    pub client: ClientConfig
}

impl Default for Config {
    fn default() -> Config {
        Config {
            log_file: String::from(""),
            testing_mode: true,
            storage: StorageConfig::default(),
	        enclave: EnclaveConfig::default(),
	        client: ClientConfig::default(),
        }
    }
}

impl Config {
    /// Load Config instance reading default values, overridden with Settings.toml,
    /// overriden with environment variables in form HUB_[setting_name]
    pub fn load() -> Result<Self> {
        let mut conf_rs = ConfigRs::new();
        let _ = conf_rs
        // First merge struct default config
        .merge(ConfigRs::try_from(&Config::default())?)?;
        // Override with settings in file Settings.toml if exists
        conf_rs.merge(File::with_name("Settings").required(false))?;
        // Override any config from env using HUB prefix
        conf_rs.merge(Environment::with_prefix("HUB"))?;

        if let Ok(v) = env::var("HUB_KEY_DB_PATH") {
            let _ = conf_rs.set("storage.key_db_path", v)?;
        }
	
	    if let Ok(v) = env::var("HUB_ENC_INDEX") {
            let _ = conf_rs.set("enclave.index", v)?;
	    }

	    if let Ok(v) = env::var("HUB_LOCKBOX_URLS") {
            let _ = conf_rs.set("client.lockbox_urls", v)?;
	    }   
	
        Ok(conf_rs.try_into()?)
    }

    pub fn test_config() -> Self {

        let db_uuid = Uuid::new_v4();

        Config{
            log_file: String::from("test/log.txt"),
            testing_mode: true,
            storage: StorageConfig{
                db_path: format!("/tmp/test_db_{}", db_uuid),
                key_db_path: format!("/tmp/test_key_db_{}", db_uuid),
            },
            enclave: EnclaveConfig{
                index: 0
            },
            client: ClientConfig{
                lockbox_urls: String::from("\"http://0.0.0.0:8001,http://0.0.0.0:8002\"")
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_config() {
        let _config = get_test_config();
    }

    #[test]
    fn test_get_urls() {
        let _config = get_test_config();
        let urls = _config.client.get_urls().unwrap();
        assert_eq!(urls[0],Url::parse("http://0.0.0.0:8001").unwrap());
        assert_eq!(urls[1],Url::parse("http://0.0.0.0:8002").unwrap());
    }

    #[test]
    fn test_config() {
        let _config = get_config();
    }
}