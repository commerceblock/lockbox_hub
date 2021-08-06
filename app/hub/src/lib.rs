#![allow(unused_parens)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene, decl_macro)]
extern crate chrono;
extern crate config as config_rs;
extern crate uuid;
#[macro_use]
extern crate failure;
extern crate error_chain;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate cfg_if;
extern crate hex;
extern crate jsonwebtoken as jwt;
extern crate log4rs;
extern crate rocksdb;
extern crate tempdir;
extern crate num_traits;
extern crate rand;
extern crate lazy_static;
extern crate reqwest;
extern crate floating_duration;

extern crate sgx_types;
extern crate sgx_urts;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate serde_cbor;
#[macro_use]
extern crate serde_big_array;

big_array! { BigArray; }

extern crate mockall;
#[cfg(test)]
extern crate mockito;
#[cfg(test)]
#[macro_use]
extern crate serial_test;
extern crate shared_lib;
extern crate url;

pub mod config;
pub mod error;
pub mod protocol;
pub mod hub;
pub mod client;
pub mod storage;
pub mod enclave;
pub mod db;

pub type Result<T> = std::result::Result<T, error::HubError>;

use uuid::Uuid;
use std::convert::{From, AsRef};
use std::{fmt, time::Duration};
use crate::error::HubError;
use url::Url;

#[derive(Clone, Debug)]
pub struct Key(Uuid);

impl Key {
    fn from_uuid(id: &Uuid) -> Self {
	Self(*id)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8]{
	self.0.as_bytes()
    }
}

impl fmt::Display for Key {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({})", self.0)
    }
}

impl From<u32> for Key {
    fn from(item : u32) -> Self {
	Self(Uuid::from_u128(item as u128))
    }
}

pub struct Client {
    pub client: reqwest::blocking::Client,
    pub endpoint: String,
    pub active: bool,
}

impl Client {
    pub fn new(endpoint: &Url) -> Client {
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(60)).build().unwrap();
        let endpoint_str = endpoint.as_str();
        let active = endpoint_str.len() > 0;
        let lb = Client {
            client,
            endpoint: String::from(endpoint_str),
            active,
        };
        lb
    }
}

pub fn post<T, V>(client: &Client, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post(client, path, body)
}

fn _post<T, V>(client: &Client, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    // catch reqwest errors
    let value = match client.client.post(&format!("{}/{}", client.endpoint, path)).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        return Err(HubError::Generic(format!(
                            "POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        }
        Err(e) => return Err(HubError::from(e)),
    };
    
    match serde_json::from_str(value.as_str()) {
	    Ok(r) => Ok(r),
	    Err(e) => {
	        Err(HubError::Generic(format!("Error derserialising POST response: {}: {}", value.as_str(), e)))
	    }
    }
}

pub fn get<V>(client: &Client, path: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));

    let b = client
        .client
        .get(&format!("{}/{}", client.endpoint, path));

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(HubError::from(e)),
    };

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(HubError::Generic(value));
    }

    Ok(serde_json::from_str(value.as_str()).unwrap())
}