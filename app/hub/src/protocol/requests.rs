//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Instant;

use crate::client::Client;
use super::super::Result;
use crate::error::HubError;

pub fn post<T, V>(hub: &Client, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post(hub, path, body)
}

fn _post<T, V>(hub: &Client, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    // catch reqwest errors
    let value = match hub.client.post(&format!("{}/{}", hub.endpoint, path)).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("Hub POST value ignored because of size: {}", l);
                        return Err(HubError::Generic(format!(
                            "Hub POST value ignored because of size: {}",
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

    info!("Hub request {}, took: {})", path, TimeFormat(start.elapsed()));
    Ok(serde_json::from_str(value.as_str()).unwrap())
}

pub fn get<V>(hub: &Client, path: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    let b = hub
        .client
        .get(&format!("{}/{}", hub.endpoint, path));

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(HubError::from(e)),
    };

    info!("GET return value: {:?}", value);

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(HubError::Generic(value));
    }

    Ok(serde_json::from_str(value.as_str()).unwrap())
}
