use reqwest;

#[derive(Debug, Clone)]
pub struct Client {
    pub client: reqwest::blocking::Client,
    pub endpoint: String,
    pub active: bool,
}

impl Client {
    pub fn new(endpoint: String) -> Client {
        let client = reqwest::blocking::Client::new();
        let active = endpoint.len() > 0;
        let lb = Client {
            client,
            endpoint,
            active,
        };
        lb
    }
}
