//! # Error
//!
//! Custom Error types for Hub

//use shared_lib::error::SharedLibError;

use config_rs::ConfigError;
use std::error;
use std::fmt;
use std::time::SystemTimeError;


/// State Entity library specific errors
#[derive(Debug, Deserialize)]
pub enum HubError {
    /// Generic error from string error message
    Generic(String),
    /// Athorisation failed
    AuthError,
    /// DB error no ID found
    DBError(String),
    /// Client error
    ClientError(String)
}

impl From<String> for HubError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<rocksdb::Error> for HubError {
    fn from(e: rocksdb::Error) -> Self {
	HubError::DBError(e.into_string())
    }
}


impl From<SystemTimeError> for HubError {
    fn from(e: SystemTimeError) -> Self {
        Self::Generic(e.to_string())
    }
}

impl From<ConfigError> for HubError {
    fn from(e: ConfigError) -> Self {
        Self::Generic(e.to_string())
    }
}

impl From<reqwest::Error> for HubError {
    fn from(e: reqwest::Error) -> Self {
        Self::ClientError(e.to_string())
    }
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HubError::Generic(ref e) => write!(f, "Error: {}", e),
            HubError::AuthError => write!(f, "Authentication Error: User authorisation failed"),
            HubError::DBError(ref e) => write!(f, "DB Error: {}", e),
	    HubError::ClientError(ref e) => write!(f, "Client Error: {}", e),
        }
    }
}

impl error::Error for HubError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}