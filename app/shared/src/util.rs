//! Util
//!
//! Utilities methods for state entity protocol shared library

#[allow(dead_code)]
pub const RBF: u32 = 0xffffffff - 2;
pub const DUSTLIMIT: u64 = 100;
/// Temporary - fees should be calculated dynamically
pub const FEE: u64 = 1000;

pub mod keygen {
    pub use bitcoin::secp256k1::{key::SecretKey, Message, PublicKey, Secp256k1};
    pub use bitcoin::util;
    pub use bitcoin::{Amount, Network, OutPoint, Script};
    pub use rand::rngs::OsRng;
    pub const NETWORK: bitcoin::network::constants::Network = Network::Regtest;
    /// generate bitcoin::util::key key pair
    pub fn generate_keypair() -> (util::key::PrivateKey, util::key::PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = generate_secret_key();
        let priv_key = util::key::PrivateKey {
            compressed: true,
            network: NETWORK,
            key: secret_key,
        };
        let pub_key = util::key::PublicKey::from_private_key(&secp, &priv_key);
        return (priv_key, pub_key);
    }

    pub fn generate_secp_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = generate_secret_key();
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        return (secret_key, pub_key);
    }

    pub fn generate_secret_key() -> SecretKey {
        let mut rng = OsRng::new().expect("OsRng");
        SecretKey::new(&mut rng)
    }
}