use crate::config::Config;
use crate::protocol::attestation::Attestation;
use crate::enclave::Enclave;
use crate::Key;
use rocksdb::DB;
use crate::db::get_db;
extern crate lazy_static;
use std::convert::TryInto;

pub struct Hub {
    pub config: Config,
    pub enclave: Enclave,
    pub key_database: DB,
}

impl Hub
{
    pub fn init() -> Self {

        let enclave = Enclave::new().expect("failed to start enclave");
        
        #[cfg(not(test))]
        let config = enclave.get_config();

        #[cfg(test)]
        let config = enclave.get_test_config();
	    let key_database = get_db(&config);
		
        let mut hub = Self {
            config,
            enclave,
            key_database,
        };

	    //Get the enclave id from the enclave
	    let report = hub.enclave.get_self_report().unwrap();
	    let key_id = report.body.mr_enclave.m;
        let mut key_uuid = uuid::Builder::from_bytes(key_id[..16].try_into().unwrap());

        let db_key = Key::from_uuid(&key_uuid.build());

	    //Get the sealed enclave key from the database and store it in the enclave struct
        hub.get_enclave_key(&db_key).unwrap();
        
	    hub
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial]
    fn test_init() {
        Hub::init();
    }

}
