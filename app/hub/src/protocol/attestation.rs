
    

//! Lockbox Attestation
//!
//! Lockbox Attestation protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::structs::*;


use crate::error::HubError;
use crate::hub::Hub;

use std::convert::TryInto;
use crate::Key;

/// Lockbox Attestation protocol trait
pub trait Attestation { 
	fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2>;
    fn proc_msg3(&mut self, dh_msg3: &DHMsg3) -> Result<()>;
    fn end_session(&self) -> Result<()>;
    fn enclave_id(&self) -> EnclaveIDMsg;
    fn put_enclave_key(&mut self, db_key: &Key, sealed_log: [u8; 8192]) -> Result<()>;
    fn get_enclave_key(&mut self, db_key: &Key) -> Result<[u8; 8192]>;
	fn get_session_enclave_key(&mut self) -> Result<[u8; 8192]>;
}

impl Attestation for Hub{
    fn end_session(&self) -> Result<()> {
		println!("doing end session");
		Ok(())
    }

    fn enclave_id(&self) -> EnclaveIDMsg {
        EnclaveIDMsg { inner: self.enclave.geteid() }
    }

    fn put_enclave_key(&mut self, db_key: &Key, sealed_log: [u8; 8192]) -> Result<()> {
		let cf = match self.key_database.cf_handle("enclave_key"){
	    	Some(x) => x,
	    	None => return Err(HubError::Generic(String::from("enclave_key not found"))),
		};
		match self.key_database.put_cf(cf, db_key, &sealed_log){
	    	Ok(_) => {
				self.enclave.set_ec_key(Some(sealed_log));
				Ok(())
	    	},
	    	Err(e) => Err(HubError::Generic(format!("{}",e))),
		}
	}

    fn get_enclave_key(&mut self, db_key: &Key) -> Result<[u8; 8192]> {
		let cf = &self.key_database.cf_handle("enclave_key").ok_or(HubError::Generic(String::from("expected database handle \"enclave_key\" to exist")))?;
		dbg!("getting key from database");
		match self.key_database.get_cf(cf, db_key){
	    	Ok(Some(x)) => match x.try_into() {
				Ok(x) => {
					dbg!("setting key in enclave");
		    		self.enclave.set_ec_key(Some(x));
		    		match self.enclave.set_ec_key_enclave(x){
						Ok(_) => match self.enclave.get_ec_key(){
							Some(ec_key) => Ok(*ec_key),
							None => Err(HubError::Generic(String::from("expected some enclave key, got None"))),
						},
						Err(e) => Err(HubError::Generic(format!("Error setting enclave key: {}", e)))
					}
				},
				Err(e) => return Err(HubError::Generic(format!("sealed enclave key format error: {:?}", e))),
	    	},
	    	Ok(None) => {
				dbg!("setting a random ec key");
				//set a random ec key
				self.enclave.set_random_ec_key().map_err(|e| HubError::Generic(format!("Error setting enclave key: {}", e)))?;
				dbg!("getting ec key");
				let ec_key = *self.enclave.get_ec_key();
				match ec_key {
					Some(ec_key) => {
						dbg!("setting ec key");
						self.enclave.set_ec_key(Some(ec_key.clone()));
						dbg!("putting ec key");
						self.put_enclave_key(&db_key, ec_key)?;
						dbg!("putting ec key - ok");
						Ok(ec_key)
					},
					None => Err(HubError::Generic(String::from("expected some enclave key, got None"))),
				}
			},
	    	Err(e) => Err(e.into()),
		} 
    }

	fn get_session_enclave_key(&mut self) -> Result<[u8; 8192]> {
		self.enclave.get_session_enclave_key().map_err(|x| 
			HubError::Generic(format!("get session enclave key error: {}", x)))
	}

	fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2> {
		match self.enclave.proc_msg1(dh_msg1) {
			Ok(r) => {
			Ok(r)
			},
			Err(e) => Err(HubError::Generic(format!("proc_msg1: {}",e))),
		}
	}
	
	fn proc_msg3(&mut self, dh_msg3: &DHMsg3) -> Result<()> {
		let (db_key, sealed_log) = match self.enclave.proc_msg3(dh_msg3) {
			Ok(sealed_log) => {
				let key_id = dh_msg3.inner.msg3_body.report.body.mr_enclave.m;
				let mut key_uuid = uuid::Builder::from_bytes(key_id[..16].try_into().unwrap());
				let db_key = Key::from_uuid(&key_uuid.build());
	
				(db_key, sealed_log)
			},
				Err(e) => return Err(HubError::Generic(format!("proc_msg3: {}",e))),
		};
		self.put_enclave_key(&db_key, sealed_log)
	}
}
