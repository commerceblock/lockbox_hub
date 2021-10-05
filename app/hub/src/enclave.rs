use std::ops::{Deref, DerefMut};
extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;
use self::sgx_urts::SgxEnclave;
use crate::error::HubError;
use crate::shared_lib::structs::*;
use crate::config::Config;

extern crate bitcoin;

static ENCLAVE_FILE: &'static str = "/opt/lockbox_hub/bin/enclave.signed.so";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

//Shared encryption key for enclaves
pub const EC_KEY_SEALED_SIZE: usize = 650;
pub type EcKeySealed = [u8; EC_KEY_SEALED_SIZE];

pub const EC_LOG_SIZE: usize = 8192;
pub type EcLog = [u8; EC_LOG_SIZE];

pub const DH_MSG_SIZE: usize = 1800;
pub const DH_MSG3_SIZE: usize = 2000;

pub struct Enclave {
    inner: SgxEnclave,
    ec_key: Option<EcLog>
}

impl Deref for Enclave {
     type Target = SgxEnclave;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for Enclave {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


#[derive(Clone)]
pub struct SgxReport(sgx_report_t);

impl Deref for SgxReport {
    type Target = sgx_report_t;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/*
impl Serialize for SgxReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        // Any implementation of Serialize.
    }
}

impl DeSerialize for SgxReport {
    fn deserialize<D>(&self, deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer
    {
        // Any implementation of Serialize.
    }
}
 */

impl Enclave {
    pub fn new() -> Result<Self> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
		let mut launch_token_updated: i32 = 0;
    	// call sgx_create_enclave to initialize an enclave instance
    	// Debug Support: set 2nd parameter to 1
    	let debug = 1;
    	let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
		match SgxEnclave::create(ENCLAVE_FILE,
				 debug,
                       		 &mut launch_token,
                       		 &mut launch_token_updated,
                       		 &mut misc_attr){
	    	Ok(v) => Ok(Self{inner:v, ec_key: None}),
	    	Err(e) => {
				return Err(HubError::Generic(e.to_string()).into())
			},
		}
    }

	pub fn get_ec_key(&self) -> &Option<EcLog> {
		&self.ec_key
	}
	
	pub fn set_ec_key(&mut self, key: Option<EcLog>) {
		self.ec_key = key;
	}

	pub fn set_ec_key_enclave(&self, sealed_log: EcLog) -> Result<()> {
		
		let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
		let _result = unsafe {
	    	set_ec_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
		};
	
		match enclave_ret {
	    	sgx_status_t::SGX_SUCCESS => {
				Ok(())
			},
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
		}
    }

	pub fn get_session_enclave_key(&self) -> Result<EcLog> {
		let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
		let sealed_log = [0u8; 8192];
		let _result = unsafe {
			get_session_enclave_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8)
		};

		match enclave_ret {
	    	sgx_status_t::SGX_SUCCESS => {
				Ok(sealed_log)
			},
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
		}
	}
 		
	pub fn get_config(&self) -> Config {
		crate::config::get_config()
	}

	pub fn get_test_config(&self) -> Config {
		crate::config::get_test_config()
	}
   
    pub fn test_create_session(&self) -> Result<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe {
            test_create_session(self.geteid(),
				&mut retval)
    	};

		match result {
            sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }

    
    pub fn say_something(&self, input_string: String) -> Result<String> {
     	let mut retval = sgx_status_t::SGX_SUCCESS;
	
     	let result = unsafe {
            say_something(self.geteid(),
			  &mut retval,
			  input_string.as_ptr() as * const u8,
			  input_string.len())
    	};
	
    	match result {
            sgx_status_t::SGX_SUCCESS => Ok(result.as_str().to_string()),
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }

	pub fn set_random_ec_key(&mut self) -> Result<()> {
		let sealed_log = [0u8; 8192];
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let _result = unsafe { set_random_ec_key(self.geteid(), &mut retval,  sealed_log.as_ptr() as * mut u8 )}; 
		match retval {
			sgx_status_t::SGX_SUCCESS => {
				self.set_ec_key(Some(sealed_log));
				Ok(())
			},
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into())
		}
	}

    pub fn session_request(&self, id_msg: &EnclaveIDMsg) -> Result<DHMsg1> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let mut dh_msg1 = [0u8;DH_MSG_SIZE];

		//	let mut session_ptr: usize = 0;
		let src_enclave_id = id_msg.inner;


		match retval {
	    	sgx_status_t::SGX_SUCCESS  =>(),
	    	_ => return Err(HubError::Generic(format!("[-] ECALL Enclave Failed - say something {}!", retval.as_str())).into()),
		};
	
		
     	unsafe {
            session_request(self.geteid(),
			&mut retval,
			src_enclave_id,
			dh_msg1.as_mut_ptr() as *mut u8)
    	};
		
		match retval {
	    	sgx_status_t::SGX_SUCCESS  => {
			let c = dh_msg1[0].clone();
			let c = &[c];
			let nc_str = std::str::from_utf8(c).unwrap();
			let nc = nc_str.parse::<usize>().unwrap();
			let size_str = std::str::from_utf8(&dh_msg1[1..(nc+1)]).unwrap();
			let size = size_str.parse::<usize>().unwrap();
			let msg_str = std::str::from_utf8(&dh_msg1[(nc+1)..(size+nc+1)]).unwrap().to_string();
			let dh_msg1 : DHMsg1  = serde_json::from_str(&msg_str).unwrap();
			Ok(dh_msg1)
	    	},
	    	_ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed -  session_request {}!", retval.as_str())).into()),
		}
    }

    pub fn exchange_report(&self, ep_msg: &shared_lib::structs::ExchangeReportMsg) -> Result<(DHMsg3, EcLog)> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let sealed_log = [0u8; 8192];

		let mut dh_msg3_arr = [0u8;DH_MSG3_SIZE];
		let src_enclave_id = ep_msg.src_enclave_id;
		let dh_msg2_str = serde_json::to_string(&ep_msg.dh_msg2).unwrap();
		
     	unsafe {
            exchange_report(self.geteid(),
			    &mut retval,
			    src_enclave_id,
			    dh_msg2_str.as_ptr() as * const u8,
			    dh_msg2_str.len(),
			    dh_msg3_arr.as_mut_ptr() as *mut u8,
			    sealed_log.as_ptr() as * mut u8)
    	};

		match retval {
	    	sgx_status_t::SGX_SUCCESS  => {
			let c = dh_msg3_arr[0].clone();
			let c = &[c];
			let nc_str = std::str::from_utf8(c).unwrap();
			let nc = nc_str.parse::<usize>().unwrap();
			let size_str = std::str::from_utf8(&dh_msg3_arr[1..(nc+1)]).unwrap();
			let size = size_str.parse::<usize>().unwrap();
			let msg_str = std::str::from_utf8(&dh_msg3_arr[(nc+1)..(size+nc+1)]).unwrap().to_string();
			let dh_msg3 : DHMsg3  = serde_json::from_str(&msg_str).unwrap();
			Ok((dh_msg3, sealed_log))
	    	},
	    	_ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
		}
    }
    
    pub fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2> {
	let mut retval = sgx_status_t::SGX_SUCCESS;


	let mut dh_msg2_arr = [0u8;1800];
	
	let dh_msg1_str = serde_json::to_string(dh_msg1).unwrap();
	
     	unsafe {
            proc_msg1(self.geteid(),
		      &mut retval,
		      dh_msg1_str.as_ptr() as * const u8,
		      dh_msg1_str.len(),
		      dh_msg2_arr.as_mut_ptr() as *mut u8);
    	};

	

	match retval {
	    sgx_status_t::SGX_SUCCESS  => {
		
		let c = dh_msg2_arr[0].clone();
		let c = &[c];
		
		let nc_str = std::str::from_utf8(c).unwrap();
		
		let nc = nc_str.parse::<usize>().unwrap();
		
		let size_str = std::str::from_utf8(&dh_msg2_arr[1..(nc+1)]).unwrap();
		
		let size = size_str.parse::<usize>().unwrap();
		
		let msg_str = std::str::from_utf8(&dh_msg2_arr[(nc+1)..(size+nc+1)]).unwrap().to_string();
		
		let dh_msg2 : DHMsg2  = serde_json::from_str(&msg_str).unwrap();
		
		Ok(dh_msg2)
	    },
	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
	}
    }

    pub fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<EcLog> {
		let sealed_log = [0u8; 8192];
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let dh_msg3_str = serde_json::to_string(dh_msg3).unwrap();
		unsafe {
            proc_msg3(self.geteid(),
		      &mut retval,
		      dh_msg3_str.as_ptr() as * const u8,
		      dh_msg3_str.len(),
		      sealed_log.as_ptr() as * mut u8)
    	};
		match retval {
	    	sgx_status_t::SGX_SUCCESS  => {
				Ok(sealed_log)
			},
	    	_ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
		}
    }
    
    pub fn get_self_report(&self) -> Result<sgx_report_t> {
     	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut ret_report: sgx_report_t = sgx_report_t::default();
	
     	let result = unsafe {
            get_self_report(self.geteid(),
			    &mut retval,
			    &mut ret_report as *mut sgx_report_t)
    	};
	
    	match result {
            sgx_status_t::SGX_SUCCESS => Ok(ret_report),
       	    _ => Err(HubError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }
   
    pub fn destroy(&self) {
     	unsafe {
	    	sgx_destroy_enclave(self.geteid());
		}
    }

}

extern {

    fn test_create_session(eid: sgx_enclave_id_t, retval: *mut sgx_status_t)
			   -> sgx_status_t;

    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;

    fn get_self_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		       p_report: *mut sgx_report_t) -> sgx_status_t;

	fn set_ec_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
				sealed_log: * mut u8, sealed_log_size: u32);
  

    fn session_request(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
    		       src_enclave_id: sgx_enclave_id_t,
    		       dh_msg1: *mut u8);

    fn exchange_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		       src_enclave_id: sgx_enclave_id_t, dh_msg2: *const u8,
		       msg2_len: size_t,
		       dh_msg3: *mut u8,
		       sealed_log: *mut u8);

	fn get_session_enclave_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		sealed_log: *mut u8);

    fn proc_msg1(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		 dh_msg1: *const u8,
		 msg1_len: size_t,
		 dh_msg2: *mut u8);

    fn proc_msg3(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		 dh_msg3: *const u8,
		 msg3_len: size_t,
		 sealed_log: *mut u8);

	fn set_random_ec_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, sealed_log: *mut u8) 
		-> sgx_status_t;
    
//    public uint32_t end_session(sgx_enclave_id_t src_enclave_id, [user_check]size_t* session_ptr);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[serial]
    #[test]
    fn test_new() {
       let enc = Enclave::new().unwrap();
       enc.destroy();
    }

	#[serial]
    #[test]
	fn test_set_random_ec_key() {
		let mut enc = Enclave::new().unwrap();
		enc.set_random_ec_key().unwrap();
		enc.destroy();
	}

    #[serial]
    #[test]
    fn test_say_something() {
       let enc = Enclave::new().unwrap();
       let _ = enc.say_something("From test_say_something. ".to_string()).unwrap();
       enc.destroy();
    }

    #[serial]
    #[test]
    fn test_self_report() {
	let enc = Enclave::new().unwrap();
	let _report = enc.get_self_report().unwrap();
	enc.destroy();
    }
}



