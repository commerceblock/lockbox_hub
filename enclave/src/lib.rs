
// Licensed to the Apache Software Foundation secret key(ASF) under only
// more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "hub_enclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
extern crate sgx_tse;
extern crate sgx_tdh;
extern crate sgx_trts;
use sgx_tdh::{SgxDhMsg2, SgxDhMsg3, SgxDhInitiator, SgxDhResponder};
use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence, rsgx_raw_is_within_enclave};
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate libsecp256k1 as libsecp256k1;
extern crate secp256k1_sgx as secp256k1;
extern crate num_integer as integer;
extern crate num_traits;
extern crate uuid;
extern crate subtle;
extern crate ecies;
#[macro_use]
extern crate serde_big_array;
extern crate lazy_static;
extern crate hex;
use sgx_types::*;
use sgx_tcrypto::*;  
use std::string::String;
use sgx_types::marker::ContiguousMemory;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::convert::{TryFrom, TryInto};
use std::mem;
use sgx_rand::{Rng, StdRng};
use sgx_tseal::{SgxSealedData};
use std::ops::{Deref, DerefMut};
use std::default::Default;
use core::ptr;
extern crate attestation;
use attestation::types::*;
use attestation::err::*;
use std::boxed::Box;
use lazy_static::lazy_static;
use std::sync::SgxMutex as Mutex;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;

pub const EC_LOG_SIZE: usize = 8192;
pub type EcLog = [u8; EC_LOG_SIZE];

pub const EC_LOG_SIZE_LG: usize = 32400;
pub type EcLogLg = [u8; EC_LOG_SIZE_LG];

//Using lazy_static in order to be able to use a heap-allocated
//static variable requiring runtime executed code
lazy_static!{
    static ref INITIATOR: Mutex<SgxDhInitiator> = Mutex::new(SgxDhInitiator::init_session());
    static ref RESPONDER: Mutex<SgxDhResponder> = Mutex::new(SgxDhResponder::init_session());
    static ref SESSIONINFO: Mutex<DhSessionInfo> = Mutex::new(DhSessionInfo::default());
    static ref SESSIONKEY: Mutex<sgx_align_key_128bit_t> = Mutex::new(sgx_align_key_128bit_t::default());
    static ref ECKEY: Mutex<sgx_align_key_128bit_t> = Mutex::new(sgx_align_key_128bit_t::default());
}

big_array! {
    BigArray;
    +42,
}

fn test_vec() -> Vec<u8>{
    vec![123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 57, 50, 53, 48, 98, 52, 48, 98, 57, 55, 53, 49, 97, 57, 50, 50, 51, 57, 56, 50, 50, 56, 50, 52, 98, 49, 52, 56, 97, 55, 54, 54, 52, 48, 102, 100, 100, 56, 98, 49, 50, 53, 51, 97, 97, 102, 100, 50, 99, 100, 50, 101, 56, 49, 53, 50, 53, 49, 98, 99, 98, 51, 102, 49, 34, 125]
}

#[derive(Clone, Debug, Default)]
pub struct SgxSealable {
    inner: Vec<u8>
}

impl SgxSealable {
    fn to_sealed(&self) -> SgxResult<SgxSealedData<[u8]>> {
	    let aad: [u8; 0] = [0_u8; 0];
	    SgxSealedData::<[u8]>::seal_data(&aad, self.deref().as_slice())
    }

    fn try_from_sealed(sd: &SgxSealedData<[u8]>) -> SgxResult<Self> {
	    sd.unseal_data().map(|x|Self{inner: x.get_decrypt_txt().to_vec()})
    }

    #[inline]
    pub const fn size() -> usize {
	EC_LOG_SIZE
    }
}

impl Deref for SgxSealable {
     type Target = Vec<u8>;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for SgxSealable {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

#[derive(Clone, Debug)]
pub struct SgxSealedLog {
    inner: [u8; Self::size()]
}

impl SgxSealedLog{
    #[inline]
    pub const fn size() -> usize {
	EC_LOG_SIZE
    }
}

impl Default for SgxSealedLog {
    fn default() -> Self {
	Self{inner: [0;Self::size()]}
    }
}

impl Deref for SgxSealedLog {
    type Target = [u8; Self::size()];
     fn deref(&self) -> &Self::Target {
        &self.inner
     }
}

impl DerefMut for SgxSealedLog {
     fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
     }
}


impl TryFrom<SgxSealable> for SgxSealedLog {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {
	let sealed_data = match item.to_sealed(){
	    Ok(v) => v,
	    Err(e) => return Err(e)
	};
	let mut sealed_log  = Self::default();

	let opt = to_sealed_log_for_slice(&sealed_data, (*sealed_log).as_mut_ptr(), Self::size() as u32);
	if opt.is_none() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}
	Ok(sealed_log)
    }
}

impl TryFrom<RandDataSerializable> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: RandDataSerializable) -> Result<Self, Self::Error> {
	let encoded_vec = match serde_cbor::to_vec(&item){
	    Ok(v) => v,
	    Err(e) => {
		println!("error: {:?}",e);
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

	    }
	};
	let res = Self{inner: encoded_vec};
	Ok(res)
    }
}

impl TryFrom<SgxSealable> for RandDataSerializable {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

	match serde_cbor::from_slice(&item){
	    Ok(v) => Ok(v),
	    Err(_e) => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
	}
    }
}

//#[derive(Serialize, Deserialize, Clone, Default, Debug)]
//struct SessionKey {
//    inner: sgx_key_128bit_t
//}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SgxKey128BitSealed {
    inner: sgx_key_128bit_t
}

impl TryFrom<(* mut u8, u32)> for SgxKey128BitSealed {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}


impl TryFrom<SgxKey128BitSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: SgxKey128BitSealed) -> Result<Self, Self::Error> {
	let encoded_vec = match serde_cbor::to_vec(&item){
	    Ok(v) => v,
	    Err(e) => {
		println!("error: {:?}",e);
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

	    }
	};
	let res = Self{inner: encoded_vec};
	Ok(res)
    }
}

impl TryFrom<SgxSealable> for SgxKey128BitSealed {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

	match serde_cbor::from_slice(&item){
	    Ok(v) => Ok(v),
	    Err(_e) => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
	}
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
struct Bytes32{
    inner: [u8; 32]
}

impl TryFrom<Bytes32> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: Bytes32) -> Result<Self, Self::Error> {
	let encoded_vec = match serde_cbor::to_vec(&item){
	    Ok(v) => v,
	    Err(e) => {
		println!("error: {:?}",e);
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

	    }
	};
	let res = Self{ inner: encoded_vec };
	Ok(res)
    }
}

impl TryFrom<SgxSealable> for Bytes32 {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {
	match serde_cbor::from_slice(&item){
	    Ok(v) => Ok(v),
	    Err(_e) => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
	}
    }
}

impl TryFrom<(* mut u8, u32)> for Bytes32 {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl From<* const u8> for Bytes32 {
    fn from(item: * const u8) -> Self {
	let inner_slice = unsafe { slice::from_raw_parts(item, 32) };
	let inner: [u8;32] = inner_slice.try_into().unwrap();
	Self{inner}
    }
}


impl Deref for Bytes32 {
     type Target = [u8; 32];
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for Bytes32 {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl Bytes32 {
    fn new_random() -> SgxResult<Bytes32> {
	let mut rand = match StdRng::new() {
            Ok(rng) => rng,
            Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};
	let mut key = [0u8; 32];
	rand.fill_bytes(&mut key);
	Ok(Self{inner: key})
    }
}

fn proc_msg1_safe(dh_msg1_str: *const u8 , msg1_len: usize,
		  dh_msg2: &mut [u8;1700]
) -> ATTESTATION_STATUS {
    
    let str_slice = unsafe { slice::from_raw_parts(dh_msg1_str, msg1_len) };
    
    
    let dh_msg1 = match std::str::from_utf8(&str_slice) {
        Ok(v) =>{
            match serde_json::from_str::<DHMsg1>(v){
                Ok(v) => v.inner,
                Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
            }
        },
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    
    let mut dh_msg2_inner: SgxDhMsg2 = SgxDhMsg2::default(); //Diffie-Hellman Message 2
    
    
    let status = match INITIATOR.lock() {
	    Ok(mut r) => r.proc_msg1(&dh_msg1, &mut dh_msg2_inner),
	    Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    if status.is_err() {
    
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    
    match serde_json::to_string(& DHMsg2 { inner: dh_msg2_inner } ) {
	Ok(v) => {
	    let len = v.len();
    
	    let mut v_sized=format!("{}", len);
	    v_sized=format!("{}{}", v_sized.len(), v_sized);
	    v_sized.push_str(&v);
    
	    let mut v_bytes=v_sized.into_bytes();
    
	    v_bytes.resize(1700,0);
    
	    *dh_msg2 = v_bytes.as_slice().try_into().unwrap();
	},
	Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    
    ATTESTATION_STATUS::SUCCESS
}


//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn proc_msg1(dh_msg1_str: *const u8 , msg1_len: usize,
                           dh_msg2: &mut [u8;1700])
				  -> ATTESTATION_STATUS {

    proc_msg1_safe(dh_msg1_str, msg1_len, dh_msg2)
}

#[no_mangle]
pub extern "C" fn set_random_ec_key() -> sgx_status_t {
    match internal_set_random_ec_key() {
        Ok(_) =>  sgx_status_t::SGX_SUCCESS,
        Err(e) => e
    }
}

fn internal_set_random_ec_key() -> SgxResult<()> {
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
    };

    let mut sgx_key = sgx_align_key_128bit_t::default();
    rand.fill_bytes(&mut sgx_key.key);
    Ok(())
}

fn internal_set_ec_key(val: sgx_align_key_128bit_t) -> SgxResult<()> {
    match ECKEY.lock() {
        Ok(mut key) => {
            let default = sgx_align_key_128bit_t::default();
            if key.key != default.key {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            *key = val;
            Ok(())
        },
        Err(_) => Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
    }
}

fn internal_set_session_key(val: sgx_align_key_128bit_t) -> SgxResult<()> {
    match SESSIONKEY.lock() {
        Ok(mut key) => {
            let default = sgx_align_key_128bit_t::default();
            if key.key != default.key {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            *key = val;
            Ok(())
        },
        Err(_) => Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
    }
}

fn proc_msg3_safe(dh_msg3_str: *const u8 , msg3_len: usize, sealed_log:  * mut u8) -> ATTESTATION_STATUS {

    let str_slice = unsafe { slice::from_raw_parts(dh_msg3_str, msg3_len) };
    println!("str_slice: {:?}", &str_slice);
    let mut dh_msg3_raw = match std::str::from_utf8(&str_slice) {
        Ok(v) =>{
            match serde_json::from_str::<DHMsg3>(v){
                Ok(v) => v.inner,
                Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
            }
        },
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };
    println!("dhmsg3_raw");
    let mut dh_aek: sgx_align_key_128bit_t = sgx_align_key_128bit_t::default(); // Session Key
    println!("dh_aek");    
    let mut responder_identity: sgx_dh_session_enclave_identity_t = sgx_dh_session_enclave_identity_t::default();
    println!("responder_identity");    

    let dh_msg3_raw_len = mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe{ SgxDhMsg3::from_raw_dh_msg3_t(&mut dh_msg3_raw, dh_msg3_raw_len ) };
    println!("dh_msg3");    
    if dh_msg3.is_none() {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let dh_msg3 = dh_msg3.unwrap();
    
    println!("r.proc_msg3");    
    let status = match INITIATOR.lock() {
	    Ok(mut r) => r.proc_msg3(&dh_msg3, &mut dh_aek.key, &mut responder_identity),
	    Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR,
    };
    println!("status: {:?}", &status);    
    
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    /*
    let cb = get_callback();
    if cb.is_some() {
        let ret = (cb.unwrap().verify)(&responder_identity);
        if ret != ATTESTATION_STATUS::SUCCESS as u32{
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    }
     */
    

    let key_sealed  = SgxKey128BitSealed {
	    inner: dh_aek.key
    };

    println!("key_sealed: {:?}", &key_sealed);    
    
    let sealable = match SgxSealable::try_from(key_sealed){
	    Ok(x) => x,
        Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    println!("sealable: {:?}", &sealable);    

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };
    println!("sealed_data");    
    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, EC_LOG_SIZE as u32);
    println!("opt: {:?}", &opt);    
    if opt.is_none() {
	    return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    println!("internal_set_session_key: ");    
    match internal_set_session_key(dh_aek){
        Ok(_) => {
            println!("internal_set_session_key success.");    
            ATTESTATION_STATUS::SUCCESS
        },
        Err(_) => ATTESTATION_STATUS::INVALID_SESSION
    }    
}


//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn proc_msg3(dh_msg3_str: *const u8 , msg3_len: usize, sealed_log:  * mut u8)
				  -> ATTESTATION_STATUS {
    let result = proc_msg3_safe(dh_msg3_str, msg3_len, sealed_log);
    println!("finished proc_msg3_safe");
    result
}

#[allow(unused_variables)]
fn exchange_report_safe(src_enclave_id: sgx_enclave_id_t,
			dh_msg2_str: *const u8 , msg2_len: usize,
			dh_msg3_arr: &mut [u8;1600],
			sealed_log: *mut u8
//			session_info: &mut DhSessionInfo
) -> ATTESTATION_STATUS {
    
    let str_slice = unsafe { slice::from_raw_parts(dh_msg2_str, msg2_len) };
    
    let dh_msg2 = match std::str::from_utf8(&str_slice) {
	Ok(v) =>{
	    match serde_json::from_str::<DHMsg2>(v){
		Ok(v) => v.inner,
		Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
	    }
	},
	Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };
    
    let mut dh_aek = sgx_align_key_128bit_t::default() ;   // Session key
    
    let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();

    
    let dh_msg3_r  = match SESSIONINFO.lock() {
	    Ok(session_info) => {
    
	        let mut responder = match session_info.session.session_status {
		        DhSessionStatus::InProgress(res) => {res},
		        _ => {
		            return ATTESTATION_STATUS::INVALID_SESSION;
		        }
	        };

	        let mut result = SgxDhMsg3::default();
        
	        let status = responder.proc_msg2(&dh_msg2, &mut result, &mut dh_aek.key, &mut initiator_identity);
	        if status.is_err() {
        	    return ATTESTATION_STATUS::ATTESTATION_ERROR;
	        }
	        result
	    },
	    Err(e) => {
            return ATTESTATION_STATUS::INVALID_SESSION
        }
    };

    let raw_len = dh_msg3_r.calc_raw_sealed_data_size();
    let mut dh_msg3_inner = sgx_dh_msg3_t::default();
    let _ = unsafe{ dh_msg3_r.to_raw_dh_msg3_t(&mut dh_msg3_inner, raw_len ) };

    match serde_json::to_string(& DHMsg3 { inner: dh_msg3_inner } ) {
	Ok(v) => {
	    let len = v.len();
	    let mut v_sized=format!("{}", len);
	    v_sized=format!("{}{}", v_sized.len(), v_sized);
	    v_sized.push_str(&v);
	    let mut v_bytes=v_sized.into_bytes();
	    v_bytes.resize(1600,0);
	    *dh_msg3_arr = v_bytes.as_slice().try_into().unwrap();
	},
	Err(e) => {
            return ATTESTATION_STATUS::INVALID_SESSION
        }
    };


    let key_sealed  = SgxKey128BitSealed {
	    inner: dh_aek.key
    };
    
    let sealable = match SgxSealable::try_from(key_sealed){
	Ok(x) => x,
        Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };
    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, EC_LOG_SIZE as u32);
    if opt.is_none() {
	return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    match internal_set_session_key(dh_aek){
        Ok(_) => (),
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION,
    };
    
    match SESSIONINFO.lock() {
	Ok(mut session_info) => {
                session_info
				 .session.session_status = DhSessionStatus::Active(dh_aek);
				 ATTESTATION_STATUS::SUCCESS},
	Err(e) => {
            ATTESTATION_STATUS::INVALID_SESSION
        },
    }
    
}
//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
#[no_mangle]
pub extern "C" fn exchange_report(src_enclave_id: sgx_enclave_id_t,
				  dh_msg2_str: *const u8, msg2_len: usize,
				  dh_msg3_arr: &mut [u8;1600],
				  sealed_log: *mut u8,
	//,
	//			  session_ptr: *mut usize
) -> ATTESTATION_STATUS {
    

//    if rsgx_raw_is_outside_enclave(session_ptr as * const u8, mem::size_of::<DhSessionInfo>()) {
//        return ATTESTATION_STATUS::INVALID_PARAMETER;
//    }
    rsgx_lfence();

    exchange_report_safe(src_enclave_id, dh_msg2_str, msg2_len, dh_msg3_arr, sealed_log)
}

//Respond to the request from the Source Enclave to close the session
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn end_session(src_enclave_id: sgx_enclave_id_t)
   // , session_ptr: *mut usize)
        -> ATTESTATION_STATUS {

    /*
    if rsgx_raw_is_outside_enclave(session_ptr as * const u8, mem::size_of::<DhSessionInfo>()) {
        return ATTESTATION_STATUS::INVALID_PARAMETER;
    }
     */
    rsgx_lfence();
    
    
    //    let _ = unsafe { Box::from_raw(session_ptr as *mut DhSessionInfo) };

    match SESSIONINFO.lock() {
	Ok(mut session_info) => {
	    *session_info = DhSessionInfo::default();
	    ATTESTATION_STATUS::SUCCESS
	},
	Err(_) => ATTESTATION_STATUS::INVALID_SESSION
    }
}


// A sample struct to show the usage of serde + seal
// This struct could not be used in sgx_seal directly because it is
// **not** continuous in memory. The `vec` is the bad member.
// However, it is serializable. So we can serialize it first and
// put convert the Vec<u8> to [u8] then put [u8] to sgx_seal API!
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct RandDataSerializable {
    key: u32,
    rand: [u8; 16],
    vec: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct SgxPayload {
    payload_size: u32,
    reserved: [u8; 12],
    payload_tag: [u8; SGX_SEAL_TAG_SIZE],
    encrypt: Box<[u8]>,
    additional: Box<[u8]>,
}

/*
impl_struct! {
    pub struct encrypted_data_t {
        pub plain_text_offset: uint32_t,
        pub reserved: [uint8_t; 12],
        pub aes_data: sgx_aes_gcm_data_t,
    }
}
 */

/*
impl_struct! {
    pub struct sgx_aes_gcm_data_t {
        pub payload_size: uint32_t,
        pub reserved: [uint8_t; 12],
        pub payload_tag: [uint8_t; SGX_SEAL_TAG_SIZE],
        pub payload: [uint8_t; 0],
    }

    pub struct sgx_sealed_data_t {
        pub key_request: sgx_key_request_t,
        pub plain_text_offset: uint32_t,
        pub reserved: [uint8_t; 12],
	pub aes_data: sgx_aes_gcm_data_t,
    }
}
*/


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EncryptedData {
    payload_data: SgxPayload,
}

impl EncryptedData {
    pub fn new() -> Self {
        EncryptedData::default()
    }
    pub fn get_payload_size(&self) -> u32 {
        self.payload_data.payload_size
    }
    pub fn get_payload_tag(&self) -> &[u8; SGX_SEAL_TAG_SIZE] {
        &self.payload_data.payload_tag
    }

    pub fn get_encrypt_txt(&self) -> &[u8] {
        &*self.payload_data.encrypt
    }
    pub fn get_additional_txt(&self) -> &[u8] {
        &*self.payload_data.additional
    }

    pub fn calc_raw_sealed_data_size(add_mac_txt_size: u32, encrypt_txt_size: u32) -> u32 {
        let max = u32::MAX;
        let sealed_data_size = mem::size_of::<sgx_sealed_data_t>() as u32;

        if add_mac_txt_size > max - encrypt_txt_size {
            return max;
        }
        let payload_size: u32 = add_mac_txt_size + encrypt_txt_size;
        if payload_size > max - sealed_data_size {
            return max;
        }
        sealed_data_size + payload_size
    }

    pub fn get_add_mac_txt_len(&self) -> u32 {
        let data_size = self.payload_data.additional.len();
        if data_size > self.payload_data.payload_size as usize
            || data_size >= u32::MAX as usize
        {
            u32::MAX
        } else {
            data_size as u32
        }
    }

    pub fn get_encrypt_txt_len(&self) -> u32 {
        let data_size = self.payload_data.encrypt.len();
        if data_size > self.payload_data.payload_size as usize
            || data_size >= u32::MAX as usize
        {
            u32::MAX
        } else {
            data_size as u32
	}
    }


    pub fn try_from(additional_text: &[u8], encrypt_text: &[u8],
    payload_iv: &[u8], encrypt_key: &mut sgx_align_key_128bit_t) -> SgxResult<Self> {
	
    
	let mut enc_data = Self::new();
	enc_data.payload_data.encrypt = vec![0_u8; encrypt_text.len()].into_boxed_slice();
    println!("encrypt...");
	let error = rsgx_rijndael128GCM_encrypt(
            &encrypt_key.key,
            encrypt_text,
            payload_iv,
            &additional_text,
            &mut enc_data.payload_data.encrypt,
            &mut enc_data.payload_data.payload_tag,
	);
	if error.is_err() {
            println!("encrypt error...");
            return Err(error.unwrap_err());
	}
	println!("get payload size...");
	enc_data.payload_data.payload_size = (encrypt_text.len() + additional_text.len()) as u32;
	if !additional_text.is_empty() {
            println!("get payload size...");
            enc_data.payload_data.additional = additional_text.to_vec().into_boxed_slice();
	}
	println!("finished encrypted data from");
	Ok(enc_data)
    }
    
    pub fn unencrypt(&self, encrypt_key: &mut sgx_align_key_128bit_t) -> SgxResult<UnencryptedData> {
	//
        // code that calls sgx_unseal_data commonly does some sanity checks
        // related to plain_text_offset.  We add fence here since we don't
        // know what crypto code does and if plain_text_offset-related
        // checks mispredict the crypto code could operate on unintended data
        //
        rsgx_lfence();

        let payload_iv = [0_u8; SGX_SEAL_IV_SIZE];
        let mut unsealed_data: UnencryptedData = UnencryptedData::default();
        unsealed_data.decrypt = vec![0_u8; self.payload_data.encrypt.len()].into_boxed_slice();

        let error = rsgx_rijndael128GCM_decrypt(
            &encrypt_key.key,
            self.get_encrypt_txt(),
            &payload_iv,
            self.get_additional_txt(),
            self.get_payload_tag(),
            &mut unsealed_data.decrypt,
        );
        if error.is_err() {
	        println!("unencrypt error: {}", error.unwrap_err());
            return Err(error.unwrap_err());
        }

        if self.payload_data.additional.len() > 0 {
            unsealed_data.additional = self.get_additional_txt().to_vec().into_boxed_slice();
        }
        unsealed_data.payload_size = self.get_payload_size();


        Ok(unsealed_data)
    }


    pub unsafe fn to_raw_sealed_data_t(
        &self,
        p: *mut sgx_sealed_data_t,
        len: u32,
    ) -> Option<*mut sgx_sealed_data_t> {
        if p.is_null() {
            return None;
        }
        if !rsgx_raw_is_within_enclave(p as *mut u8, len as usize)
            && !rsgx_raw_is_outside_enclave(p as *mut u8, len as usize)
        {
            return None;
        }

        let additional_len = self.get_add_mac_txt_len();
        let encrypt_len = self.get_encrypt_txt_len();
        if (additional_len == u32::MAX) || (encrypt_len == u32::MAX) {
            return None;
        }
        if (additional_len + encrypt_len) != self.get_payload_size() {
            return None;
        }

        let sealed_data_size = sgx_calc_sealed_data_size(additional_len, encrypt_len);
        if sealed_data_size == u32::MAX {
            return None;
        }
        if len < sealed_data_size {
            return None;
        }

        let ptr_sealed_data = p as *mut u8;
        let ptr_encrypt = ptr_sealed_data.add(mem::size_of::<sgx_sealed_data_t>());
        if encrypt_len > 0 {
            ptr::copy_nonoverlapping(
                self.payload_data.encrypt.as_ptr(),
                ptr_encrypt,
                encrypt_len as usize,
            );
        }
        if additional_len > 0 {
            let ptr_additional = ptr_encrypt.offset(encrypt_len as isize);
            ptr::copy_nonoverlapping(
                self.payload_data.additional.as_ptr(),
                ptr_additional,
                additional_len as usize,
            );
        }

        let raw_sealed_data = &mut *p;
	    raw_sealed_data.key_request = sgx_key_request_t::default();
        raw_sealed_data.plain_text_offset = encrypt_len;
        raw_sealed_data.aes_data.payload_size = self.payload_data.payload_size;
        raw_sealed_data.aes_data.payload_tag = self.payload_data.payload_tag;

        Some(p)
    }


    #[allow(clippy::cast_ptr_alignment)]
    pub unsafe fn from_raw_sealed_data_t(p: *const sgx_sealed_data_t, len: u32) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        if !rsgx_raw_is_within_enclave(p as *mut u8, len as usize)
            && !rsgx_raw_is_outside_enclave(p as *mut u8, len as usize)
        {
            return None;
        }

        if (len as usize) < mem::size_of::<sgx_sealed_data_t>() {
            return None;
        }

        let raw_encrypted_data = &*p;
        if raw_encrypted_data.plain_text_offset > raw_encrypted_data.aes_data.payload_size {
            return None;
        }

        let ptr_encrypted_data = p as *mut u8;
        let additional_len = sgx_get_add_mac_txt_len(ptr_encrypted_data as *const sgx_sealed_data_t);
        let encrypt_len = sgx_get_encrypt_txt_len(ptr_encrypted_data as *const sgx_sealed_data_t);
        if (additional_len == u32::MAX) || (encrypt_len == u32::MAX) {
            return None;
        }
        if (additional_len + encrypt_len) != raw_encrypted_data.aes_data.payload_size {
            return None;
        }

        let encrypted_data_size = sgx_calc_sealed_data_size(additional_len, encrypt_len);
        if encrypted_data_size == u32::MAX {
            return None;
        }
        if len < encrypted_data_size {
            return None;
        }

        let ptr_encrypt = ptr_encrypted_data.add(mem::size_of::<sgx_sealed_data_t>());

        let encrypt: Vec<u8> = if encrypt_len > 0 {
            let mut temp: Vec<u8> = Vec::with_capacity(encrypt_len as usize);
            temp.set_len(encrypt_len as usize);
            ptr::copy_nonoverlapping(
                ptr_encrypt as *const u8,
                temp.as_mut_ptr(),
                encrypt_len as usize,
            );
            temp
        } else {
            Vec::new()
        };

        let additional: Vec<u8> = if additional_len > 0 {
            let ptr_additional = ptr_encrypt.offset(encrypt_len as isize);
            let mut temp: Vec<u8> = Vec::with_capacity(additional_len as usize);
            temp.set_len(additional_len as usize);
            ptr::copy_nonoverlapping(
                ptr_additional as *const u8,
                temp.as_mut_ptr(),
                additional_len as usize,
            );
            temp
        } else {
            Vec::new()
        };

        let mut encrypted_data = Self::default();
        encrypted_data.payload_data.payload_size = raw_encrypted_data.aes_data.payload_size;
        encrypted_data.payload_data.payload_tag = raw_encrypted_data.aes_data.payload_tag;
        encrypted_data.payload_data.additional = additional.into_boxed_slice();
        encrypted_data.payload_data.encrypt = encrypt.into_boxed_slice();

        Some(encrypted_data)
    }

}

#[derive(Clone, Default)]
pub struct UnencryptedData {
    pub payload_size: u32,
    pub decrypt: Box<[u8]>,
    pub additional: Box<[u8]>,
}

impl UnencryptedData {
    ///
    /// Get the payload size of the UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_payload_size(&self) -> u32 {
        self.payload_size
    }
    ///
    /// Get the pointer of decrypt buffer in UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_decrypt_txt(&self) -> &[u8] {
        &*self.decrypt
    }
    ///
    /// Get the pointer of additional buffer in UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_additional_txt(&self) -> &[u8] {
        &*self.additional
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg2_t")]
struct DHMsg2Def {
    #[serde(with = "EC256PublicDef")]
    pub g_b: sgx_ec256_public_t,
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_t")]
pub struct ReportDef {
    #[serde(with = "ReportBodyDef")]
    pub body: sgx_report_body_t,
    #[serde(with = "KeyIDDef")]
    pub key_id: sgx_key_id_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub mac: sgx_mac_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_key_id_t")]
pub struct KeyIDDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub id: [uint8_t; SGX_KEYID_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_body_t")]
pub struct ReportBodyDef {
    #[serde(with = "CpuSvnDef")]
    pub cpu_svn: sgx_cpu_svn_t,
    pub misc_select: sgx_misc_select_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved1: [uint8_t; SGX_REPORT_BODY_RESERVED1_BYTES],
    pub isv_ext_prod_id: sgx_isvext_prod_id_t,
    #[serde(with = "AttributesDef")]
    pub attributes: sgx_attributes_t,
    #[serde(with = "MeasurementDef")]
    pub mr_enclave: sgx_measurement_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved2: [uint8_t; SGX_REPORT_BODY_RESERVED2_BYTES],
    #[serde(with = "MeasurementDef")]
    pub mr_signer: sgx_measurement_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved3: [uint8_t; SGX_REPORT_BODY_RESERVED3_BYTES],
    #[serde(with = "BigArray")]
    pub config_id: sgx_config_id_t,
    pub isv_prod_id: sgx_prod_id_t,
    pub isv_svn: sgx_isv_svn_t,
    pub config_svn: sgx_config_svn_t,
    #[serde(with = "BigArray")]
    pub reserved4: [uint8_t; SGX_REPORT_BODY_RESERVED4_BYTES],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub isv_family_id: sgx_isvfamily_id_t,
    #[serde(with = "ReportDataDef")]
    pub report_data: sgx_report_data_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_data_t")]
pub struct ReportDataDef {
    #[serde(with = "BigArray")]
    pub d: [uint8_t; SGX_REPORT_DATA_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_cpu_svn_t")]
pub struct CpuSvnDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub svn: [uint8_t; SGX_CPUSVN_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_target_info_t")]
struct TargetInfoDef {
    #[serde(with = "MeasurementDef")]
    pub mr_enclave: sgx_measurement_t,
    #[serde(with = "AttributesDef")]
    pub attributes: sgx_attributes_t,
    pub reserved1: [uint8_t; SGX_TARGET_INFO_RESERVED1_BYTES],
    pub config_svn: sgx_config_svn_t,
    pub misc_select: sgx_misc_select_t,
    pub reserved2: [uint8_t; SGX_TARGET_INFO_RESERVED2_BYTES],
    #[serde(with = "BigArray")]
    pub config_id: sgx_config_id_t,
    #[serde(with = "BigArray")]
    pub reserved3: [uint8_t; SGX_TARGET_INFO_RESERVED3_BYTES],
}

//impl_struct! {
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "sgx_measurement_t")]
    pub struct MeasurementDef {
	#[serde(serialize_with = "<[_]>::serialize")]
        pub m: [uint8_t; SGX_HASH_SIZE],
    }
//}



impl_struct! {
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "sgx_attributes_t")]
    pub struct AttributesDef {
        pub flags: uint64_t,
        pub xfrm: uint64_t,
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg1 {
    #[serde(with = "DHMsg1Def")]
    pub inner: sgx_dh_msg1_t,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg2 {
    #[serde(with = "DHMsg2Def")]
    pub inner: sgx_dh_msg2_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_body_t")]
struct DHMsg3BodyDef {
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    pub additional_prop_length: uint32_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub additional_prop: [uint8_t; 0],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_t")]
pub struct DHMsg3Def {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
    #[serde(with = "DHMsg3BodyDef")]
    pub msg3_body: sgx_dh_msg3_body_t,
}


#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg3 {
    #[serde(with = "DHMsg3Def")]
    pub inner: sgx_dh_msg3_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg1_t")]
struct DHMsg1Def {
    #[serde(with = "EC256PublicDef")]
    pub g_a: sgx_ec256_public_t,
    #[serde(with = "TargetInfoDef")]
    pub target: sgx_target_info_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_ec256_public_t")]
struct EC256PublicDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gx: [uint8_t; SGX_ECP256_KEY_SIZE],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gy: [uint8_t; SGX_ECP256_KEY_SIZE],
}



#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "<-This is a in-Enclave ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_self_report(p_report: &mut sgx_report_t) -> sgx_status_t {

    let self_report = sgx_tse::rsgx_self_report();

    *p_report = self_report;
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn create_sealed_random_bytes32(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    
    let data = match Bytes32::new_random(){
          Ok(v) => v,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let sealable = match SgxSealable::try_from(data){
	Ok(x) => x,
	Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
	Ok(x) => x,
        Err(ret) => return ret
    };
    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealed_bytes32(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let _data = match Bytes32::try_from((sealed_log, sealed_log_size)) {
	Ok(v) => v,
	Err(e) => return e
    };
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn set_ec_key(sealed_log: * mut u8) -> sgx_status_t {

    let data = match SgxKey128BitSealed::try_from((sealed_log, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
	Err(e) => return e
    };

    let mut key_align = sgx_align_key_128bit_t::default();
    key_align.key = data.inner;
    match internal_set_ec_key(key_align){
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(_) => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
}

#[no_mangle]
pub extern "C" fn generate_keypair(_input_str: *const u8) -> sgx_status_t {

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };
    let mut rands = [0u8;32];
    rand.fill_bytes(&mut rands);

    let privkey = match libsecp256k1::SecretKey::parse(&rands){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let _pubkey = libsecp256k1::PublicKey::from_secret_key(&privkey);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sk_tweak_add_assign(sealed_log1: * mut u8, sealed_log1_size: u32, sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t {

    let data1 = match Bytes32::try_from((sealed_log1, sealed_log1_size)) {
	Ok(v) => v,
	Err(e) => return e
    };
    
    let mut sk1 = match libsecp256k1::SecretKey::parse(&data1){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let data1_test = Bytes32{inner: sk1.serialize()};

    assert_eq!(data1, data1_test);

    let data2 = match Bytes32::try_from((sealed_log2, sealed_log2_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk2 = match libsecp256k1::SecretKey::parse(&data2){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    match sk1.tweak_add_assign(&sk2){
	Ok(_) => (),
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };


    let sealable = match SgxSealable::try_from(Bytes32{inner: sk1.serialize()}){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log1, sealed_log1_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn sk_tweak_mul_assign(sealed_log1: * mut u8, sealed_log1_size: u32, sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t {

    let data1 = match Bytes32::try_from((sealed_log1, sealed_log1_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let mut sk1 = match libsecp256k1::SecretKey::parse(&data1){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let data1_test = Bytes32{inner: sk1.serialize()};

    assert_eq!(data1, data1_test);

    let data2 = match Bytes32::try_from((sealed_log2, sealed_log2_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk2 = match libsecp256k1::SecretKey::parse(&data2){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    match sk1.tweak_mul_assign(&sk2){
	Ok(_) => (),
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let sealable = match SgxSealable::try_from(Bytes32{inner: sk1.serialize()}){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log1, sealed_log1_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sign(some_message: &[u8;32], sk_sealed_log: * mut u8, sig: &mut[u8; 64]) -> sgx_status_t {

    let message = libsecp256k1::Message::parse(some_message);

    let sk_bytes = match Bytes32::try_from((sk_sealed_log, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
        Err(e) => return e
    };

    let sk = match libsecp256k1::SecretKey::parse(&sk_bytes){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let (signature, _recovery_id) = libsecp256k1::sign(&message, &sk);

    *sig = signature.serialize();

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn get_public_key(sealed_log: * mut u8, public_key: &mut[u8;33]) -> sgx_status_t {

    let data = match Bytes32::try_from((sealed_log, SgxSealedLog::size() as u32)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk = match libsecp256k1::SecretKey::parse(&data){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    *public_key = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_sc_encrypt_unencrypt() -> sgx_status_t {

    let test_vec = test_vec();
    match encrypt(&test_vec) {
	Ok(ed) => {	    
	    match *test_vec.as_slice() == *(ed.payload_data.encrypt) {
		false => (),
		true => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    };
	    let ud = match unencrypt(&ed) {
		Ok(ud) => ud,
		Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    };
	    match *test_vec.as_slice() == *(ud.decrypt) {
		true => sgx_status_t::SGX_SUCCESS,
		false => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    }
	}
	,
	Err(ret) => return ret
    }
}

#[no_mangle]
pub extern "C" fn get_session_enclave_key(sealed_log_out: *mut u8) -> sgx_status_t {
    println!("ECKEY...");
    match ECKEY.lock() {
        Ok(k) => {
            
            println!("session encrypt - key to key_vec - k.key: {:?}", &k.key);
/*
            let key_vec = match serde_cbor::to_vec(&k.key){
                Ok(r) => r,
                Err(e) => {
                    println!("{}", e);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                },
            };

            println!("session encrypt - key_vec: {:?}", &key_vec);
            
            match session_encrypt(&key_vec){
                Ok(ed) => {
                    println!("to encrypted log for slice - encrypted data: {:?}", &ed);
                    let mut test_output : EcLog = [0u8;EC_LOG_SIZE];
                    let opt = to_encrypted_log_for_slice(&ed, test_output.as_ptr() as * mut u8, EC_LOG_SIZE as u32);
                    println!("sealed log: {:?}", test_output);
                    if opt.is_none() {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                    }
                    println!("finished get_session_enclave_key");
                    sgx_status_t::SGX_SUCCESS
                },
                Err(e) => {
                    println!("error encrypting - {}", e);
                    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                },
            }
            */  

            println!("session encrypt - finished");
            sgx_status_t::SGX_SUCCESS
        },
        Err(e) => {
            println!("ECKEY error: {}", e);
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER
        }
        
    }

}

fn encrypt(encrypt: &[u8]) -> SgxResult<EncryptedData> {
    match ECKEY.lock() {
	Ok(mut k) => {
	    EncryptedData::try_from(&[], encrypt, &[0;12], &mut k)
	},
	Err(e) => {
	    println!("ECKEY error: {}", e);
	    Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	}
    }
}

fn unencrypt(encrypt: &EncryptedData) -> SgxResult<UnencryptedData> {
    match ECKEY.lock() {
	Ok(mut k) => {
	    encrypt.unencrypt(&mut k) 
	},
	Err(_) => {
        Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

fn session_encrypt(encrypt: &[u8]) -> SgxResult<EncryptedData> {
    println!("get session key...");
    match SESSIONKEY.lock() {
	    Ok(mut k) => {
            println!("get encrypted data from session key...");
	        EncryptedData::try_from(&[], encrypt, &[0;12], &mut k)
	    },
	    Err(e) => {
	        println!("ECKEY error: {}", e);
	        Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
    }
}

#[no_mangle]
pub extern "C" fn test_encrypt_to_out(sealed_log_out: *mut u8 ) -> sgx_status_t {

    let test_vec = test_vec();

    match encrypt(&test_vec) {
	Ok(ed) => {
	    let opt = to_encrypted_log_for_slice(&ed, sealed_log_out, EC_LOG_SIZE as u32);
	    if opt.is_none() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
	    }
	},
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_in_to_decrypt(data_in: *const u8, data_len: usize) -> sgx_status_t 
{
    let str_slice = unsafe { slice::from_raw_parts(data_in, data_len)};

    let encrypted_data_str = match std::str::from_utf8(&str_slice) {
	Ok(r) => r,
	Err(e) => {
	    let _ = io::stdout().write(format!("encrypted data str error: {:?}", e).as_str().as_bytes());
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

    let encrypted_data: EncryptedData = match serde_json::from_str(&encrypted_data_str){
        Ok(r) => r,
        Err(e) => {
	    let _ = io::stdout().write(format!("encrypted data error: {:?}", e).as_str().as_bytes());
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

    match unencrypt(&encrypted_data) {
	Ok(ud) => {
	    match  *test_vec().as_slice() == *(ud.decrypt) {
		true => sgx_status_t::SGX_SUCCESS,
		false => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
		
	    }
	},
	Err(e) => {
	    println!("unencrypt error: {:?}", e);
	    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    }
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}


fn to_encrypted_log_for_slice(encrypted_data: &EncryptedData, encrypted_log: * mut u8, encrypted_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        encrypted_data.to_raw_sealed_data_t(encrypted_log as * mut sgx_sealed_data_t, encrypted_log_size)
    }
}