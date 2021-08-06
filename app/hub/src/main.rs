extern crate hub_lib;
extern crate url;
extern crate shared_lib;
extern crate log;
use hub_lib::{Client, post};
use log::{info, warn};
use std::{thread, time};



use shared_lib::structs::{EnclaveIDMsg, DHMsg1, DHMsg2, DHMsg3, 
    ExchangeReportMsg, SetSessionEnclaveKeyMsg};

use hub_lib::hub;
use hub::{Hub};
use hub_lib::protocol::attestation::Attestation;
use crate::hub_lib::Result;


fn main() {
   env_logger::init();

   let mut hub = Hub::init();
   
   let urls = hub.config.client.get_urls().unwrap();
   
   for url in &urls {
        info!("Initializing lockbox enclave: {}", &url);
        match init_enclave(&mut hub, &Client::new(url)){
            Ok(_) => info!("Initialized lockbox enclave: {}", &url),
            Err(e) => warn!("Failed to initialize lockbox enclave: {} - {}", &url, &e)
        }
   }
}

fn init_enclave(hub: &mut Hub, lockbox: &Client) -> Result<()> {

    let one_second = time::Duration::from_millis(1000);
    let five_seconds = time::Duration::from_millis(5000);
    
    thread::sleep(five_seconds);

    info!("...getting src enclave id...\n");
    let enclave_id_msg: EnclaveIDMsg = hub.enclave_id();

    info!("hub enclave id: {:?}", enclave_id_msg);
   
    
    info!("...requesting session...\n");
    let dhmsg1: DHMsg1 = post(lockbox, "attestation/session_request", &enclave_id_msg)?;
    thread::sleep(one_second);

    info!("...proc_msg1...\n");
    let dh_msg2: DHMsg2 = hub.proc_msg1(&dhmsg1)?;

    
    let rep_msg = ExchangeReportMsg {
	    src_enclave_id: enclave_id_msg.inner,
	    dh_msg2,
    };
    
    info!("...exchange_report...\n");
    let dh_msg3: DHMsg3 = post(lockbox, "attestation/exchange_report", &rep_msg)?;
    thread::sleep(one_second);


    info!("...proc_msg3...\n");
    let _key_msg = hub.proc_msg3(&dh_msg3)?;

    
    info!("...get_session_enclave_key...\n");

    let sess_ec = hub.get_session_enclave_key()?;

    info!("...got_session_enclave_key...\n");

    let session_ec_key_msg = SetSessionEnclaveKeyMsg {
        data: sess_ec
    };

    info!("...posting set_session_enclave_key\n");

    let _result: () = post(lockbox, "attestation/set_session_enclave_key", &session_ec_key_msg)?;

    thread::sleep(one_second);

    info!("...init_shared completed.\n");
    
    Ok(())
}
