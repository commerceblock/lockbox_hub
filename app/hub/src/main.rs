extern crate hub_lib;
extern crate url;
extern crate shared_lib;
extern crate log;
use hub_lib::{Client, post};
use log::{info, warn};
use url::Url;

use shared_lib::structs::{EnclaveIDMsg, DHMsg1, DHMsg2, DHMsg3, 
    ExchangeReportMsg, SetSessionEnclaveKeyMsg};

use hub_lib::hub;
use hub::{Hub};
use hub_lib::protocol::attestation::Attestation;
use crate::hub_lib::Result;


fn main() {
   let mut hub = Hub::init();
   
   let urls = hub.config.client.get_urls().unwrap();
   
   for url in &urls {
        match init_enclave(&mut hub, &Client::new(url)){
            Ok(_) => info!("Initialized lockbox enclave: {}", &url),
            Err(e) => warn!("Failed to initialize lockbox enclave: {} - {}", &url, &e)
        }
   }
}

fn init_enclave(hub: &mut Hub, lockbox: &Client) -> Result<()> {
    
    println!("...getting src enclave id...\n");
    let enclave_id_msg: EnclaveIDMsg = hub.enclave_id();

    println!("hub enclave id: {:?}", enclave_id_msg);
   
    
    println!("...requesting session with dst...\n");
    let dhmsg1: DHMsg1 = post(lockbox, "attestation/session_request", &enclave_id_msg)?;

    println!("...proc_msg1...\n");
    let dh_msg2: DHMsg2 = hub.proc_msg1(&dhmsg1)?;
    
    //post(&hub_url, "attestation/proc_msg1", &dhmsg1).unwrap();
    
    let rep_msg = ExchangeReportMsg {
	    src_enclave_id: enclave_id_msg.inner,
	    dh_msg2,
    };
    
    println!("...exchange_report...\n");
    let dh_msg3: DHMsg3 = post(lockbox, "attestation/exchange_report", &rep_msg)?;


    dbg!(serde_json::ser::to_string(&dh_msg3).unwrap());

    println!("...proc_msg3...\n");
    let _key_msg = hub.proc_msg3(&dh_msg3)?;

    println!("...get_session_enclave_key...\n");

    let sess_ec = hub.get_session_enclave_key()?;

    println!("...got_session_enclave_key: {:?}\n", &sess_ec);

    let session_ec_key_msg = SetSessionEnclaveKeyMsg {
        data: sess_ec
    };

    println!("...posting set_session_enclave_key\n");

    post(lockbox, "attestation/set_session_enclave_key", &session_ec_key_msg)?;

    println!("...init_shared completed.\n");

    Ok(())
}
