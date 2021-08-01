//! Structs
//!
//! Struct definitions used in State entity protocols

extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;

big_array! {
    BigArray;
    +42,
}

#[derive(Deserialize, Serialize, Copy, Clone)]
#[serde(remote = "sgx_dh_msg1_t")]
#[allow(unaligned_references)]
struct DHMsg1Def {
    #[serde(with = "EC256PublicDef")]
    pub g_a: sgx_ec256_public_t,
    #[serde(with = "TargetInfoDef")]
    pub target: sgx_target_info_t,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg2_t")]
#[allow(unaligned_references)]
struct DHMsg2Def {
    #[serde(with = "EC256PublicDef")]
    pub g_b: sgx_ec256_public_t,
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_body_t")]
#[allow(unaligned_references)]
struct DHMsg3BodyDef {
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    pub additional_prop_length: uint32_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub additional_prop: [uint8_t; 0],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_t")]
pub struct DHMsg3Def {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
    #[serde(with = "DHMsg3BodyDef")]
    pub msg3_body: sgx_dh_msg3_body_t,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_report_t")]
pub struct ReportDef {
    #[serde(with = "ReportBodyDef")]
    pub body: sgx_report_body_t,
    #[serde(with = "KeyIDDef")]
    pub key_id: sgx_key_id_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub mac: sgx_mac_t,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_key_id_t")]
pub struct KeyIDDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub id: [uint8_t; SGX_KEYID_SIZE],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_report_data_t")]
pub struct ReportDataDef {
    #[serde(with = "BigArray")]
    pub d: [uint8_t; SGX_REPORT_DATA_SIZE],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_cpu_svn_t")]
pub struct CpuSvnDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub svn: [uint8_t; SGX_CPUSVN_SIZE],
}



#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(remote = "sgx_ec256_public_t")]
struct EC256PublicDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gx: [uint8_t; SGX_ECP256_KEY_SIZE],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gy: [uint8_t; SGX_ECP256_KEY_SIZE],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
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


    #[derive(Copy, Clone, Serialize, Deserialize)]
    #[serde(remote = "sgx_measurement_t")]
    pub struct MeasurementDef {
	#[serde(serialize_with = "<[_]>::serialize")]
        pub m: [uint8_t; SGX_HASH_SIZE],
    }




//impl_struct! {
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "sgx_attributes_t")]
    pub struct AttributesDef {
        pub flags: uint64_t,
        pub xfrm: uint64_t,
    }
//}

//Attestation
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnclaveIDMsg {
    pub inner: sgx_enclave_id_t
}

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct ExchangeReportMsg {
    pub src_enclave_id: sgx_enclave_id_t,
    pub dh_msg2: DHMsg2,
//    pub session_ptr: usize,
}


#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct DHMsg1 {
    #[serde(with = "DHMsg1Def")]
    pub inner: sgx_dh_msg1_t,
}

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct DHMsg2 {
    #[serde(with = "DHMsg2Def")]
    pub inner: sgx_dh_msg2_t,
}

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct DHMsg3 {
    #[serde(with = "DHMsg3Def")]
    pub inner: sgx_dh_msg3_t,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct SetSessionEnclaveKeyMsg {
    #[serde(with = "BigArray")]
    pub data: [u8; 8192]
}