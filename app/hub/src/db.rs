use rocksdb::{DB, Options as DBOptions, ColumnFamilyDescriptor};
use crate::config::Config;

pub fn get_db(config_rs: &Config) ->  DB {
    get_db_write_opt(config_rs, false)
}

pub fn get_db_read_only(config_rs: &Config) -> DB {
    get_db_write_opt(config_rs, true)
}

pub fn get_db_write_opt(config_rs: &Config, readonly: bool) -> DB {
    
    let key_db_path = config_rs.storage.key_db_path.to_owned();
            
        let mut key_db_opts = DBOptions::default();
        key_db_opts.create_missing_column_families(true);
        key_db_opts.create_if_missing(true);
        
        let mut key_db_cf_opts = DBOptions::default();	
        key_db_cf_opts.set_max_write_buffer_number(16);
        let mut key_db_column_families = Vec::<ColumnFamilyDescriptor>::new();
        key_db_column_families.push(ColumnFamilyDescriptor::new("enclave_id", key_db_cf_opts.clone()));
        key_db_column_families.push(ColumnFamilyDescriptor::new("enclave_key", key_db_cf_opts.clone()));

    
    if readonly{
        match DB::open_for_read_only(&key_db_opts, key_db_path, false) {
            Ok(key_db) => key_db,
            Err(e) => { panic!("failed to open key database: {:?}", e) }
        }
    } else {
        match DB::open_cf_descriptors(&key_db_opts, key_db_path, key_db_column_families) {
            Ok(key_db) => key_db,
            Err(e) => { panic!("failed to open key database: {:?}", e) }
        }
    }
}


