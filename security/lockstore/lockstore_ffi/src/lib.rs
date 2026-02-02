/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use lockstore_rs::{
    datastore_filename, LockstoreDatastore, LockstoreKeystore, LockstoreKeystoreError,
    SecurityLevel, KEYSTORE_FILENAME,
};
use nserror::{
    nsresult, NS_ERROR_ALREADY_INITIALIZED, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG,
    NS_ERROR_NOT_AVAILABLE, NS_OK,
};
use nsstring::{nsACString, nsCString};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thin_vec::ThinVec;

// ============================================================================
// Global State
// ============================================================================

static PROFILE_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static KEYSTORE: Mutex<Option<Arc<LockstoreKeystore>>> = Mutex::new(None);
static DATASTORES: Mutex<Option<HashMap<String, LockstoreDatastore>>> = Mutex::new(None);

fn with_datastores<F, R>(f: F) -> R
where
    F: FnOnce(&HashMap<String, LockstoreDatastore>) -> R,
{
    let mut guard = DATASTORES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn with_datastores_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, LockstoreDatastore>) -> R,
{
    let mut guard = DATASTORES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn error_to_nsresult(err: LockstoreKeystoreError) -> nsresult {
    log::error!("Lockstore error: {}", err);
    match err {
        LockstoreKeystoreError::NotFound(_) => NS_ERROR_NOT_AVAILABLE,
        LockstoreKeystoreError::Serialization(_) => NS_ERROR_INVALID_ARG,
        _ => NS_ERROR_FAILURE,
    }
}

// ============================================================================
// Security Level FFI Type
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum LockstoreSecurityLevel {
    LocalKey = 0,
}

impl From<LockstoreSecurityLevel> for SecurityLevel {
    fn from(level: LockstoreSecurityLevel) -> Self {
        match level {
            LockstoreSecurityLevel::LocalKey => SecurityLevel::LocalKey,
        }
    }
}

// ============================================================================
// Keystore FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn lockstore_keystore_open(profile_path: &nsACString) -> nsresult {
    log::debug!("lockstore_keystore_open");

    if profile_path.is_empty() {
        log::error!("Profile path cannot be empty");
        return NS_ERROR_INVALID_ARG;
    }

    let mut keystore_guard = KEYSTORE.lock().unwrap();
    if keystore_guard.is_some() {
        log::error!("Keystore already opened");
        return NS_ERROR_ALREADY_INITIALIZED;
    }

    let profile_path_str = profile_path.to_utf8();
    let profile = PathBuf::from(profile_path_str.as_ref());
    let keystore_path = profile.join(KEYSTORE_FILENAME);

    let keystore = match LockstoreKeystore::new(Some(keystore_path), "lockstore".to_string()) {
        Ok(k) => Arc::new(k),
        Err(e) => return error_to_nsresult(e),
    };

    *PROFILE_PATH.lock().unwrap() = Some(profile);
    *keystore_guard = Some(keystore);

    log::info!("Keystore opened for profile: {}", profile_path_str);
    NS_OK
}

#[no_mangle]
pub extern "C" fn lockstore_keystore_create_dek(
    collection: &nsACString,
    security_level: LockstoreSecurityLevel,
) -> nsresult {
    log::debug!("lockstore_keystore_create_dek");

    if collection.is_empty() {
        log::error!("Collection cannot be empty");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();

    let keystore_guard = KEYSTORE.lock().unwrap();
    let keystore = match keystore_guard.as_ref() {
        Some(k) => k,
        None => {
            log::error!("Keystore not opened");
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    match keystore.create_dek(
        &coll_str,
        security_level.into(),
        lockstore_rs::DEFAULT_CIPHER_SUITE,
    ) {
        Ok(_) => {
            log::info!("DEK created for collection: {}", coll_str);
            NS_OK
        }
        Err(e) => error_to_nsresult(e),
    }
}

#[no_mangle]
pub extern "C" fn lockstore_keystore_delete_dek(
    collection: &nsACString,
    ret_deleted: &mut bool,
) -> nsresult {
    log::debug!("lockstore_keystore_delete_dek");

    if collection.is_empty() {
        log::error!("Collection cannot be empty");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();

    let keystore_guard = KEYSTORE.lock().unwrap();
    let keystore = match keystore_guard.as_ref() {
        Some(k) => k,
        None => {
            log::error!("Keystore not opened");
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    match keystore.delete_dek(&coll_str) {
        Ok(deleted) => {
            *ret_deleted = deleted;
            log::info!("DEK delete result for {}: {}", coll_str, deleted);
            NS_OK
        }
        Err(e) => error_to_nsresult(e),
    }
}

#[no_mangle]
pub extern "C" fn lockstore_keystore_list_collections(
    ret_collections: &mut ThinVec<nsCString>,
) -> nsresult {
    log::debug!("lockstore_keystore_list_collections");

    let keystore_guard = KEYSTORE.lock().unwrap();
    let keystore = match keystore_guard.as_ref() {
        Some(k) => k,
        None => {
            log::error!("Keystore not opened");
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    match keystore.list_collections() {
        Ok(collections) => {
            *ret_collections = collections
                .into_iter()
                .map(|c| nsCString::from(&c[..]))
                .collect();
            log::debug!("Listed {} collections", ret_collections.len());
            NS_OK
        }
        Err(e) => error_to_nsresult(e),
    }
}

#[no_mangle]
pub extern "C" fn lockstore_keystore_close() -> nsresult {
    log::debug!("lockstore_keystore_close");

    // Close all datastores first
    with_datastores_mut(|datastores| {
        for (name, datastore) in datastores.drain() {
            log::debug!("Closing datastore for collection: {}", name);
            datastore.close();
        }
    });

    let mut keystore_guard = KEYSTORE.lock().unwrap();
    if keystore_guard.is_none() {
        log::warn!("Keystore not opened");
        return NS_ERROR_NOT_AVAILABLE;
    }

    *keystore_guard = None;
    *PROFILE_PATH.lock().unwrap() = None;

    log::info!("Keystore closed");
    NS_OK
}

// ============================================================================
// Datastore FFI Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn lockstore_datastore_open(collection: &nsACString) -> nsresult {
    log::debug!("lockstore_datastore_open");

    if collection.is_empty() {
        log::error!("Collection cannot be empty");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();

    let profile_path = match PROFILE_PATH.lock().unwrap().clone() {
        Some(p) => p,
        None => {
            log::error!("Profile path not set - open keystore first");
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    let keystore = match KEYSTORE.lock().unwrap().clone() {
        Some(k) => k,
        None => {
            log::error!("Keystore not opened");
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    // Check if already open and insert in one operation
    with_datastores_mut(|datastores| {
        if datastores.contains_key(coll_str.as_ref()) {
            log::error!("Datastore already opened for collection: {}", coll_str);
            return NS_ERROR_ALREADY_INITIALIZED;
        }

        let datastore_path = profile_path.join(datastore_filename(&coll_str));

        let datastore =
            match LockstoreDatastore::new(Some(datastore_path), coll_str.to_string(), keystore) {
                Ok(d) => d,
                Err(e) => return error_to_nsresult(e),
            };

        datastores.insert(coll_str.to_string(), datastore);

        log::info!("Datastore opened for collection: {}", coll_str);
        NS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn lockstore_datastore_put(
    collection: &nsACString,
    entry_name: &nsACString,
    data_ptr: *const u8,
    data_len: usize,
) -> nsresult {
    log::debug!("lockstore_datastore_put");

    if collection.is_empty() || entry_name.is_empty() {
        log::error!("Invalid arguments");
        return NS_ERROR_INVALID_ARG;
    }

    if data_ptr.is_null() || data_len == 0 {
        log::error!("Invalid data pointer or length");
        return NS_ERROR_INVALID_ARG;
    }

    let data_slice = std::slice::from_raw_parts(data_ptr, data_len);
    let coll_str = collection.to_utf8();
    let entry_str = entry_name.to_utf8();

    with_datastores(|datastores| {
        let datastore = match datastores.get(coll_str.as_ref()) {
            Some(d) => d,
            None => {
                log::error!("Datastore not found: {}", coll_str);
                return NS_ERROR_NOT_AVAILABLE;
            }
        };

        match datastore.put(&entry_str, data_slice) {
            Ok(_) => {
                log::debug!("Put successful: {}", entry_str);
                NS_OK
            }
            Err(e) => error_to_nsresult(e),
        }
    })
}

#[no_mangle]
pub extern "C" fn lockstore_datastore_get(
    collection: &nsACString,
    entry_name: &nsACString,
    ret_data: &mut ThinVec<u8>,
) -> nsresult {
    log::debug!("lockstore_datastore_get");

    if collection.is_empty() || entry_name.is_empty() {
        log::error!("Invalid arguments");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();
    let entry_str = entry_name.to_utf8();

    with_datastores(|datastores| {
        let datastore = match datastores.get(coll_str.as_ref()) {
            Some(d) => d,
            None => {
                log::error!("Datastore not found: {}", coll_str);
                return NS_ERROR_NOT_AVAILABLE;
            }
        };

        match datastore.get(&entry_str) {
            Ok(data) => {
                *ret_data = data.into();
                log::debug!("Get successful: {}, len={}", entry_str, ret_data.len());
                NS_OK
            }
            Err(e) => error_to_nsresult(e),
        }
    })
}

#[no_mangle]
pub extern "C" fn lockstore_datastore_delete(
    collection: &nsACString,
    entry_name: &nsACString,
    ret_deleted: &mut bool,
) -> nsresult {
    log::debug!("lockstore_datastore_delete");

    if collection.is_empty() || entry_name.is_empty() {
        log::error!("Invalid arguments");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();
    let entry_str = entry_name.to_utf8();

    with_datastores(|datastores| {
        let datastore = match datastores.get(coll_str.as_ref()) {
            Some(d) => d,
            None => {
                log::error!("Datastore not found: {}", coll_str);
                return NS_ERROR_NOT_AVAILABLE;
            }
        };

        match datastore.delete(&entry_str) {
            Ok(deleted) => {
                *ret_deleted = deleted;
                log::debug!("Delete result for {}: {}", entry_str, deleted);
                NS_OK
            }
            Err(e) => error_to_nsresult(e),
        }
    })
}

#[no_mangle]
pub extern "C" fn lockstore_datastore_list(
    collection: &nsACString,
    ret_entries: &mut ThinVec<nsCString>,
) -> nsresult {
    log::debug!("lockstore_datastore_list");

    if collection.is_empty() {
        log::error!("Invalid arguments");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();

    with_datastores(|datastores| {
        let datastore = match datastores.get(coll_str.as_ref()) {
            Some(d) => d,
            None => {
                log::error!("Datastore not found: {}", coll_str);
                return NS_ERROR_NOT_AVAILABLE;
            }
        };

        match datastore.list() {
            Ok(entries) => {
                *ret_entries = entries
                    .into_iter()
                    .map(|e| nsCString::from(&e[..]))
                    .collect();
                log::debug!("Listed {} entries", ret_entries.len());
                NS_OK
            }
            Err(e) => error_to_nsresult(e),
        }
    })
}

#[no_mangle]
pub extern "C" fn lockstore_datastore_close(collection: &nsACString) -> nsresult {
    log::debug!("lockstore_datastore_close");

    if collection.is_empty() {
        log::error!("Collection cannot be empty");
        return NS_ERROR_INVALID_ARG;
    }

    let coll_str = collection.to_utf8();

    with_datastores_mut(|datastores| match datastores.remove(coll_str.as_ref()) {
        Some(datastore) => {
            datastore.close();
            log::info!("Datastore closed: {}", coll_str);
            NS_OK
        }
        None => {
            log::warn!("Datastore not found for closing: {}", coll_str);
            NS_ERROR_NOT_AVAILABLE
        }
    })
}
