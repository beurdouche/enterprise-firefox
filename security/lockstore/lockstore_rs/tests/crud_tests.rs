/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use lockstore_rs::{Lockstore, LockstoreError, SecurityLevel};
use std::path::PathBuf;

#[test]
fn test_crud_operations() {
    let mut store = Lockstore::new(None, "test_db".to_string()).expect("Failed to create store");

    store.put("key1", b"value1").expect("Failed to put");

    let value = store.get("key1").expect("Failed to get");
    assert_eq!(value, b"value1");

    let keys = store.list().expect("Failed to list");
    assert_eq!(keys, vec!["key1"]);

    store.put("key2", b"value2").expect("Failed to put key2");
    let keys = store.list().expect("Failed to list");
    assert_eq!(keys.len(), 2);

    let deleted = store.delete("key1").expect("Failed to delete");
    assert!(deleted);

    let keys = store.list().expect("Failed to list after delete");
    assert_eq!(keys, vec!["key2"]);

    store.close();
}

#[test]
fn test_get_nonexistent_key() {
    let mut store = Lockstore::new(None, "test_db".to_string()).expect("Failed to create store");

    let result = store.get("nonexistent");
    assert!(matches!(result, Err(LockstoreError::NotFound(_))));

    store.close();
}

#[test]
fn test_delete_nonexistent_key() {
    let store = Lockstore::new(None, "test_db".to_string()).expect("Failed to create store");

    let deleted = store.delete("nonexistent").expect("Failed to delete");
    assert!(!deleted);

    store.close();
}

#[test]
fn test_update_existing_key() {
    let mut store = Lockstore::new(None, "test_db".to_string()).expect("Failed to create store");

    store.put("key1", b"value1").expect("Failed to put");
    let value = store.get("key1").expect("Failed to get");
    assert_eq!(value, b"value1");

    store.put("key1", b"value2").expect("Failed to update");
    let value = store.get("key1").expect("Failed to get updated value");
    assert_eq!(value, b"value2");

    let keys = store.list().expect("Failed to list");
    assert_eq!(keys.len(), 1);

    store.close();
}

#[test]
fn test_empty_list() {
    let store = Lockstore::new(None, "test_db".to_string()).expect("Failed to create store");

    let keys = store.list().expect("Failed to list");
    assert_eq!(keys.len(), 0);

    store.close();
}

#[test]
fn test_encrypted_storage() {
    let profile_path = PathBuf::from("/tmp/lockstore_test_profile");
    let mut store = Lockstore::with_security_level(
        None,
        "test_encrypted_db".to_string(),
        SecurityLevel::LocalKey,
        Some(profile_path),
    )
    .expect("Failed to create encrypted store");

    store
        .put("secret_key", b"secret_value")
        .expect("Failed to put encrypted");

    let value = store.get("secret_key").expect("Failed to get encrypted");
    assert_eq!(value, b"secret_value");

    let keys = store.list().expect("Failed to list encrypted");
    assert_eq!(keys, vec!["secret_key"]);

    store.close();
}

#[test]
fn test_encryption_persistence() {
    let profile_path = PathBuf::from("/tmp/lockstore_test_profile2");

    {
        let mut store = Lockstore::with_security_level(
            None,
            "test_persist_db".to_string(),
            SecurityLevel::LocalKey,
            Some(profile_path.clone()),
        )
        .expect("Failed to create encrypted store");

        store
            .put("persist_key", b"persist_value")
            .expect("Failed to put");
        store.close();
    }

    {
        let mut store = Lockstore::with_security_level(
            None,
            "test_persist_db".to_string(),
            SecurityLevel::LocalKey,
            Some(profile_path),
        )
        .expect("Failed to create encrypted store");

        let value = store
            .get("persist_key")
            .expect("Failed to get persisted value");
        assert_eq!(value, b"persist_value");
        store.close();
    }
}
