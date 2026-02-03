/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! LockstoreKeystore: A secure key-value storage system with encryption support
//!
//! # Architecture
//!
//! Uses a two-layer encryption model:
//! - **KEK (Key Encryption Key)**: Derived from security level, used to wrap DEKs
//! - **DEK (Data Encryption Key)**: Random per-collection key that encrypts all data in that collection
//!
//! # Collections and Security Levels
//!
//! Each collection (identified by `db_key`) has its own DEK with its own:
//! - **Security Level**: Determines which KEK protects the DEK (LocalKey, etc.)
//! - **Cipher Suite**: Determines encryption algorithm (AES-256-GCM, ChaCha20-Poly1305)
//!
//! Examples:
//! - `com.mozilla.logins` → LocalKey security, AES-256-GCM
//! - `com.mozilla.cards` → LocalKey security, ChaCha20-Poly1305
//!
//! This allows different data types to have different security properties while
//! sharing the same underlying database file.

mod crypto;
mod utils;

pub use crypto::CipherSuite;
pub use crypto::DEFAULT_CIPHER_SUITE;

pub const KEYSTORE_FILENAME: &str = "lockstore.keys.sqlite";
pub const DATASTORE_FILENAME_PREFIX: &str = "lockstore.data.";
pub const DATASTORE_FILENAME_SUFFIX: &str = ".sqlite";

pub fn datastore_filename(collection_name: &str) -> String {
    format!(
        "{}{}{}",
        DATASTORE_FILENAME_PREFIX, collection_name, DATASTORE_FILENAME_SUFFIX
    )
}

use kvstore::skv::store::{Store, StoreError, StorePath};
use kvstore::skv::{Database, DatabaseError, GetOptions, Key};
use nss_gk_api::Error as NssError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

// Constants
const KEK_PREFIX: &str = "lockstore::kek::"; // Prefix for KEK storage keys
const DEK_PREFIX: &str = "lockstore::dek::"; // Prefix for DEK storage keys (encrypted with KEK)

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum LockstoreKeystoreError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("DEK is not extractable: {0}")]
    NotExtractable(String),
}

impl From<serde_json::Error> for LockstoreKeystoreError {
    fn from(err: serde_json::Error) -> Self {
        LockstoreKeystoreError::Serialization(err.to_string())
    }
}

impl From<NssError> for LockstoreKeystoreError {
    fn from(err: NssError) -> Self {
        LockstoreKeystoreError::Encryption(err.to_string())
    }
}

// ============================================================================
// Security Level
// ============================================================================

/// Security level for data encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Local key encryption - random key stored in profile directory
    LocalKey,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::LocalKey
    }
}

impl SecurityLevel {
    pub fn as_str(&self) -> &str {
        match self {
            SecurityLevel::LocalKey => "local",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "local" => Some(SecurityLevel::LocalKey),
            _ => None,
        }
    }
}

// ============================================================================
// Storage Format
// ============================================================================

/// Internal format for stored values with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredValue {
    pub data: Vec<u8>,
    pub timestamp: u64,
}

/// Metadata stored with the DEK
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DekMetadata {
    wrapped_dek: Vec<u8>,
    cipher_suite: String,
    security_level: String,
    kek_ref: String,
    #[serde(default)]
    extractable: bool,
}

// ============================================================================
// LockstoreKeystore
// ============================================================================

/// Secure key-value storage with optional encryption
#[derive(Clone)]
pub struct LockstoreKeystore {
    store: Arc<Store>,
    db_key: String,
    default_security_level: SecurityLevel,
    default_cipher_suite: CipherSuite,
}

impl LockstoreKeystore {
    /// Creates a new lockstore with LocalKey security
    ///
    /// # Arguments
    /// * `path` - Database file path, or None for in-memory storage
    /// * `db_key` - Collection name (e.g., "com.mozilla.logins", "com.mozilla.cookies")
    pub fn new(path: Option<PathBuf>, db_key: String) -> Result<Self, LockstoreKeystoreError> {
        Self::with_security_level(path, db_key, SecurityLevel::LocalKey)
    }

    /// Creates a new lockstore with specified security level
    ///
    /// # Arguments
    /// * `path` - Database file path, or None for in-memory storage
    /// * `db_key` - Collection name (e.g., "com.mozilla.logins", "com.mozilla.cookies")
    ///               Each collection gets its own DEK with its own security level
    /// * `security_level` - Security level for encryption (default for new collections)
    pub fn with_security_level(
        path: Option<PathBuf>,
        db_key: String,
        security_level: SecurityLevel,
    ) -> Result<Self, LockstoreKeystoreError> {
        Self::with_security_and_cipher(path, db_key, security_level, DEFAULT_CIPHER_SUITE)
    }

    /// Creates a new lockstore with specified security level and cipher suite
    ///
    /// # Arguments
    /// * `path` - Database file path, or None for in-memory storage
    /// * `db_key` - Collection name (e.g., "com.mozilla.logins", "com.mozilla.cookies")
    ///               Each collection gets its own DEK with its own security level and cipher suite
    /// * `security_level` - Security level for encryption (default for new collections)
    /// * `cipher_suite` - Cipher suite to use for encryption (default for new collections)
    pub fn with_security_and_cipher(
        path: Option<PathBuf>,
        db_key: String,
        security_level: SecurityLevel,
        cipher_suite: CipherSuite,
    ) -> Result<Self, LockstoreKeystoreError> {
        let store_path = match path {
            Some(p) => StorePath::OnDisk(p),
            None => StorePath::for_in_memory(),
        };

        let store = Arc::new(Store::new(store_path));

        // Initialize NSS (idempotent)
        nss_gk_api::init();

        Ok(Self {
            store,
            db_key,
            default_security_level: security_level,
            default_cipher_suite: cipher_suite,
        })
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.default_cipher_suite
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.default_security_level
    }

    /// Creates a new DEK for a collection
    ///
    /// Generates a new random DEK, wraps it with the KEK, and stores it in the keystore.
    /// Returns an error if the DEK already exists.
    ///
    /// # Arguments
    /// * `collection_name` - Name of the collection (e.g., "com.mozilla.logins")
    /// * `security_level` - Security level for this collection
    /// * `cipher_suite` - Cipher suite to use for encryption
    /// * `extractable` - Whether the raw DEK bytes can be retrieved via `get_dek`
    pub fn create_dek(
        &self,
        collection_name: &str,
        security_level: SecurityLevel,
        cipher_suite: CipherSuite,
        extractable: bool,
    ) -> Result<(), LockstoreKeystoreError> {
        let dek_key = format!("{}{}", DEK_PREFIX, collection_name);

        // Check if DEK already exists
        let db = Database::new(&self.store, &self.db_key);
        let key = Key::from(dek_key.as_str());
        let existing = db.get(&key, &GetOptions::default())?;

        if existing.is_some() {
            return Err(LockstoreKeystoreError::InvalidConfiguration(format!(
                "DEK already exists for collection: {}",
                collection_name
            )));
        }

        // Generate new DEK
        let new_dek = crypto::generate_random_key(cipher_suite);

        // Get KEK for encryption
        let kek = self.get_kek_for(cipher_suite, security_level)?;

        // Wrap the DEK
        let wrapped_dek = crypto::encrypt_with_key(&new_dek, &kek, cipher_suite)?;

        // Create metadata
        let metadata = DekMetadata {
            wrapped_dek,
            cipher_suite: cipher_suite.as_str().to_string(),
            security_level: security_level.as_str().to_string(),
            kek_ref: Self::get_kek_key_for_security_level(security_level),
            extractable,
        };

        // Store metadata
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let value = utils::bytes_to_value(&metadata_bytes)?;
        db.put(&[(key, Some(value))])?;

        Ok(())
    }

    /// Internal method to get DEK metadata and unwrap the key
    fn get_dek_internal(
        &self,
        collection_name: &str,
    ) -> Result<(Vec<u8>, CipherSuite, SecurityLevel, bool), LockstoreKeystoreError> {
        let dek_key = format!("{}{}", DEK_PREFIX, collection_name);

        let db = Database::new(&self.store, &self.db_key);
        let key = Key::from(dek_key.as_str());

        // Try to load existing DEK metadata
        let existing_metadata = db.get(&key, &GetOptions::default())?;

        let metadata_value = existing_metadata.ok_or_else(|| {
            LockstoreKeystoreError::NotFound(format!(
                "DEK not found for collection: {}",
                collection_name
            ))
        })?;

        // Load existing DEK metadata
        let metadata_bytes = utils::value_to_bytes(&metadata_value)?;
        let metadata: DekMetadata = serde_json::from_slice(&metadata_bytes)?;

        // Parse cipher suite
        let cipher_suite = CipherSuite::from_str(&metadata.cipher_suite).ok_or_else(|| {
            LockstoreKeystoreError::InvalidConfiguration(format!(
                "Unknown cipher suite: {}",
                metadata.cipher_suite
            ))
        })?;

        // Parse security level
        let security_level =
            SecurityLevel::from_str(&metadata.security_level).ok_or_else(|| {
                LockstoreKeystoreError::InvalidConfiguration(format!(
                    "Unknown security level: {}",
                    metadata.security_level
                ))
            })?;

        // Validate that the KEK reference matches the expected KEK for this security level
        let expected_kek_ref = Self::get_kek_key_for_security_level(security_level);
        if metadata.kek_ref != expected_kek_ref {
            return Err(LockstoreKeystoreError::InvalidConfiguration(format!(
                "DEK references invalid KEK: expected '{}', found '{}'",
                expected_kek_ref, metadata.kek_ref
            )));
        }

        // Validate that the referenced KEK exists
        if !metadata.kek_ref.is_empty() {
            let kek_key = Key::from(metadata.kek_ref.as_str());
            let kek_exists = db.has(&kek_key, &GetOptions::default())?;
            if !kek_exists {
                return Err(LockstoreKeystoreError::InvalidConfiguration(format!(
                    "DEK references non-existent KEK: '{}'",
                    metadata.kek_ref
                )));
            }
        }

        // Get KEK
        let kek = self.get_kek_for(cipher_suite, security_level)?;

        // Unwrap the DEK
        let dek = crypto::decrypt_with_key(&metadata.wrapped_dek, &kek, cipher_suite)?;

        Ok((dek, cipher_suite, security_level, metadata.extractable))
    }

    /// Gets a DEK for a collection (only works for extractable DEKs)
    ///
    /// Retrieves and unwraps the DEK for the specified collection.
    /// Returns an error if the DEK doesn't exist or is not extractable.
    ///
    /// # Arguments
    /// * `collection_name` - Name of the collection
    ///
    /// # Returns
    /// Tuple of (dek_bytes, cipher_suite, security_level)
    pub fn get_dek(
        &self,
        collection_name: &str,
    ) -> Result<(Vec<u8>, CipherSuite, SecurityLevel), LockstoreKeystoreError> {
        let (dek, cipher_suite, security_level, extractable) =
            self.get_dek_internal(collection_name)?;

        if !extractable {
            return Err(LockstoreKeystoreError::NotExtractable(format!(
                "DEK for '{}' is not extractable",
                collection_name
            )));
        }

        Ok((dek, cipher_suite, security_level))
    }

    /// Gets a DEK for datastore use (bypasses extractable check)
    ///
    /// This is for internal use by the datastore to access DEKs that
    /// are not marked as extractable.
    pub fn get_dek_for_datastore(
        &self,
        collection_name: &str,
    ) -> Result<(Vec<u8>, CipherSuite, SecurityLevel), LockstoreKeystoreError> {
        let (dek, cipher_suite, security_level, _extractable) =
            self.get_dek_internal(collection_name)?;
        Ok((dek, cipher_suite, security_level))
    }

    /// Deletes a DEK for a collection
    ///
    /// Removes the DEK from the keystore database.
    ///
    /// # Arguments
    /// * `collection_name` - Name of the collection
    ///
    /// # Returns
    /// True if the DEK was deleted, false if it didn't exist
    pub fn delete_dek(&self, collection_name: &str) -> Result<bool, LockstoreKeystoreError> {
        let dek_key = format!("{}{}", DEK_PREFIX, collection_name);

        let db = Database::new(&self.store, &self.db_key);
        let key = Key::from(dek_key.as_str());

        let exists = db.has(&key, &GetOptions::default())?;
        if exists {
            db.delete(&key)?;
        }

        Ok(exists)
    }

    /// Lists all collections that have DEKs in the keystore
    ///
    /// # Returns
    /// Vector of collection names
    pub fn list_collections(&self) -> Result<Vec<String>, LockstoreKeystoreError> {
        let reader = self.store.reader()?;

        let collections = reader
            .read(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT data.key FROM data
                         JOIN dbs ON data.db_id = dbs.id
                         WHERE dbs.name = ?1
                         AND data.key LIKE ?2
                         ORDER BY data.key",
                    )
                    .map_err(DatabaseError::from)?;

                let dek_pattern = format!("{}%", DEK_PREFIX);
                let collection_strings: Result<Vec<String>, _> = stmt
                    .query_map([&self.db_key, &dek_pattern], |row| {
                        let key: String = row.get(0)?;
                        // Strip the DEK_PREFIX to get just the collection name
                        Ok(key.strip_prefix(DEK_PREFIX).unwrap_or(&key).to_string())
                    })
                    .map_err(DatabaseError::from)?
                    .collect();

                collection_strings.map_err(DatabaseError::from)
            })
            .map_err(LockstoreKeystoreError::Database)?;

        Ok(collections)
    }

    fn get_kek_key_for_security_level(security_level: SecurityLevel) -> String {
        match security_level {
            SecurityLevel::LocalKey => format!("{}local", KEK_PREFIX),
        }
    }

    fn get_kek_for(
        &self,
        cipher_suite: CipherSuite,
        security_level: SecurityLevel,
    ) -> Result<Vec<u8>, LockstoreKeystoreError> {
        let kek = match security_level {
            SecurityLevel::LocalKey => {
                let kek_key = Self::get_kek_key_for_security_level(security_level);
                let db = Database::new(&self.store, &self.db_key);
                let key = Key::from(kek_key.as_str());

                let existing_kek = db.get(&key, &GetOptions::default())?;

                if let Some(value) = existing_kek {
                    utils::value_to_bytes(&value)?
                } else {
                    let new_kek = crypto::generate_random_key(cipher_suite);
                    let value = utils::bytes_to_value(&new_kek)?;
                    db.put(&[(key, Some(value))])?;
                    new_kek
                }
            }
        };

        Ok(kek)
    }

    /// Closes the lockstore and releases resources
    pub fn close(self) {
        self.store.close();
    }
}

// ============================================================================
// LockstoreDatastore
// ============================================================================

/// Datastore for a specific collection with encryption
///
/// Manages CRUD operations for collection entries, storing data with
/// collection-prefixed keys (e.g., "com.mozilla.logins::entry_123").
/// Fetches DEK from the keystore for each operation (no caching).
#[derive(Clone)]
pub struct LockstoreDatastore {
    store: Arc<Store>,
    keystore: Arc<LockstoreKeystore>,
    collection_name: String,
}

impl LockstoreDatastore {
    /// Creates a new datastore for a collection
    ///
    /// # Arguments
    /// * `data_path` - Path to the data database file, or None for in-memory storage
    /// * `collection_name` - Collection identifier (e.g., "com.mozilla.logins")
    /// * `keystore` - Reference to the keystore that manages DEKs
    ///
    /// # Returns
    /// Error if the DEK doesn't exist for this collection
    pub fn new(
        data_path: Option<PathBuf>,
        collection_name: String,
        keystore: Arc<LockstoreKeystore>,
    ) -> Result<Self, LockstoreKeystoreError> {
        // Validate that DEK exists for this collection (use internal method to bypass extractable check)
        keystore.get_dek_for_datastore(&collection_name)?;

        let store_path = match data_path {
            Some(p) => StorePath::OnDisk(p),
            None => StorePath::for_in_memory(),
        };

        let store = Arc::new(Store::new(store_path));

        Ok(Self {
            store,
            keystore,
            collection_name,
        })
    }

    /// Stores data in the datastore
    ///
    /// # Arguments
    /// * `entry_name` - The entry name (will be prefixed with collection name)
    /// * `data` - The data to store
    pub fn put(&self, entry_name: &str, data: &[u8]) -> Result<(), LockstoreKeystoreError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = StoredValue {
            data: data.to_vec(),
            timestamp,
        };

        let plaintext = serde_json::to_vec(&stored)?;

        // Get DEK from keystore (use internal method to bypass extractable check)
        let (dek, cipher_suite, _security_level) =
            self.keystore.get_dek_for_datastore(&self.collection_name)?;

        // Always encrypt
        let data_to_store = crypto::encrypt_with_key(&plaintext, &dek, cipher_suite)?;

        // Store in database with collection prefix
        let full_key = format!("{}::{}", self.collection_name, entry_name);
        let value = utils::bytes_to_value(&data_to_store)?;

        let db = Database::new(&self.store, &self.collection_name);
        let key_obj = Key::from(full_key.as_str());
        db.put(&[(key_obj, Some(value))])?;

        Ok(())
    }

    /// Retrieves data from the datastore
    ///
    /// # Arguments
    /// * `entry_name` - The entry name
    ///
    /// # Returns
    /// The stored data, or NotFound error if entry doesn't exist
    pub fn get(&self, entry_name: &str) -> Result<Vec<u8>, LockstoreKeystoreError> {
        // Retrieve from database with collection prefix
        let full_key = format!("{}::{}", self.collection_name, entry_name);
        let db = Database::new(&self.store, &self.collection_name);
        let key_obj = Key::from(full_key.as_str());

        let value = db
            .get(&key_obj, &GetOptions::default())?
            .ok_or_else(|| LockstoreKeystoreError::NotFound(entry_name.to_string()))?;

        let stored_bytes = utils::value_to_bytes(&value)?;

        // Get DEK from keystore (use internal method to bypass extractable check)
        let (dek, cipher_suite, _security_level) =
            self.keystore.get_dek_for_datastore(&self.collection_name)?;

        // Always decrypt
        let plaintext = crypto::decrypt_with_key(&stored_bytes, &dek, cipher_suite)?;

        // Deserialize stored value
        let stored: StoredValue = serde_json::from_slice(&plaintext)?;
        Ok(stored.data)
    }

    /// Deletes an entry from the datastore
    ///
    /// # Arguments
    /// * `entry_name` - The entry name to delete
    ///
    /// # Returns
    /// True if the entry was deleted, false if it didn't exist
    pub fn delete(&self, entry_name: &str) -> Result<bool, LockstoreKeystoreError> {
        let full_key = format!("{}::{}", self.collection_name, entry_name);
        let db = Database::new(&self.store, &self.collection_name);
        let key_obj = Key::from(full_key.as_str());

        let exists = db.has(&key_obj, &GetOptions::default())?;
        if exists {
            db.delete(&key_obj)?;
        }

        Ok(exists)
    }

    /// Lists all entry names in the datastore
    ///
    /// # Returns
    /// Vector of entry names (without collection prefix)
    pub fn list(&self) -> Result<Vec<String>, LockstoreKeystoreError> {
        let reader = self.store.reader()?;
        let prefix = format!("{}::", self.collection_name);

        let entries = reader
            .read(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT data.key FROM data
                         JOIN dbs ON data.db_id = dbs.id
                         WHERE dbs.name = ?1
                         AND data.key LIKE ?2
                         ORDER BY data.key",
                    )
                    .map_err(DatabaseError::from)?;

                let pattern = format!("{}%", prefix);
                let entry_strings: Result<Vec<String>, _> = stmt
                    .query_map([&self.collection_name, &pattern], |row| {
                        let key: String = row.get(0)?;
                        // Strip the collection prefix to get just the entry name
                        Ok(key.strip_prefix(&prefix).unwrap_or(&key).to_string())
                    })
                    .map_err(DatabaseError::from)?
                    .collect();

                entry_strings.map_err(DatabaseError::from)
            })
            .map_err(LockstoreKeystoreError::Database)?;

        Ok(entries)
    }

    /// Closes the datastore and releases resources
    pub fn close(self) {
        self.store.close();
    }
}
