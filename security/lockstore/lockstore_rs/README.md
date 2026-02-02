# Lockstore Rust Library

Secure key-value storage with encryption using NSS (Network Security Services).

## Overview

Lockstore provides a secure storage solution for sensitive data in Firefox. It uses a two-tier encryption model where data is encrypted with Data Encryption Keys (DEKs), which are themselves protected by a Key Encryption Key (KEK). This design allows for efficient key rotation and provides cryptographic isolation between different data collections.

## Architecture

Lockstore separates key management from data storage using two distinct components:

- **LockstoreKeystore**: Manages the cryptographic keys. It stores the KEK and all DEKs in a dedicated keystore database. The keystore is responsible for generating new keys, wrapping/unwrapping DEKs, and maintaining the key hierarchy.

- **LockstoreDatastore**: Handles encrypted CRUD operations for a specific collection. Each collection has its own datastore that uses the collection's DEK (obtained from the keystore) to encrypt and decrypt user data.

This separation means you can have multiple datastores (one per collection) all sharing a single keystore, which centralizes key management while keeping data organized by collection.

## Key Hierarchy

The encryption follows a hierarchical key model:

```
KEK (Key Encryption Key)
  └── DEK (Data Encryption Key) - one per collection
        └── Encrypted Data - entries within a collection
```

**How it works:**
1. When the keystore is first created, it generates a KEK using NSS cryptographic primitives
2. When you create a DEK for a collection, the DEK is generated randomly and then "wrapped" (encrypted) using the KEK before being stored
3. When a datastore needs to encrypt/decrypt data, it retrieves and unwraps the DEK from the keystore
4. User data is then encrypted/decrypted using the unwrapped DEK with the specified cipher suite

This hierarchy means that even if the datastore database is compromised, the data cannot be decrypted without access to both the keystore (for the wrapped DEK) and the KEK.

## Storage Structure

Lockstore uses SQLite databases via the kvstore crate for persistence. Keys are organized with namespaced prefixes to avoid collisions.

### Keystore Database Keys
```
lockstore::kek::local                     → KEK (unencrypted random key)
lockstore::dek::com.mozilla.logins        → DEK metadata (wrapped_dek, cipher_suite, security_level, kek_ref)
lockstore::dek::com.mozilla.cookies       → DEK metadata
```

### Datastore Database Keys
```
com.mozilla.logins::login_123             → Encrypted user data
com.mozilla.logins::login_456             → Encrypted user data
com.mozilla.cookies::cookie_abc           → Encrypted user data
```

## Usage Examples

### Basic Setup

This example demonstrates the typical workflow: create a keystore, generate a DEK for your collection, create a datastore, and perform CRUD operations. All data passed to `put()` is automatically encrypted, and data from `get()` is automatically decrypted.

```rust
use lockstore_rs::{LockstoreKeystore, LockstoreDatastore, SecurityLevel, CipherSuite};
use std::sync::Arc;
use std::path::PathBuf;

// Create keystore and generate DEK for a collection
let keystore_path = PathBuf::from("/path/to/keystore.db");
let keystore = Arc::new(LockstoreKeystore::new(Some(keystore_path), "db_key".to_string())?);

// Create a DEK for the "com.mozilla.logins" collection
keystore.create_dek(
    "com.mozilla.logins",
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
)?;

// Create datastore for the collection
let data_path = PathBuf::from("/path/to/logins.db");
let datastore = LockstoreDatastore::new(
    Some(data_path),
    "com.mozilla.logins".to_string(),
    Arc::clone(&keystore)
)?;

// Store encrypted data
let login_data = b"username:password";
datastore.put("login_123", login_data)?;

// Retrieve and decrypt data
let retrieved = datastore.get("login_123")?;
assert_eq!(retrieved, login_data);

// List all entries
let entries = datastore.list()?;
println!("Entries: {:?}", entries);

// Delete an entry
let deleted = datastore.delete("login_123")?;
assert!(deleted);
```

### Multiple Collections with Shared Keystore

A single keystore can manage DEKs for multiple collections. Each collection gets its own datastore with its own database file, but they all share the same keystore for key management. This is the recommended pattern for applications that need to store different types of sensitive data.

```rust
use lockstore_rs::{LockstoreKeystore, LockstoreDatastore, SecurityLevel, CipherSuite};
use std::sync::Arc;
use std::path::PathBuf;

// Single keystore for all collections
let keystore = Arc::new(LockstoreKeystore::new(
    Some(PathBuf::from("/path/to/keystore.db")),
    "db_key".to_string()
)?);

// Create DEKs for multiple collections
keystore.create_dek("com.mozilla.logins", SecurityLevel::LocalKey, CipherSuite::Aes256Gcm)?;
keystore.create_dek("com.mozilla.cookies", SecurityLevel::LocalKey, CipherSuite::ChaCha20Poly1305)?;

// Create separate datastores for each collection
let logins_store = LockstoreDatastore::new(
    Some(PathBuf::from("/path/to/logins.db")),
    "com.mozilla.logins".to_string(),
    Arc::clone(&keystore)
)?;

let cookies_store = LockstoreDatastore::new(
    Some(PathBuf::from("/path/to/cookies.db")),
    "com.mozilla.cookies".to_string(),
    Arc::clone(&keystore)
)?;

// Use each datastore independently
logins_store.put("user1", b"secret_password")?;
cookies_store.put("session", b"cookie_value")?;

// List all collections
let collections = keystore.list_collections()?;
println!("Collections: {:?}", collections);
```

### Key Management Operations

The keystore provides methods to manage the lifecycle of DEKs. You can create new DEKs, retrieve DEK metadata (useful for debugging or migration), list all collections that have DEKs, and delete DEKs when they're no longer needed.

Note that deleting a DEK makes all data encrypted with that DEK permanently inaccessible. Always ensure the associated datastore data is no longer needed before deleting a DEK.

```rust
use lockstore_rs::{LockstoreKeystore, SecurityLevel, CipherSuite};
use std::path::PathBuf;

let keystore = LockstoreKeystore::new(
    Some(PathBuf::from("/path/to/keystore.db")),
    "db_key".to_string()
)?;

// Create a DEK
keystore.create_dek(
    "com.mozilla.passwords",
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
)?;

// Retrieve DEK information
let (dek_bytes, cipher_suite, security_level) = keystore.get_dek("com.mozilla.passwords")?;
println!("DEK size: {} bytes", dek_bytes.len());
println!("Cipher: {:?}", cipher_suite);

// List all collections
let collections = keystore.list_collections()?;
for collection in collections {
    println!("Collection: {}", collection);
}

// Delete a DEK
let deleted = keystore.delete_dek("com.mozilla.passwords")?;
if deleted {
    println!("DEK deleted successfully");
}
```

## Security Levels

Security levels determine how the DEK is protected:

- **SecurityLevel::LocalKey**: The DEK is encrypted using a locally-generated KEK stored in the keystore database. This provides encryption at rest, protecting data if the database files are copied or the disk is accessed offline.

## Cipher Suites

Cipher suites determine the encryption algorithm used to protect user data:

- **CipherSuite::Aes256Gcm**: AES-256 in Galois/Counter Mode. This is the recommended default. AES-GCM is widely supported, hardware-accelerated on most modern CPUs, and provides authenticated encryption (both confidentiality and integrity).

- **CipherSuite::ChaCha20Poly1305**: ChaCha20 stream cipher with Poly1305 authenticator. An alternative AEAD cipher that performs well in software on platforms without AES hardware acceleration. Provides equivalent security to AES-256-GCM.

## Error Handling

All operations return `Result<T, LockstoreKeystoreError>`. The error type provides specific variants for different failure modes, allowing callers to handle errors appropriately:

```rust
use lockstore_rs::LockstoreKeystoreError;

match datastore.get("entry_name") {
    Ok(data) => println!("Retrieved: {:?}", data),
    Err(LockstoreKeystoreError::EntryNotFound(msg)) => println!("Not found: {}", msg),
    Err(LockstoreKeystoreError::Decryption(msg)) => println!("Decryption failed: {}", msg),
    Err(e) => println!("Error: {:?}", e),
}
```

## Thread Safety

Lockstore is designed for use in multi-threaded applications:

- `LockstoreKeystore` should be wrapped in `Arc` for sharing across threads
- Internal synchronization is handled by kvstore
- Multiple datastores can safely share the same keystore

The recommended pattern is to create the keystore once at application startup, wrap it in `Arc`, and clone the `Arc` when creating datastores or passing the keystore to different threads.

## Best Practices

1. **Single keystore**: Use a single keystore for all collections in your application. This centralizes key management and simplifies backup/recovery.

2. **Separate datastores**: Create separate data databases for each collection. This provides logical separation and allows collections to be managed independently.

3. **Check DEK existence**: Always ensure a DEK exists before creating a datastore. The datastore constructor will fail if no DEK is found for the collection.

4. **Use AES-256-GCM**: Use `CipherSuite::Aes256Gcm` for most use cases. It's the recommended default with excellent performance on modern hardware.

5. **Clean up unused DEKs**: Delete DEKs when collections are no longer needed. This reduces the attack surface and ensures cryptographic material doesn't persist unnecessarily.
