# Lockstore Rust Library

Secure key-value storage with encryption using NSS (Network Security Services).

## Architecture

Lockstore provides two separate APIs:

- **LockstoreKeystore**: Manages Key Encryption Keys (KEKs) and Data Encryption Keys (DEKs) in a dedicated keystore database
- **LockstoreDatastore**: Manages encrypted CRUD operations for a specific collection using a separate data database

## Key Hierarchy

```
KEK (Key Encryption Key)
  └── DEK (Data Encryption Key) - one per collection
        └── Encrypted Data - entries within a collection
```

## Storage Structure

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

```rust
use lockstore_rs::{LockstoreKeystore, LockstoreDatastore, SecurityLevel, CipherSuite};
use std::sync::Arc;
use std::path::PathBuf;

// Create keystore and generate DEK for a collection
let keystore_path = PathBuf::from("/path/to/keystore.db");
let keystore = Arc::new(LockstoreKeystore::new(Some(keystore_path))?);

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

```rust
use lockstore_rs::{LockstoreKeystore, LockstoreDatastore, SecurityLevel, CipherSuite};
use std::sync::Arc;
use std::path::PathBuf;

// Single keystore for all collections
let keystore = Arc::new(LockstoreKeystore::new(
    Some(PathBuf::from("/path/to/keystore.db"))
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

```rust
use lockstore_rs::{LockstoreKeystore, SecurityLevel, CipherSuite};
use std::path::PathBuf;

let keystore = LockstoreKeystore::new(
    Some(PathBuf::from("/path/to/keystore.db"))
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

### Unencrypted Storage

```rust
use lockstore_rs::{LockstoreKeystore, LockstoreDatastore, SecurityLevel, CipherSuite};
use std::sync::Arc;
use std::path::PathBuf;

let keystore = Arc::new(LockstoreKeystore::new(
    Some(PathBuf::from("/path/to/keystore.db"))
)?);

// Create unencrypted DEK
keystore.create_dek(
    "com.mozilla.cache",
    SecurityLevel::Unencrypted,
    CipherSuite::None
)?;

let datastore = LockstoreDatastore::new(
    Some(PathBuf::from("/path/to/cache.db")),
    "com.mozilla.cache".to_string(),
    Arc::clone(&keystore)
)?;

// Data is stored without encryption
datastore.put("temp_data", b"not sensitive")?;
```

## Security Levels

- **SecurityLevel::Unencrypted**: No encryption (for non-sensitive data)
- **SecurityLevel::LocalKey**: Local encryption using NSS-generated keys

## Cipher Suites

- **CipherSuite::None**: No encryption (must use with SecurityLevel::Unencrypted)
- **CipherSuite::Aes256Gcm**: AES-256-GCM (default, recommended)
- **CipherSuite::ChaCha20Poly1305**: ChaCha20-Poly1305 (alternative AEAD cipher)

## Error Handling

All operations return `Result<T, LockstoreKeystoreError>`:

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

- `LockstoreKeystore` should be wrapped in `Arc` for sharing across threads
- Internal synchronization is handled by kvstore
- Multiple datastores can safely share the same keystore

## Best Practices

1. Use a single keystore for all collections in your application
2. Create separate data databases for each collection
3. Always check if a DEK exists before creating a datastore
4. Use `SecurityLevel::LocalKey` with `CipherSuite::Aes256Gcm` for encrypted storage
5. Delete DEKs when collections are no longer needed
