# Lockstore FFI (C++ Interface)

C++ Foreign Function Interface (FFI) for the Lockstore Rust library.

## Architecture

The FFI layer provides C++ bindings for:

- **Keystore Operations**: Manage KEKs and DEKs
- **Datastore Operations**: CRUD operations for encrypted collections

## Header File

Include the generated header:

```cpp
#include "lockstore_ffi_generated.h"
```

## Enums

### SecurityLevel

```cpp
enum class SecurityLevel : uint8_t {
    Unencrypted = 0,
    LocalKey = 1,
};
```

### CipherSuite

```cpp
enum class CipherSuite : uint8_t {
    None = 0,
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
};
```

## C++ Usage Examples

### Basic Setup and CRUD Operations

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"

// Create keystore
nsAutoCString keystorePath("/path/to/keystore.db");
nsresult rv = lockstore_keystore_new(&keystorePath);
if (NS_FAILED(rv)) {
    // Handle error
    return rv;
}

// Create a DEK for a collection
nsAutoCString collection("com.mozilla.logins");
rv = lockstore_keystore_create_dek(
    &keystorePath,
    &collection,
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
);
if (NS_FAILED(rv)) {
    // Handle error (DEK might already exist)
    return rv;
}

// Create datastore
nsAutoCString dataPath("/path/to/logins.db");
rv = lockstore_datastore_new(&dataPath, &collection, &keystorePath);
if (NS_FAILED(rv)) {
    // Handle error (DEK might not exist)
    return rv;
}

// Store encrypted data
nsAutoCString entryName("login_123");
const uint8_t* data = reinterpret_cast<const uint8_t*>("username:password");
size_t dataLen = strlen("username:password");
rv = lockstore_datastore_put(&dataPath, &collection, &entryName, data, dataLen);
if (NS_FAILED(rv)) {
    // Handle error
    return rv;
}

// Retrieve data
nsTArray<uint8_t> retrievedData;
rv = lockstore_datastore_get(&dataPath, &collection, &entryName, &retrievedData);
if (NS_FAILED(rv)) {
    // Handle error (entry might not exist)
    return rv;
}

// Use retrieved data
printf("Retrieved %zu bytes\n", retrievedData.Length());

// Delete an entry
bool deleted = false;
rv = lockstore_datastore_delete(&dataPath, &collection, &entryName, &deleted);
if (NS_SUCCEEDED(rv) && deleted) {
    printf("Entry deleted successfully\n");
}

// Close datastore
rv = lockstore_datastore_close(&dataPath, &collection);

// Close keystore
rv = lockstore_keystore_close(&keystorePath);
```

### Multiple Collections

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"

nsAutoCString keystorePath("/path/to/keystore.db");

// Initialize keystore
nsresult rv = lockstore_keystore_new(&keystorePath);
if (NS_FAILED(rv)) return rv;

// Create DEKs for multiple collections
nsAutoCString loginsCollection("com.mozilla.logins");
rv = lockstore_keystore_create_dek(
    &keystorePath,
    &loginsCollection,
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
);
if (NS_FAILED(rv)) return rv;

nsAutoCString cookiesCollection("com.mozilla.cookies");
rv = lockstore_keystore_create_dek(
    &keystorePath,
    &cookiesCollection,
    SecurityLevel::LocalKey,
    CipherSuite::ChaCha20Poly1305
);
if (NS_FAILED(rv)) return rv;

// Create separate datastores
nsAutoCString loginsPath("/path/to/logins.db");
rv = lockstore_datastore_new(&loginsPath, &loginsCollection, &keystorePath);
if (NS_FAILED(rv)) return rv;

nsAutoCString cookiesPath("/path/to/cookies.db");
rv = lockstore_datastore_new(&cookiesPath, &cookiesCollection, &keystorePath);
if (NS_FAILED(rv)) return rv;

// Use each datastore independently
const uint8_t* loginData = reinterpret_cast<const uint8_t*>("password");
rv = lockstore_datastore_put(
    &loginsPath,
    &loginsCollection,
    &nsAutoCString("user1"),
    loginData,
    8
);

const uint8_t* cookieData = reinterpret_cast<const uint8_t*>("session=abc");
rv = lockstore_datastore_put(
    &cookiesPath,
    &cookiesCollection,
    &nsAutoCString("session"),
    cookieData,
    11
);

// List all collections in keystore
nsTArray<nsCString> collections;
rv = lockstore_keystore_list_collections(&keystorePath, &collections);
if (NS_SUCCEEDED(rv)) {
    for (const auto& coll : collections) {
        printf("Collection: %s\n", coll.get());
    }
}
```

### Key Management

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"

nsAutoCString keystorePath("/path/to/keystore.db");
nsresult rv = lockstore_keystore_new(&keystorePath);
if (NS_FAILED(rv)) return rv;

// Create DEK
nsAutoCString collection("com.mozilla.passwords");
rv = lockstore_keystore_create_dek(
    &keystorePath,
    &collection,
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
);

if (rv == NS_ERROR_FILE_ALREADY_EXISTS) {
    printf("DEK already exists for this collection\n");
    return rv;
}

// List all collections with DEKs
nsTArray<nsCString> collections;
rv = lockstore_keystore_list_collections(&keystorePath, &collections);
if (NS_SUCCEEDED(rv)) {
    printf("Found %zu collections:\n", collections.Length());
    for (const auto& coll : collections) {
        printf("  - %s\n", coll.get());
    }
}

// Delete a DEK
bool deleted = false;
rv = lockstore_keystore_delete_dek(&keystorePath, &collection, &deleted);
if (NS_SUCCEEDED(rv)) {
    if (deleted) {
        printf("DEK deleted successfully\n");
    } else {
        printf("DEK not found\n");
    }
}

// Close keystore
rv = lockstore_keystore_close(&keystorePath);
```

### List Entries in a Collection

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"

nsAutoCString dataPath("/path/to/logins.db");
nsAutoCString collection("com.mozilla.logins");
nsAutoCString keystorePath("/path/to/keystore.db");

// Ensure keystore and datastore are initialized
nsresult rv = lockstore_keystore_new(&keystorePath);
if (NS_FAILED(rv)) return rv;

rv = lockstore_datastore_new(&dataPath, &collection, &keystorePath);
if (NS_FAILED(rv)) return rv;

// List all entries
nsTArray<nsCString> entries;
rv = lockstore_datastore_list(&dataPath, &collection, &entries);
if (NS_SUCCEEDED(rv)) {
    printf("Found %zu entries:\n", entries.Length());
    for (const auto& entry : entries) {
        printf("  - %s\n", entry.get());
    }
}

// Retrieve each entry
for (const auto& entryName : entries) {
    nsTArray<uint8_t> data;
    rv = lockstore_datastore_get(&dataPath, &collection, &entryName, &data);
    if (NS_SUCCEEDED(rv)) {
        printf("Entry '%s': %zu bytes\n", entryName.get(), data.Length());
    }
}
```

### Error Handling

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"

nsAutoCString keystorePath("/path/to/keystore.db");
nsAutoCString collection("com.mozilla.test");

// Try to create a duplicate DEK
nsresult rv = lockstore_keystore_create_dek(
    &keystorePath,
    &collection,
    SecurityLevel::LocalKey,
    CipherSuite::Aes256Gcm
);

if (rv == NS_ERROR_FILE_ALREADY_EXISTS) {
    printf("DEK already exists\n");
} else if (NS_FAILED(rv)) {
    printf("Failed to create DEK: 0x%x\n", static_cast<uint32_t>(rv));
}

// Try to get non-existent entry
nsAutoCString dataPath("/path/to/test.db");
nsAutoCString entryName("nonexistent");
nsTArray<uint8_t> data;

rv = lockstore_datastore_get(&dataPath, &collection, &entryName, &data);
if (rv == NS_ERROR_FILE_NOT_FOUND) {
    printf("Entry not found\n");
} else if (NS_FAILED(rv)) {
    printf("Failed to get entry: 0x%x\n", static_cast<uint32_t>(rv));
}
```

### Unencrypted Storage

```cpp
#include "lockstore_ffi_generated.h"
#include "nsString.h"

nsAutoCString keystorePath("/path/to/keystore.db");
nsAutoCString collection("com.mozilla.cache");

// Initialize keystore
nsresult rv = lockstore_keystore_new(&keystorePath);
if (NS_FAILED(rv)) return rv;

// Create unencrypted DEK
rv = lockstore_keystore_create_dek(
    &keystorePath,
    &collection,
    SecurityLevel::Unencrypted,
    CipherSuite::None
);
if (NS_FAILED(rv)) return rv;

// Create datastore
nsAutoCString dataPath("/path/to/cache.db");
rv = lockstore_datastore_new(&dataPath, &collection, &keystorePath);
if (NS_FAILED(rv)) return rv;

// Data is stored without encryption
const uint8_t* data = reinterpret_cast<const uint8_t*>("not sensitive");
rv = lockstore_datastore_put(
    &dataPath,
    &collection,
    &nsAutoCString("temp"),
    data,
    13
);
```

## API Reference

### Keystore Functions

#### lockstore_keystore_new
```cpp
nsresult lockstore_keystore_new(const nsACString* keystore_path);
```
Creates or opens a keystore database.

#### lockstore_keystore_create_dek
```cpp
nsresult lockstore_keystore_create_dek(
    const nsACString* keystore_path,
    const nsACString* collection,
    SecurityLevel security_level,
    CipherSuite cipher_suite
);
```
Creates a new DEK for a collection. Returns `NS_ERROR_FILE_ALREADY_EXISTS` if DEK exists.

#### lockstore_keystore_delete_dek
```cpp
nsresult lockstore_keystore_delete_dek(
    const nsACString* keystore_path,
    const nsACString* collection,
    bool* ret_deleted
);
```
Deletes a DEK for a collection. Sets `ret_deleted` to true if deleted.

#### lockstore_keystore_list_collections
```cpp
nsresult lockstore_keystore_list_collections(
    const nsACString* keystore_path,
    nsTArray<nsCString>* ret_collections
);
```
Lists all collections with DEKs in the keystore.

#### lockstore_keystore_close
```cpp
nsresult lockstore_keystore_close(const nsACString* keystore_path);
```
Closes a keystore and removes it from the registry.

### Datastore Functions

#### lockstore_datastore_new
```cpp
nsresult lockstore_datastore_new(
    const nsACString* data_path,
    const nsACString* collection,
    const nsACString* keystore_path
);
```
Creates or opens a datastore for a collection. Requires DEK to exist.

#### lockstore_datastore_put
```cpp
nsresult lockstore_datastore_put(
    const nsACString* data_path,
    const nsACString* collection,
    const nsACString* entry_name,
    const uint8_t* data_ptr,
    size_t data_len
);
```
Stores encrypted data in the datastore.

#### lockstore_datastore_get
```cpp
nsresult lockstore_datastore_get(
    const nsACString* data_path,
    const nsACString* collection,
    const nsACString* entry_name,
    nsTArray<uint8_t>* ret_data
);
```
Retrieves and decrypts data. Returns `NS_ERROR_FILE_NOT_FOUND` if entry doesn't exist.

#### lockstore_datastore_delete
```cpp
nsresult lockstore_datastore_delete(
    const nsACString* data_path,
    const nsACString* collection,
    const nsACString* entry_name,
    bool* ret_deleted
);
```
Deletes an entry. Sets `ret_deleted` to true if deleted.

#### lockstore_datastore_list
```cpp
nsresult lockstore_datastore_list(
    const nsACString* data_path,
    const nsACString* collection,
    nsTArray<nsCString>* ret_entries
);
```
Lists all entry names in the collection.

#### lockstore_datastore_close
```cpp
nsresult lockstore_datastore_close(
    const nsACString* data_path,
    const nsACString* collection
);
```
Closes a datastore and removes it from the registry.

## Error Codes

Common nsresult values returned:

- `NS_OK`: Success
- `NS_ERROR_FAILURE`: General failure
- `NS_ERROR_FILE_ALREADY_EXISTS`: DEK already exists
- `NS_ERROR_FILE_NOT_FOUND`: DEK or entry not found
- `NS_ERROR_INVALID_ARG`: Invalid arguments

## Best Practices

1. Always check `nsresult` return values
2. Create keystore before creating datastores
3. Create DEK before creating datastore for a collection
4. Close datastores before closing keystores
5. Use `SecurityLevel::LocalKey` with `CipherSuite::Aes256Gcm` for encrypted storage
6. Handle `NS_ERROR_FILE_ALREADY_EXISTS` when creating DEKs
7. Handle `NS_ERROR_FILE_NOT_FOUND` when retrieving entries

## Thread Safety

The FFI layer uses internal registries with mutexes for thread safety. Multiple threads can safely call these functions concurrently.
