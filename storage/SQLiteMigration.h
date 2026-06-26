/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef STORAGE_SQLITEMIGRATION_H_
#define STORAGE_SQLITEMIGRATION_H_

#include <cstdint>
#include <functional>

#include "nsStringFwd.h"

class nsIFile;
enum class nsresult : uint32_t;

namespace mozilla::storage {

// Direction of a single-database conversion. The engine is the same for all
// three; only which key each side of the VACUUM INTO receives differs.
enum class MigrationDirection : uint8_t {
  PlaintextToEncrypted,  // source: plaintext       -> dest: new DEK
  EncryptedToPlaintext,  // source: old DEK         -> dest: plaintext
  RotateDek,             // source: old DEK         -> dest: new (different) DEK
};

// On-disk shape of a database file, decided purely by inspecting its header
// (no key required). Encrypted == the obfsvfs signature (8192-byte pages with
// 32 reserved bytes); Plaintext == any other well-formed SQLite header.
enum class OnDiskEncryptionState : uint8_t {
  Missing,    // file does not exist
  NotSqlite,  // exists but is not a SQLite-shaped file (skip it)
  Plaintext,  // a plain SQLite database
  Encrypted,  // an obfsvfs-encrypted database
  Error,      // exists but its header could not be read
};

// Inspect |aDbFile|'s leading bytes and classify it. Pure read; safe on any
// thread. Uses the same 8192/32 obfsvfs signature as obfsvfs's internal
// PeekOnDiskHeader and nsAppRunner's DetectEncryptedDBHeader.
OnDiskEncryptionState PeekDatabaseEncryptionState(nsIFile* aDbFile);

// Convert a single SQLite database file in place: VACUUM INTO a sibling temp
// file, then atomically rename it over the original. A no-op (returns NS_OK)
// when the file is already in the target on-disk state, or is missing / not a
// SQLite database.
//
// |aOldKeyHex| / |aNewKeyHex| are 64-hex (32-byte) DEKs; pass an empty string
// for whichever side has no key (the plaintext side). The caller is
// responsible for keeping |aNewKeyHex| consistent with whatever
// GetEncryptionKey will later return for this database's lockstore collection.
//
// MUST run on a thread where blocking disk IO is acceptable -- never the main
// thread for large databases.
//
// Implementation note: VACUUM INTO opens its destination through an internal
// ATTACH, which honours the `vfs=` and `key=` URI query parameters. That lets
// a single connection read through one VFS while the destination is written
// through the other, which is what makes all three directions a single
// VACUUM INTO statement.
nsresult ConvertDatabaseFile(nsIFile* aDbFile, MigrationDirection aDirection,
                             const nsACString& aOldKeyHex,
                             const nsACString& aNewKeyHex);

// Invoke |aCallback| once for every migratable in-profile SQLite database,
// recursing through the profile tree. Excludes the bootstrap databases
// (lockstore keystore + NSS softoken), the ephemeral storage/private/
// private-browsing subtree, non-".sqlite" files, sidecars, and symlinks.
// |aRelativePath| is the database's '/'-separated path relative to the
// profile -- the same string used as its lockstore collection name. Stops at
// and returns the first failing callback result; an unreadable subdirectory is
// skipped rather than treated as fatal.
nsresult ForEachProfileDatabase(
    nsIFile* aProfileDir,
    const std::function<nsresult(nsIFile* aDbFile,
                                 const nsACString& aRelativePath)>& aCallback);

// Convert every plaintext in-profile database to encrypted. Mints each
// database's DEK via GetEncryptionKey(CreateIfNew) before converting, so the
// on-disk encryption key matches what later opens will resolve. Idempotent and
// resumable: already-encrypted databases are skipped. This is the direction
// wired into startup. Requires NSS initialized and the profile path resolvable;
// callers run it on a worker thread before any storage consumer opens a DB.
nsresult MigrateProfileToEncrypted(nsIFile* aProfileDir);

// Rotate every encrypted in-profile database's DEK: mint a fresh key,
// re-encrypt the database under it, then repoint the lockstore to match. Each
// database is guarded by a sibling ".rekey-pending" journal so an interrupted
// file-swap or keystore-repoint is completed on the next run (this function
// first resolves any journals left by a prior interrupted rotation). Must run
// with no live database connections, so it is routed through the next-startup
// barrier. Requires NSS initialized and the profile path resolvable.
nsresult RotateProfileDeks(nsIFile* aProfileDir);

}  // namespace mozilla::storage

#endif  // STORAGE_SQLITEMIGRATION_H_
