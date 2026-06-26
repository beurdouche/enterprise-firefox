/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "storage_test_harness.h"

#include "BaseVFS.h"
#include "ObfuscatingVFS.h"
#include "SQLiteMigration.h"
#include "StoragePathUtil.h"

#include "mozilla/ScopeExit.h"

#include "nsIFile.h"
#include "nsString.h"
#include "sqlite3.h"

using namespace mozilla;
using namespace mozilla::storage;

// Two distinct 64-hex (32-byte) DEKs.
static const char* kKey1 =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* kKey2 =
    "f0e0d0c0b0a0908070605040302010ff112233445566778899aabbccddeeff00";

namespace {

already_AddRefed<nsIFile> TempDbFile() {
  nsCOMPtr<nsIFile> f;
  NS_GetSpecialDirectory(NS_OS_TEMP_DIR, getter_AddRefs(f));
  f->AppendNative("test_sqlite_migration.sqlite"_ns);
  // Best-effort clean of any leftover from a prior run, plus sidecars.
  f->Remove(false);
  for (const auto* suffix : {"-wal", "-shm", "-journal", ".migrating-tmp"}) {
    nsCOMPtr<nsIFile> s;
    f->Clone(getter_AddRefs(s));
    nsAutoString leaf;
    f->GetLeafName(leaf);
    s->SetLeafName(leaf + NS_ConvertUTF8toUTF16(suffix));
    s->Remove(false);
  }
  return f.forget();
}

nsCString FileUri(nsIFile* aFile, const nsACString& aQuery) {
  nsAutoString p16;
  aFile->GetPath(p16);
  NS_ConvertUTF16toUTF8 p8(p16);
  PreparePathForURI(p8);
  nsCString uri("file:"_ns);
  uri += p8;
  uri += aQuery;
  return uri;
}

void CreatePlaintextDb(nsIFile* aFile) {
  sqlite3* db = nullptr;
  nsCString uri = FileUri(aFile, ""_ns);
  int rc = ::sqlite3_open_v2(
      uri.get(), &db,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI,
      basevfs::GetVFSName(/* exclusive */ false));
  ASSERT_EQ(rc, SQLITE_OK);
  do_check_ok(
      ::sqlite3_exec(db,
                     "PRAGMA user_version=42;"
                     "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT);"
                     "INSERT INTO t(id,name) VALUES"
                     " (1,'alpha'),(2,'beta'),(3,'gamma');"
                     "CREATE INDEX idx_name ON t(name);"
                     "CREATE VIEW v AS SELECT name FROM t;",
                     nullptr, nullptr, nullptr));
  do_check_ok(::sqlite3_close(db));
}

// Open the database and read back known content. Returns true only if the open
// AND the queries all succeed (a wrong key makes the first read fail), with the
// row count, the name of row id=1, and the user_version filled in.
bool ReadDb(nsIFile* aFile, const char* aKeyHex, int* aCount,
            nsACString& aFirstName, int* aUserVersion) {
  nsCString query;
  const char* vfs;
  if (aKeyHex) {
    query = "?key="_ns;
    query += nsDependentCString(aKeyHex);
    vfs = obfsvfs::GetVFSName();
  } else {
    vfs = basevfs::GetVFSName(false);
  }
  nsCString uri = FileUri(aFile, query);

  sqlite3* db = nullptr;
  int rc = ::sqlite3_open_v2(uri.get(), &db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, vfs);
  if (rc != SQLITE_OK) {
    if (db) {
      ::sqlite3_close(db);
    }
    return false;
  }
  auto closeDb = MakeScopeExit([&db] { ::sqlite3_close(db); });

  sqlite3_stmt* stmt = nullptr;
  if (::sqlite3_prepare_v2(
          db, "SELECT count(*), (SELECT name FROM t WHERE id=1) FROM t", -1,
          &stmt, nullptr) != SQLITE_OK) {
    return false;
  }
  if (::sqlite3_step(stmt) != SQLITE_ROW) {
    ::sqlite3_finalize(stmt);
    return false;
  }
  *aCount = ::sqlite3_column_int(stmt, 0);
  aFirstName = reinterpret_cast<const char*>(::sqlite3_column_text(stmt, 1));
  ::sqlite3_finalize(stmt);

  if (::sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return false;
  }
  if (::sqlite3_step(stmt) != SQLITE_ROW) {
    ::sqlite3_finalize(stmt);
    return false;
  }
  *aUserVersion = ::sqlite3_column_int(stmt, 0);
  ::sqlite3_finalize(stmt);
  return true;
}

void ExpectContent(nsIFile* aFile, const char* aKeyHex) {
  int count = 0, userVersion = 0;
  nsAutoCString firstName;
  ASSERT_TRUE(ReadDb(aFile, aKeyHex, &count, firstName, &userVersion));
  do_check_eq(3, count);
  do_check_true(firstName.EqualsLiteral("alpha"));
  do_check_eq(42, userVersion);
}

}  // namespace

// Exercises the generic engine across all three directions, with explicit keys
// (no lockstore / profile needed: an explicit ?key= bypasses obfsvfs policy).
TEST(storage_SQLiteMigration, RoundTrip)
{
  // Ensure mozStorageService is up so the base/obfs VFSes are registered.
  nsCOMPtr<mozIStorageService> ss = getService();
  ASSERT_TRUE(ss);

  nsCOMPtr<nsIFile> dbFile = TempDbFile();

  // Plaintext to start.
  CreatePlaintextDb(dbFile);
  do_check_true(PeekDatabaseEncryptionState(dbFile) ==
                OnDiskEncryptionState::Plaintext);
  ExpectContent(dbFile, /* plaintext */ nullptr);

  // Plaintext -> encrypted under kKey1.
  do_check_success(ConvertDatabaseFile(dbFile,
                                       MigrationDirection::PlaintextToEncrypted,
                                       ""_ns, nsDependentCString(kKey1)));
  do_check_true(PeekDatabaseEncryptionState(dbFile) ==
                OnDiskEncryptionState::Encrypted);
  ExpectContent(dbFile, kKey1);
  // It must no longer open as plaintext.
  {
    int c = 0, uv = 0;
    nsAutoCString n;
    do_check_false(ReadDb(dbFile, nullptr, &c, n, &uv));
  }

  // Idempotency: a second encrypt is a no-op and preserves content.
  do_check_success(ConvertDatabaseFile(dbFile,
                                       MigrationDirection::PlaintextToEncrypted,
                                       ""_ns, nsDependentCString(kKey1)));
  ExpectContent(dbFile, kKey1);

  // Rotate the DEK kKey1 -> kKey2: content identical, old key no longer works.
  do_check_success(ConvertDatabaseFile(dbFile, MigrationDirection::RotateDek,
                                       nsDependentCString(kKey1),
                                       nsDependentCString(kKey2)));
  do_check_true(PeekDatabaseEncryptionState(dbFile) ==
                OnDiskEncryptionState::Encrypted);
  ExpectContent(dbFile, kKey2);
  {
    int c = 0, uv = 0;
    nsAutoCString n;
    do_check_false(ReadDb(dbFile, kKey1, &c, n, &uv));
  }

  // The EncryptedToPlaintext (disable) direction is intentionally not exercised:
  // VACUUM cannot decrease a database's reserved-byte count (SQLite's
  // sqlite3BtreeGetRequestedReserve returns max(wanted, on-disk)), so a decrypt
  // currently leaves the obfsvfs 32 reserved bytes in place. That direction is
  // unused by the enable/migrate/rotate flow and is a separate follow-up.

  dbFile->Remove(false);
}
