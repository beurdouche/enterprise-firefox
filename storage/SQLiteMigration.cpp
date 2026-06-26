/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "SQLiteMigration.h"

#include <cstring>

#include "BaseVFS.h"
#include "ObfuscatingVFS.h"
#include "SQLiteEncryption.h"
#include "StoragePathUtil.h"

#include "mozilla/Logging.h"
#include "mozilla/ScopeExit.h"
#include "nsCOMPtr.h"
#include "nsIDirectoryEnumerator.h"
#include "nsIFile.h"
#include "nsString.h"
#include "prio.h"
#include "sqlite3.h"

namespace mozilla::storage {

// Reserved bytes per page in the obfsvfs on-disk format. Together with
// obfsvfs::kObfsPageSize this is the signature that distinguishes an encrypted
// database from a plaintext one. Must match obfsvfs's on-disk layout; kept in
// sync with PeekOnDiskHeader in ObfuscatingVFS.cpp.
static constexpr uint32_t kObfsReservedBytes = 32;

// SQLite's "SQLite format 3\0" file magic (first 16 bytes of every database).
static const unsigned char kSQLiteMagic[16] = {'S', 'Q', 'L', 'i', 't', 'e',
                                               ' ', 'f', 'o', 'r', 'm', 'a',
                                               't', ' ', '3', '\0'};

OnDiskEncryptionState PeekDatabaseEncryptionState(nsIFile* aDbFile) {
  bool exists = false;
  if (NS_FAILED(aDbFile->Exists(&exists))) {
    return OnDiskEncryptionState::Error;
  }
  if (!exists) {
    return OnDiskEncryptionState::Missing;
  }

  PRFileDesc* fd = nullptr;
  if (NS_FAILED(aDbFile->OpenNSPRFileDesc(PR_RDONLY, 0, &fd)) || !fd) {
    return OnDiskEncryptionState::Error;
  }
  auto closeFd = MakeScopeExit([fd] { PR_Close(fd); });

  // The page size (offset 16) and reserved-byte count (offset 20) both live in
  // the first 24 bytes, after the 16-byte magic.
  unsigned char hdr[24] = {0};
  int32_t n = PR_Read(fd, hdr, sizeof(hdr));
  if (n != static_cast<int32_t>(sizeof(hdr))) {
    return OnDiskEncryptionState::NotSqlite;
  }
  if (::memcmp(hdr, kSQLiteMagic, sizeof(kSQLiteMagic)) != 0) {
    return OnDiskEncryptionState::NotSqlite;
  }

  uint32_t pageSize = (static_cast<uint32_t>(hdr[16]) << 8) | hdr[17];
  if (pageSize == 1) {
    pageSize = 65536;  // SQLite encodes a 65536-byte page size as 1.
  }
  uint32_t reservedBytes = hdr[20];
  if (pageSize == static_cast<uint32_t>(obfsvfs::kObfsPageSize) &&
      reservedBytes == kObfsReservedBytes) {
    return OnDiskEncryptionState::Encrypted;
  }
  return OnDiskEncryptionState::Plaintext;
}

// Remove the rollback-journal / WAL sidecar files left next to |aDbFile|. A
// clean SQLite close usually deletes these already; this mops up any that an
// unclean prior shutdown left behind so they cannot shadow the migrated file.
static void RemoveSidecars(nsIFile* aDbFile) {
  nsAutoString leaf;
  if (NS_FAILED(aDbFile->GetLeafName(leaf))) {
    return;
  }
  for (const auto* suffix : {u"-wal", u"-shm", u"-journal"}) {
    nsCOMPtr<nsIFile> sidecar;
    if (NS_FAILED(aDbFile->Clone(getter_AddRefs(sidecar)))) {
      continue;
    }
    if (NS_FAILED(sidecar->SetLeafName(leaf + nsDependentString(suffix)))) {
      continue;
    }
    bool exists = false;
    if (NS_SUCCEEDED(sidecar->Exists(&exists)) && exists) {
      sidecar->Remove(false);
    }
  }
}

// Run `VACUUM INTO aDestUri` reading from the database at aSrcUri opened
// through aSrcVfs. VACUUM INTO faithfully reproduces every schema object
// (tables, indexes, triggers, views, FTS virtual tables) and re-paginates in
// one step.
//
// The VACUUM INTO target inherits its page size and reserved-bytes from the
// source connection, so two optional knobs let the caller steer them without
// touching the source file on disk:
//   * aSetSrcPageSize > 0 issues `PRAGMA page_size` on the source so the target
//     adopts that page size (used to re-paginate to the obfuscated page size).
//   * aSetSrcReserve >= 0 sets the source connection's *requested*
//   reserved-byte
//     count via SQLITE_FCNTL_RESERVE_BYTES so the target adopts it. This
//     updates only the connection's wanted value; it does not rewrite the
//     source (VACUUM INTO only reads it), so the source file's own header stays
//     unchanged.
static nsresult RunVacuumInto(const nsACString& aSrcUri, const char* aSrcVfs,
                              const nsACString& aDestUri, int aSetSrcPageSize,
                              int aSetSrcReserve, mozilla::LogModule* aLog) {
  // READWRITE (not READONLY) so SQLite can recover an unclean WAL/journal
  // before we read; VACUUM INTO itself only reads the source.
  sqlite3* srcDb = nullptr;
  int srv = ::sqlite3_open_v2(PromiseFlatCString(aSrcUri).get(), &srcDb,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI, aSrcVfs);
  if (srv != SQLITE_OK) {
    MOZ_LOG(aLog, mozilla::LogLevel::Error,
            ("RunVacuumInto: opening source failed (%d) for %s", srv,
             PromiseFlatCString(aSrcUri).get()));
    if (srcDb) {
      ::sqlite3_close(srcDb);
    }
    return NS_ERROR_FAILURE;
  }
  auto closeSrc = MakeScopeExit([&srcDb] {
    if (srcDb) {
      ::sqlite3_close(srcDb);
    }
  });

  if (aSetSrcPageSize > 0) {
    nsAutoCString pragma("PRAGMA page_size="_ns);
    pragma.AppendInt(aSetSrcPageSize);
    srv = ::sqlite3_exec(srcDb, pragma.get(), nullptr, nullptr, nullptr);
    if (srv != SQLITE_OK) {
      MOZ_LOG(aLog, mozilla::LogLevel::Error,
              ("RunVacuumInto: PRAGMA page_size=%d failed (%d)",
               aSetSrcPageSize, srv));
      return NS_ERROR_FAILURE;
    }
  }
  if (aSetSrcReserve >= 0) {
    int n = aSetSrcReserve;
    ::sqlite3_file_control(srcDb, "main", SQLITE_FCNTL_RESERVE_BYTES, &n);
  }

  char* sql =
      ::sqlite3_mprintf("VACUUM INTO %Q", PromiseFlatCString(aDestUri).get());
  if (!sql) {
    return NS_ERROR_OUT_OF_MEMORY;
  }
  char* errMsg = nullptr;
  srv = ::sqlite3_exec(srcDb, sql, nullptr, nullptr, &errMsg);
  ::sqlite3_free(sql);
  if (srv != SQLITE_OK) {
    MOZ_LOG(aLog, mozilla::LogLevel::Error,
            ("RunVacuumInto: VACUUM INTO failed (%d: %s) into %s", srv,
             errMsg ? errMsg : "?", PromiseFlatCString(aDestUri).get()));
    ::sqlite3_free(errMsg);
    return NS_ERROR_FAILURE;
  }
  ::sqlite3_free(errMsg);

  srv = ::sqlite3_close(srcDb);
  srcDb = nullptr;
  closeSrc.release();
  if (srv != SQLITE_OK) {
    MOZ_LOG(aLog, mozilla::LogLevel::Error,
            ("RunVacuumInto: closing source failed (%d)", srv));
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

nsresult ConvertDatabaseFile(nsIFile* aDbFile, MigrationDirection aDirection,
                             const nsACString& aOldKeyHex,
                             const nsACString& aNewKeyHex) {
  mozilla::LogModule* log = GetSQLiteEncryptionLog();

  const OnDiskEncryptionState state = PeekDatabaseEncryptionState(aDbFile);
  switch (state) {
    case OnDiskEncryptionState::Missing:
    case OnDiskEncryptionState::NotSqlite:
      return NS_OK;  // Nothing to convert.
    case OnDiskEncryptionState::Error:
      return NS_ERROR_FILE_ACCESS_DENIED;
    case OnDiskEncryptionState::Plaintext:
    case OnDiskEncryptionState::Encrypted:
      break;
  }

  // The source side carries a key for every direction except a fresh encrypt.
  const bool srcEncrypted =
      (aDirection != MigrationDirection::PlaintextToEncrypted);
  const bool destEncrypted =
      (aDirection != MigrationDirection::EncryptedToPlaintext);

  // Idempotency / resumability: skip if the file is already in the target
  // shape. RotateDek always re-encrypts (its source and dest are both
  // Encrypted), so a header peek cannot detect a completed rotation -- that is
  // the .rekey-pending journal's job, handled by the rotation driver.
  if (aDirection == MigrationDirection::PlaintextToEncrypted &&
      state == OnDiskEncryptionState::Encrypted) {
    return NS_OK;
  }
  if (aDirection == MigrationDirection::EncryptedToPlaintext &&
      state == OnDiskEncryptionState::Plaintext) {
    return NS_OK;
  }
  // The source must actually be in the shape this direction expects to read.
  if (srcEncrypted && state != OnDiskEncryptionState::Encrypted) {
    MOZ_LOG(log, mozilla::LogLevel::Warning,
            ("ConvertDatabaseFile: expected an encrypted source; skipping"));
    return NS_OK;
  }
  if (!srcEncrypted && state != OnDiskEncryptionState::Plaintext) {
    return NS_OK;
  }

  nsAutoString srcPath16;
  nsresult rv = aDbFile->GetPath(srcPath16);
  NS_ENSURE_SUCCESS(rv, rv);
  NS_ConvertUTF16toUTF8 srcPathUtf8(srcPath16);

  nsAutoString origLeaf;
  rv = aDbFile->GetLeafName(origLeaf);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> parentDir;
  rv = aDbFile->GetParent(getter_AddRefs(parentDir));
  NS_ENSURE_SUCCESS(rv, rv);

  // The temp file is a sibling of the source so the final rename stays within
  // one directory (and thus one filesystem), keeping it atomic.
  nsCOMPtr<nsIFile> destFile;
  rv = aDbFile->Clone(getter_AddRefs(destFile));
  NS_ENSURE_SUCCESS(rv, rv);
  rv = destFile->SetLeafName(origLeaf + u".migrating-tmp"_ns);
  NS_ENSURE_SUCCESS(rv, rv);

  // Clear any stale temp file from a previously interrupted run.
  bool destExists = false;
  destFile->Exists(&destExists);
  if (destExists) {
    rv = destFile->Remove(false);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  nsAutoString destPath16;
  rv = destFile->GetPath(destPath16);
  NS_ENSURE_SUCCESS(rv, rv);
  NS_ConvertUTF16toUTF8 destPathUtf8(destPath16);

  // Source: plaintext reads through the base VFS; an encrypted source reads
  // through obfsvfs with its DEK supplied via the URI key= parameter.
  nsAutoCString srcUriPath(srcPathUtf8);
  PreparePathForURI(srcUriPath);
  nsAutoCString srcUri("file:"_ns);
  srcUri += srcUriPath;
  const char* srcVfs;
  if (srcEncrypted) {
    srcUri += "?key="_ns;
    srcUri += aOldKeyHex;
    srcVfs = obfsvfs::GetVFSName();
  } else {
    srcVfs = basevfs::GetVFSName(/* exclusive */ false);
  }

  // Destination: the vfs= URI parameter overrides the connection's VFS for the
  // VACUUM INTO target (it is opened via an internal ATTACH that parses the
  // URI), so we can write the opposite shape from the source. key= supplies
  // the destination DEK when the target is encrypted.
  nsAutoCString destUriPath(destPathUtf8);
  PreparePathForURI(destUriPath);
  nsAutoCString destUri("file:"_ns);
  destUri += destUriPath;
  destUri += "?vfs="_ns;
  destUri += nsDependentCString(
      destEncrypted ? obfsvfs::GetVFSName()
                    : basevfs::GetVFSName(/* exclusive */ false));
  if (destEncrypted) {
    destUri += "&key="_ns;
    destUri += aNewKeyHex;
  }

  // On any failure before the swap, discard the partial destination copy.
  auto removeDest = MakeScopeExit([&destFile] { destFile->Remove(false); });

  // VACUUM INTO inherits the destination's page size and reserved-bytes from
  // the source connection, while obfsvfs fixes the encrypted format at
  // obfsvfs::kObfsPageSize / kObfsReservedBytes. A plaintext source is
  // typically the 32768-byte SQLITE_DEFAULT_PAGE_SIZE with 0 reserved bytes, so
  // it cannot VACUUM INTO an encrypted destination in one step: SQLite refuses
  // to change the destination's already-fixed page size and reports the failure
  // as SQLITE_NOMEM. In that case convert in two hops -- re-paginate the
  // plaintext source to a plaintext temp at the obfuscated page size, then
  // encrypt that temp into the destination (page size and reserved-bytes now
  // agree). The rotate (encrypted->encrypted) and decrypt directions already
  // match obfsvfs's page size and convert in a single hop.
  if (destEncrypted && !srcEncrypted) {
    // Intermediate plaintext copy, re-paginated to the obfuscated page size.
    // Its on-disk reserved-bytes stays 0, so PeekDatabaseEncryptionState still
    // reads it as plaintext and never mistakes a crash-orphaned temp for
    // ciphertext; the encrypt hop sets only the *requested* reserved-bytes on
    // its connection so the destination adopts kObfsReservedBytes.
    nsCOMPtr<nsIFile> midFile;
    rv = aDbFile->Clone(getter_AddRefs(midFile));
    NS_ENSURE_SUCCESS(rv, rv);
    rv = midFile->SetLeafName(origLeaf + u".migrating-mid"_ns);
    NS_ENSURE_SUCCESS(rv, rv);
    bool midExists = false;
    midFile->Exists(&midExists);
    if (midExists) {
      rv = midFile->Remove(false);
      NS_ENSURE_SUCCESS(rv, rv);
    }
    // The intermediate is purely transient: drop it on success and failure.
    auto removeMid = MakeScopeExit([&midFile] { midFile->Remove(false); });

    nsAutoString midPath16;
    rv = midFile->GetPath(midPath16);
    NS_ENSURE_SUCCESS(rv, rv);
    NS_ConvertUTF16toUTF8 midPathUtf8(midPath16);
    nsAutoCString midUriPath(midPathUtf8);
    PreparePathForURI(midUriPath);
    nsAutoCString midUri("file:"_ns);
    midUri += midUriPath;
    midUri += "?vfs="_ns;
    midUri += nsDependentCString(basevfs::GetVFSName(/* exclusive */ false));

    // Hop 1: plaintext source -> plaintext temp at the obfuscated page size.
    rv = RunVacuumInto(srcUri, srcVfs, midUri,
                       /* setSrcPageSize */ obfsvfs::kObfsPageSize,
                       /* setSrcReserve */ -1, log);
    NS_ENSURE_SUCCESS(rv, rv);

    // Hop 2: re-paginated plaintext temp -> encrypted destination.
    rv = RunVacuumInto(midUri, basevfs::GetVFSName(/* exclusive */ false),
                       destUri, /* setSrcPageSize */ 0,
                       /* setSrcReserve */ static_cast<int>(kObfsReservedBytes),
                       log);
    NS_ENSURE_SUCCESS(rv, rv);
  } else {
    rv = RunVacuumInto(srcUri, srcVfs, destUri, /* setSrcPageSize */ 0,
                       /* setSrcReserve */ -1, log);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  // Atomic swap. The original is removed only now -- after a fully-written
  // destination -- so a crash here leaves the complete temp file to be renamed
  // into place on resume (the original is gone but the data is not lost).
  removeDest.release();
  RemoveSidecars(aDbFile);
  rv = aDbFile->Remove(false);
  NS_ENSURE_SUCCESS(rv, rv);
  rv = destFile->MoveTo(parentDir, origLeaf);
  NS_ENSURE_SUCCESS(rv, rv);

  return NS_OK;
}

static nsresult ForEachProfileDatabaseImpl(
    nsIFile* aDir, nsIFile* aProfileDir,
    const std::function<nsresult(nsIFile*, const nsACString&)>& aCallback) {
  nsCOMPtr<nsIDirectoryEnumerator> entries;
  if (NS_FAILED(aDir->GetDirectoryEntries(getter_AddRefs(entries)))) {
    // An unreadable directory is skipped, not fatal: a single locked or
    // permission-denied subdir must not abort a whole-profile migration.
    return NS_OK;
  }

  bool more = false;
  while (NS_SUCCEEDED(entries->HasMoreElements(&more)) && more) {
    nsCOMPtr<nsISupports> item;
    if (NS_FAILED(entries->GetNext(getter_AddRefs(item)))) {
      break;
    }
    nsCOMPtr<nsIFile> entry = do_QueryInterface(item);
    if (!entry) {
      continue;
    }

    // We do not expect symlinks inside a profile; never follow one.
    bool isLink = false;
    if (NS_SUCCEEDED(entry->IsSymlink(&isLink)) && isLink) {
      continue;
    }

    bool isDir = false;
    if (NS_FAILED(entry->IsDirectory(&isDir))) {
      continue;
    }

    if (isDir) {
      // Skip the ephemeral private-browsing subtree wholesale: its IndexedDB /
      // Cache databases are keyed by an in-memory CipherKey, not the profile
      // DEK, and must never be touched. (The per-file relative-path check below
      // is the backstop.)
      nsAutoCString rel;
      if (NS_SUCCEEDED(entry->GetRelativePath(aProfileDir, rel)) &&
          rel.EqualsLiteral("storage/private")) {
        continue;
      }
      nsresult rv = ForEachProfileDatabaseImpl(entry, aProfileDir, aCallback);
      NS_ENSURE_SUCCESS(rv, rv);
      continue;
    }

    nsAutoString leaf;
    if (NS_FAILED(entry->GetLeafName(leaf)) ||
        !StringEndsWith(leaf, u".sqlite"_ns)) {
      continue;
    }

    nsAutoCString rel;
    if (NS_FAILED(entry->GetRelativePath(aProfileDir, rel))) {
      continue;
    }
    // Bootstrap databases (lockstore keystore + NSS softoken) are never
    // encrypted; the private-browsing subtree is ephemeral.
    if (IsBootstrapDatabasePath(rel) ||
        StringBeginsWith(rel, "storage/private/"_ns)) {
      continue;
    }

    nsresult rv = aCallback(entry, rel);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  return NS_OK;
}

nsresult ForEachProfileDatabase(
    nsIFile* aProfileDir,
    const std::function<nsresult(nsIFile*, const nsACString&)>& aCallback) {
  return ForEachProfileDatabaseImpl(aProfileDir, aProfileDir, aCallback);
}

nsresult MigrateProfileToEncrypted(nsIFile* aProfileDir) {
  return ForEachProfileDatabase(
      aProfileDir, [](nsIFile* aDbFile, const nsACString& aRel) -> nsresult {
        if (PeekDatabaseEncryptionState(aDbFile) !=
            OnDiskEncryptionState::Plaintext) {
          return NS_OK;  // Already encrypted (or not a DB): nothing to do.
        }
        nsAutoString path16;
        nsresult rv = aDbFile->GetPath(path16);
        NS_ENSURE_SUCCESS(rv, rv);
        NS_ConvertUTF16toUTF8 pathUtf8(path16);

        // Mint (or load, race-safe) this database's DEK first, so the key we
        // encrypt with is exactly the one later opens will resolve from the
        // lockstore for this collection.
        nsAutoCString keyHex;
        rv = GetEncryptionKey(pathUtf8, OpenIntent::CreateIfNew, keyHex);
        NS_ENSURE_SUCCESS(rv, rv);

        return ConvertDatabaseFile(
            aDbFile, MigrationDirection::PlaintextToEncrypted, ""_ns, keyHex);
      });
}

// ---- DEK rotation -------------------------------------------------------

static nsresult RekeyJournalFile(nsIFile* aDbFile, nsIFile** aOut) {
  nsAutoString leaf;
  nsresult rv = aDbFile->GetLeafName(leaf);
  NS_ENSURE_SUCCESS(rv, rv);
  nsCOMPtr<nsIFile> j;
  rv = aDbFile->Clone(getter_AddRefs(j));
  NS_ENSURE_SUCCESS(rv, rv);
  rv = j->SetLeafName(leaf + u".rekey-pending"_ns);
  NS_ENSURE_SUCCESS(rv, rv);
  j.forget(aOut);
  return NS_OK;
}

// Persist the new DEK (hex) next to the database and fsync it, so an
// interrupted file-swap / keystore-repoint can be finished on the next run.
static nsresult WriteRekeyJournal(nsIFile* aDbFile, const nsACString& aHex) {
  nsCOMPtr<nsIFile> j;
  nsresult rv = RekeyJournalFile(aDbFile, getter_AddRefs(j));
  NS_ENSURE_SUCCESS(rv, rv);
  PRFileDesc* fd = nullptr;
  rv = j->OpenNSPRFileDesc(PR_WRONLY | PR_CREATE_FILE | PR_TRUNCATE, 0600, &fd);
  NS_ENSURE_SUCCESS(rv, rv);
  int32_t n = PR_Write(fd, aHex.BeginReading(), aHex.Length());
  PR_Sync(fd);
  PR_Close(fd);
  return n == static_cast<int32_t>(aHex.Length()) ? NS_OK : NS_ERROR_FAILURE;
}

static nsresult ReadRekeyJournal(nsIFile* aDbFile, nsACString& aOutHex) {
  nsCOMPtr<nsIFile> j;
  nsresult rv = RekeyJournalFile(aDbFile, getter_AddRefs(j));
  NS_ENSURE_SUCCESS(rv, rv);
  PRFileDesc* fd = nullptr;
  rv = j->OpenNSPRFileDesc(PR_RDONLY, 0, &fd);
  NS_ENSURE_SUCCESS(rv, rv);
  char buf[128];
  int32_t n = PR_Read(fd, buf, sizeof(buf));
  PR_Close(fd);
  if (n <= 0) {
    return NS_ERROR_FAILURE;
  }
  aOutHex.Assign(buf, n);
  aOutHex.Trim(" \t\r\n");
  return NS_OK;
}

static void RemoveRekeyJournal(nsIFile* aDbFile) {
  nsCOMPtr<nsIFile> j;
  if (NS_SUCCEEDED(RekeyJournalFile(aDbFile, getter_AddRefs(j)))) {
    j->Remove(false);
  }
}

// True if the database opens and reads under |aKeyHex| (used to tell which key
// an interrupted rotation left the file under).
static bool ProbeOpensWithKey(nsIFile* aDbFile, const nsACString& aKeyHex) {
  nsAutoString p16;
  if (NS_FAILED(aDbFile->GetPath(p16))) {
    return false;
  }
  NS_ConvertUTF16toUTF8 p8(p16);
  PreparePathForURI(p8);
  nsAutoCString uri("file:"_ns);
  uri += p8;
  uri += "?key="_ns;
  uri += aKeyHex;

  sqlite3* db = nullptr;
  if (::sqlite3_open_v2(uri.get(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                        obfsvfs::GetVFSName()) != SQLITE_OK) {
    if (db) {
      ::sqlite3_close(db);
    }
    return false;
  }
  auto closeDb = MakeScopeExit([&db] { ::sqlite3_close(db); });
  sqlite3_stmt* stmt = nullptr;
  if (::sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master", -1, &stmt,
                           nullptr) != SQLITE_OK) {
    return false;
  }
  int rc = ::sqlite3_step(stmt);
  ::sqlite3_finalize(stmt);
  return rc == SQLITE_ROW;
}

// Finish any rotation a prior run left mid-flight (journal present). If the
// file already reads under the journalled new key, the keystore may still hold
// the old key -- repoint it. Otherwise the file is still under the old key and
// the keystore already matches it; just drop the journal.
static nsresult ResolvePendingDekRotations(nsIFile* aProfileDir) {
  return ForEachProfileDatabase(
      aProfileDir, [](nsIFile* aDbFile, const nsACString& aRel) -> nsresult {
        nsCOMPtr<nsIFile> j;
        if (NS_FAILED(RekeyJournalFile(aDbFile, getter_AddRefs(j)))) {
          return NS_OK;
        }
        bool exists = false;
        if (NS_FAILED(j->Exists(&exists)) || !exists) {
          return NS_OK;
        }
        nsAutoCString newHex;
        if (NS_FAILED(ReadRekeyJournal(aDbFile, newHex)) ||
            newHex.Length() != 64) {
          RemoveRekeyJournal(aDbFile);
          return NS_OK;
        }
        if (ProbeOpensWithKey(aDbFile, newHex)) {
          nsAutoString path16;
          nsresult rv = aDbFile->GetPath(path16);
          NS_ENSURE_SUCCESS(rv, rv);
          NS_ConvertUTF16toUTF8 pathUtf8(path16);
          rv = ReplaceDatabaseDek(pathUtf8, newHex);
          NS_ENSURE_SUCCESS(rv, rv);
        }
        RemoveRekeyJournal(aDbFile);
        return NS_OK;
      });
}

nsresult RotateProfileDeks(nsIFile* aProfileDir) {
  nsresult rv = ResolvePendingDekRotations(aProfileDir);
  NS_ENSURE_SUCCESS(rv, rv);

  return ForEachProfileDatabase(
      aProfileDir, [](nsIFile* aDbFile, const nsACString& aRel) -> nsresult {
        if (PeekDatabaseEncryptionState(aDbFile) !=
            OnDiskEncryptionState::Encrypted) {
          return NS_OK;  // Rotation only applies to encrypted databases.
        }
        nsAutoString path16;
        nsresult rv = aDbFile->GetPath(path16);
        NS_ENSURE_SUCCESS(rv, rv);
        NS_ConvertUTF16toUTF8 pathUtf8(path16);

        nsAutoCString oldHex;
        rv = GetEncryptionKey(pathUtf8, OpenIntent::LoadExisting, oldHex);
        NS_ENSURE_SUCCESS(rv, rv);

        nsAutoCString newHex;
        rv = GenerateEncryptionKeys(newHex);
        NS_ENSURE_SUCCESS(rv, rv);

        // Journal the new key, re-encrypt the file under it, then repoint the
        // keystore. The journal lets an interrupted repoint be completed on the
        // next start (see ResolvePendingDekRotations).
        rv = WriteRekeyJournal(aDbFile, newHex);
        NS_ENSURE_SUCCESS(rv, rv);
        rv = ConvertDatabaseFile(aDbFile, MigrationDirection::RotateDek, oldHex,
                                 newHex);
        NS_ENSURE_SUCCESS(rv, rv);
        rv = ReplaceDatabaseDek(pathUtf8, newHex);
        NS_ENSURE_SUCCESS(rv, rv);
        RemoveRekeyJournal(aDbFile);
        return NS_OK;
      });
}

}  // namespace mozilla::storage
