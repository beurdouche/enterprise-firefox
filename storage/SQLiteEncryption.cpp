/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/storage/SQLiteEncryption.h"

#include "mozilla/Hex.h"
#include "mozilla/Logging.h"
#include "mozilla/Services.h"
#include "mozilla/StaticMutex.h"
#include "mozilla/StaticPtr.h"
#include "mozilla/StaticPrefs_security.h"
#include "mozilla/SyncRunnable.h"
#include "mozilla/security/lockstore/lockstore_ffi_generated.h"
#include "ScopedNSSTypes.h"
#include "nsAppDirectoryServiceDefs.h"
#include "nsCOMPtr.h"
#include "nsDirectoryServiceDefs.h"
#include "nsDirectoryServiceUtils.h"
#include "nsIFelt.h"
#include "nsIFile.h"
#include "nsIObserver.h"
#include "nsIObserverService.h"
#include "nsIXULRuntime.h"
#include "nsLocalFile.h"
#include "nsServiceManagerUtils.h"
#include "nsString.h"
#include "nsTArray.h"
#include "nsThreadUtils.h"
#include "prinrval.h"
#include "prthread.h"

namespace mozilla::storage {

mozilla::LogModule* GetSQLiteEncryptionLog() {
  static mozilla::LazyLogModule sLog("SQLiteEncryption");
  return sLog;
}

namespace {

using mozilla::security::lockstore::keystore_add_kek;
using mozilla::security::lockstore::keystore_close;
using mozilla::security::lockstore::keystore_create_dek;
using mozilla::security::lockstore::keystore_create_kek;
using mozilla::security::lockstore::keystore_delete_kek;
using mozilla::security::lockstore::keystore_get_dek;
using mozilla::security::lockstore::keystore_list_deks;
using mozilla::security::lockstore::keystore_list_keks;
using mozilla::security::lockstore::keystore_open;
using mozilla::security::lockstore::keystore_remove_kek;
using mozilla::security::lockstore::keystore_switch_kek;
using mozilla::security::lockstore::keystore_unlock_kek;
using mozilla::security::lockstore::KeystoreHandle;

// Deterministic kek_ref literals (the random-suffix in
// `lockstore::kek::<type>:<id>`) for the two KEKs the storage layer
// owns. Defined as string literals; consumers wrap them in a local
// `nsCString` before passing &-of to the FFI (which expects
// `const nsACString*`, not the more-derived `nsLiteralCString*`).
#define KEK_REF_LOCAL_SQLITE "lockstore::kek::local:sqlite"
#define KEK_REF_PASSWORD_SQLITE "lockstore::kek::password:sqlite"

// Practical max for cache_timeout_ms; "session-unlimited". Lockstore's
// 0 means "don't cache" (zero-and-discard), not "infinity".
// u32::MAX ms == ~49.7 days; if a session ever runs that long, the
// re-unlock path in GetEncryptionKey transparently re-derives.
constexpr uint32_t kKekCacheTimeoutMs = UINT32_MAX;

constexpr size_t kDekBytes = 32;

mozilla::StaticMutex sStateMutex MOZ_UNANNOTATED;
KeystoreHandle* sHandle = nullptr;
nsString sCachedProfilePath;
// Deterministic kek_ref under which every SQLite DEK is wrapped.
// In the new design this is `lockstore::kek::password:sqlite` (a
// Password KEK with primarySecret as the password); the legacy
// `lockstore::kek::local:sqlite` value is migrated away at first
// launch. Resolved lazily via the unlock-or-create flow in
// GetEncryptionKey. Guarded by sStateMutex.
nsCString sKekRef;
// Console-supplied primarySecret (64-char hex), cached for the
// lifetime of the session. Set once via EnsurePrimarySecretCached at
// profile-do-change; consumed by the Password KEK unlock/create call
// and by the transparent re-unlock path after cache expiry. Held in
// the same StaticMutex lifecycle as sHandle so it survives across
// background-thread DB opens. Cleared on quit-application.
nsCString sPrimarySecret;
// Set once quit-application has torn the keystore down, so later calls
// don't re-open it or mint key material that would never be destroyed.
bool sShuttingDown = false;

class ProfileObserver final : public nsIObserver {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIOBSERVER
 private:
  ~ProfileObserver() = default;
};

mozilla::StaticRefPtr<ProfileObserver> sObserver;

NS_IMPL_ISUPPORTS(ProfileObserver, nsIObserver)

// Synchronously pull the console-supplied primarySecret from the Felt
// IPC bridge into our static cache. The Felt parent process pre-fetches
// primarySecret before spawning Firefox and sends it as its first IPC
// message (FeltProcessParent.sys.mjs:startFirefox); the spawned child's
// FeltClientThread stashes it in PRIMARY_SECRET, which the
// nsIFelt::peekPrimarySecret accessor exposes synchronously.
//
// Polls every 50 ms up to 5 s. If the secret never arrives,
// GetEncryptionKey will hit `keystore_unlock_kek` with an empty
// password and the encryption gate in nsAppRunner refuses the launch.
//
// Returns NS_OK on success, NS_ERROR_NOT_AVAILABLE on timeout.
nsresult EnsurePrimarySecretCached() {
  MOZ_ASSERT(NS_IsMainThread());
  {
    StaticMutexAutoLock lock(sStateMutex);
    if (!sPrimarySecret.IsEmpty()) {
      return NS_OK;
    }
  }
  nsCOMPtr<nsIFelt> felt = do_GetService("@mozilla.org/toolkit/library/felt;1");
  if (!felt) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
            ("Felt service unavailable; cannot fetch primarySecret"));
    return NS_ERROR_NOT_AVAILABLE;
  }
  constexpr uint32_t kTimeoutMs = 5000;
  constexpr uint32_t kStepMs = 50;
  uint32_t waited = 0;
  nsAutoCString secret;
  while (waited < kTimeoutMs) {
    secret.Truncate();
    nsresult rv = felt->PeekPrimarySecret(secret);
    if (NS_SUCCEEDED(rv) && !secret.IsEmpty()) {
      StaticMutexAutoLock lock(sStateMutex);
      sPrimarySecret = secret;
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
              ("primarySecret cached (len=%u) after %ums",
               secret.Length(), waited));
      return NS_OK;
    }
    PR_Sleep(PR_MillisecondsToInterval(kStepMs));
    waited += kStepMs;
  }
  MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
          ("primarySecret never arrived from Felt IPC after %ums",
           kTimeoutMs));
  return NS_ERROR_NOT_AVAILABLE;
}

// One-shot migration. Called at most once per profile, from the
// create branch of GetEncryptionKey. Rotates every DEK currently
// wrapped under `lockstore::kek::local:sqlite` to instead be wrapped
// under `lockstore::kek::password:sqlite`, then deletes the now-orphan
// LocalKey record. Idempotent: on a true-fresh profile there's no
// local:sqlite to rotate and this is a no-op.
//
// Caller must hold sStateMutex.
nsresult MigrateLocalToPasswordKek() {
  sStateMutex.AssertCurrentThreadOwns();
  MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
          ("Migrating local:sqlite -> password:sqlite"));
  const nsCString localKek(KEK_REF_LOCAL_SQLITE ""_ns);
  const nsCString passwordKek(KEK_REF_PASSWORD_SQLITE ""_ns);
  nsTArray<nsCString> collections;
  nsresult rv = keystore_list_deks(sHandle, &collections);
  if (NS_FAILED(rv)) {
    return rv;
  }
  uint32_t rotated = 0;
  for (const auto& coll : collections) {
    nsTArray<nsCString> keks;
    if (NS_FAILED(keystore_list_keks(sHandle, &coll, &keks))) {
      continue;
    }
    bool hasLocal = false;
    for (const auto& k : keks) {
      if (k.Equals(localKek)) {
        hasLocal = true;
        break;
      }
    }
    if (!hasLocal) {
      continue;
    }
    // Add the password wrapping, switch primary to it, drop the
    // local wrapping. Each step independently fallible; log and
    // move on so a single bad collection doesn't strand the rest.
    nsresult ar = keystore_add_kek(sHandle, &coll, &localKek, &passwordKek);
    if (NS_FAILED(ar)) {
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
              ("migrate: add_kek failed for %s: 0x%" PRIx32, coll.get(),
               static_cast<uint32_t>(ar)));
      continue;
    }
    nsresult sr =
        keystore_switch_kek(sHandle, &coll, &localKek, &passwordKek);
    if (NS_FAILED(sr)) {
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
              ("migrate: switch_kek failed for %s: 0x%" PRIx32, coll.get(),
               static_cast<uint32_t>(sr)));
      continue;
    }
    nsresult rr = keystore_remove_kek(sHandle, &coll, &localKek);
    if (NS_FAILED(rr)) {
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
              ("migrate: remove_kek failed for %s: 0x%" PRIx32, coll.get(),
               static_cast<uint32_t>(rr)));
      continue;
    }
    rotated++;
  }
  // After all collections are rotated, drop the LocalKey record
  // entirely. Lockstore's in-use guard rejects this if any
  // collection slipped through above; in that case the LocalKey
  // record survives and we'll retry on the next launch.
  nsresult dr = keystore_delete_kek(sHandle, &localKek);
  if (NS_FAILED(dr)) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
            ("migrate: delete_kek(local:sqlite) failed: 0x%" PRIx32
             " (will retry on next launch)",
             static_cast<uint32_t>(dr)));
  } else {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
            ("Migrated %u collections; local:sqlite deleted", rotated));
  }
  return NS_OK;
}

// Resolve the profile directory and cache it. MAIN-THREAD ONLY:
// NS_GetSpecialDirectory -> nsDirectoryService::Get asserts NS_IsMainThread()
// ("Do not call dirsvc::get on non-main threads!") and, in opt builds where
// the assert is compiled out, races its internal hashtable against the main
// thread. Off-main-thread callers must go through
// EnsureProfilePathCachedAnyThread() instead.
void EnsureProfilePathCached() {
  MOZ_ASSERT(NS_IsMainThread());
  nsCOMPtr<nsIFile> profileDir;
  nsresult rv = NS_GetSpecialDirectory(NS_APP_USER_PROFILE_50_DIR,
                                       getter_AddRefs(profileDir));
  if (NS_FAILED(rv) || !profileDir) {
    return;
  }
  nsString path;
  if (NS_FAILED(profileDir->GetPath(path)) || path.IsEmpty()) {
    return;
  }
  StaticMutexAutoLock lock(sStateMutex);
  sCachedProfilePath = path;
  MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info, ("Profile path cached"));
}

// Ensure the profile path is cached; callable from any thread. Database opens
// run on worker threads (e.g. the QuotaManager / IndexedDB IO threads) where
// the directory service is unavailable, so off the main thread we bounce a
// tiny runnable to the main thread to resolve and cache the path. This is the
// safe direction (worker -> main): the main thread never blocks waiting on a
// storage IO thread, so it cannot deadlock. The fast path avoids the dispatch
// once the path is cached (which, after the first open, it always is).
void EnsureProfilePathCachedAnyThread() {
  {
    StaticMutexAutoLock lock(sStateMutex);
    if (!sCachedProfilePath.IsEmpty()) {
      return;
    }
  }
  if (NS_IsMainThread()) {
    EnsureProfilePathCached();
    return;
  }
  nsCOMPtr<nsIRunnable> r =
      NS_NewRunnableFunction("mozilla::storage::EnsureProfilePathCached",
                             []() { EnsureProfilePathCached(); });
  mozilla::SyncRunnable::DispatchToThread(GetMainThreadSerialEventTarget(), r);
}

// Snapshot the cached profile path, resolving and caching it on first use.
// Runs on whatever thread opened the database (often a worker such as the
// QuotaManager IO thread, which can open DBs before the main-thread eager
// cache or profile-after-change has populated it -- and under xpcshell
// profile-after-change never fires at all). dirsvc is main-thread only, so
// EnsureProfilePathCachedAnyThread bounces to the main thread when called from
// a worker rather than resolving (and crashing) here. Returns
// NS_ERROR_NOT_INITIALIZED if the path still cannot be resolved.
nsresult GetCachedProfilePath(nsString& aOutPath) {
  {
    StaticMutexAutoLock lock(sStateMutex);
    aOutPath = sCachedProfilePath;
  }
  if (aOutPath.IsEmpty()) {
    EnsureProfilePathCachedAnyThread();
    StaticMutexAutoLock lock(sStateMutex);
    aOutPath = sCachedProfilePath;
  }
  if (aOutPath.IsEmpty()) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
            ("Profile path not yet cached"));
    return NS_ERROR_NOT_INITIALIZED;
  }
  return NS_OK;
}

// If the encryption pref is on, mark the running profile's compatibility.ini
// with EncryptedDatabases=1 (append-only; the writer skips if already
// present), so a later launch can refuse to open the now-encrypted databases
// under a build that would treat them as plaintext. Safe to call on every
// profile-after-change.
void MarkProfileEncryptedIfNeeded() {
  MOZ_ASSERT(NS_IsMainThread());
  if (!StaticPrefs::security_storage_encryption_sqlite_enabled()) {
    return;
  }
  nsCOMPtr<nsIXULRuntime> xulRuntime =
      do_GetService("@mozilla.org/xre/app-info;1");
  if (!xulRuntime) {
    return;
  }
  (void)xulRuntime->MarkProfileEncryptedDatabases();
}

// When SQLite encryption is on, NSS must be fully initialized on the MAIN
// thread before any in-profile database is opened on a worker (the
// QuotaManager / IndexedDB IO threads). Otherwise the worker's
// EnsureNSSInitializedChromeOrContent() SyncRunnable-dispatches NSS init back
// to the main thread and blocks -- which deadlocks when the main thread is
// itself blocked awaiting that very storage operation (e.g. a synchronous
// LocalStorage/QuotaManager op spinning a nested event loop). Initializing NSS
// here, on the main thread, makes that worker call a cheap no-op (NSS init is
// an idempotent process-wide one-shot). Gated on the profile path being known
// (NSS needs cert9.db/key4.db; forcing it earlier brings NSS up via
// NSS_NoDB_Init and breaks PSM) and MAIN-THREAD ONLY (so this can never itself
// be the deadlocking worker->main dispatch).
void EnsureNSSInitializedForEncryptionIfReady() {
  MOZ_ASSERT(NS_IsMainThread());
  if (!StaticPrefs::security_storage_encryption_sqlite_enabled()) {
    return;
  }
  {
    StaticMutexAutoLock lock(sStateMutex);
    if (sCachedProfilePath.IsEmpty()) {
      return;
    }
  }
  (void)EnsureNSSInitializedChromeOrContent();
}

NS_IMETHODIMP ProfileObserver::Observe(nsISupports*, const char* aTopic,
                                       const char16_t*) {
  if (!strcmp(aTopic, "profile-do-change")) {
    // Earliest reliable main-thread point at which the profile (and its cert
    // DB) is available, in BOTH the browser and xpcshell -- unlike
    // profile-after-change, which does not fire under xpcshell. It also
    // strictly precedes any QuotaManager database open (QuotaManager refuses to
    // be created before profile-do-change). Pre-initialize NSS here so the
    // later worker-thread opens never deadlock dispatching NSS init to a
    // blocked main thread.
    EnsureProfilePathCached();
    EnsureNSSInitializedForEncryptionIfReady();
    // Also pull the Felt-supplied primarySecret into our cache here,
    // but only in the spawned-Browser-Firefox case. The Felt UI
    // process itself never receives primarySecret over IPC (it's the
    // entity that fetches it), so polling there would burn the full
    // 5s timeout for nothing -- and GetEncryptionKey routes the UI
    // process to the LocalKey path regardless.
    if (StaticPrefs::security_storage_encryption_sqlite_enabled()) {
      nsCOMPtr<nsIFelt> felt =
          do_GetService("@mozilla.org/toolkit/library/felt;1");
      bool isFeltSpawnedBrowser = false;
      if (felt) {
        (void)felt->IsFeltBrowser(&isFeltSpawnedBrowser);
      }
      if (isFeltSpawnedBrowser) {
        (void)EnsurePrimarySecretCached();
      }
    }
  } else if (!strcmp(aTopic, "profile-after-change")) {
    EnsureProfilePathCached();
    MarkProfileEncryptedIfNeeded();
  } else if (!strcmp(aTopic, "quit-application")) {
    // Close lockstore now (AppShutdownConfirmed) so the SQLite WAL
    // checkpoint that runs inside the keystore's Drop happens before
    // LateWriteChecks activates at AppShutdownNetTeardown (the default
    // toolkit.shutdown.lateWriteChecksStage = 2).
    ShutdownEncryptionKeystore();
  }
  return NS_OK;
}

}  // namespace

void InitEncryptionKeystore() {
  MOZ_ASSERT(NS_IsMainThread());

  // Eagerly try to cache the profile path. If the profile is already
  // loaded this succeeds; otherwise we fall through to the observer
  // below.
  EnsureProfilePathCached();

  // If the profile is already available (we were initialized after
  // profile-do-change, e.g. a lazily-created storage service), pre-initialize
  // NSS now; the profile-do-change observer below would otherwise miss it.
  // Mirrors nsCertOverrideService::Init's "observe, and run now if already
  // changed" pattern.
  EnsureNSSInitializedForEncryptionIfReady();

  if (sObserver) {
    return;
  }
  nsCOMPtr<nsIObserverService> os = mozilla::services::GetObserverService();
  if (!os) {
    return;
  }
  sObserver = new ProfileObserver();
  if (NS_FAILED(os->AddObserver(sObserver, "profile-do-change", false)) ||
      NS_FAILED(os->AddObserver(sObserver, "profile-after-change", false)) ||
      NS_FAILED(os->AddObserver(sObserver, "quit-application", false))) {
    os->RemoveObserver(sObserver, "profile-do-change");
    os->RemoveObserver(sObserver, "profile-after-change");
    os->RemoveObserver(sObserver, "quit-application");
    sObserver = nullptr;
  }
}

nsresult GetDatabaseEncryptionStatus(const nsACString& aDatabasePath,
                                     EncryptionStatus& aStatus) {
  nsString profilePath;
  nsresult rv = GetCachedProfilePath(profilePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> profileDir = new nsLocalFile();
  rv = profileDir->InitWithPath(profilePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> dbFile = new nsLocalFile();
  rv = dbFile->InitWithPath(NS_ConvertUTF8toUTF16(aDatabasePath));
  NS_ENSURE_SUCCESS(rv, rv);

  // A database under the profile directory is encrypted; anything else (an
  // xpcshell temp file, a migration import opened from outside the profile)
  // has no stable per-database identifier and is opened as plaintext.
  bool isUnder = false;
  rv = profileDir->Contains(dbFile, &isUnder);
  NS_ENSURE_SUCCESS(rv, rv);

  aStatus = isUnder ? EncryptionStatus::Encrypted : EncryptionStatus::Plaintext;
  if (!isUnder) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Debug,
            ("Database outside profile; opening unencrypted"));
  }
  return NS_OK;
}

nsresult GetEncryptionKey(const nsACString& aDatabasePath, OpenIntent aIntent,
                          nsACString& aOutHexKey) {
  // The caller has already established via GetDatabaseEncryptionStatus that
  // this database lives under the profile; resolve the profile path again to
  // derive the lockstore collection name.
  nsString profilePath;
  nsresult rv = GetCachedProfilePath(profilePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> profileDir = new nsLocalFile();
  rv = profileDir->InitWithPath(profilePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> dbFile = new nsLocalFile();
  rv = dbFile->InitWithPath(NS_ConvertUTF8toUTF16(aDatabasePath));
  NS_ENSURE_SUCCESS(rv, rv);

  // The collection name is the database's path relative to the profile
  // directory (e.g. "places.sqlite", "storage/permanent/.../idb/x.sqlite").
  // Unique by construction and human-readable when inspecting the
  // lockstore SQLite directly.
  nsAutoCString collection;
  rv = dbFile->GetRelativePath(profileDir, collection);
  NS_ENSURE_SUCCESS(rv, rv);

  // Open the lockstore handle (memoised per-path), resolve the shared
  // SQLite LocalKey, and read/create this database's DEK -- all while
  // holding sStateMutex so ShutdownEncryptionKeystore can't close the
  // handle out from under us (mak: avoid use-after-close).
  nsTArray<uint8_t> dek;
  {
    StaticMutexAutoLock lock(sStateMutex);

    if (sShuttingDown) {
      // After quit-application the keystore is (being) torn down; don't
      // re-open it or mint key material that would never be destroyed
      // (mak). Fail the open rather than silently dropping encryption.
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Warning,
              ("Encryption key requested during shutdown"));
      return NS_ERROR_FAILURE;
    }

    if (!sHandle) {
      NS_ConvertUTF16toUTF8 profilePathUtf8(profilePath);
      rv = keystore_open(&profilePathUtf8, &sHandle);
      if (NS_FAILED(rv)) {
        MOZ_LOG(
            GetSQLiteEncryptionLog(), LogLevel::Error,
            ("keystore_open failed: 0x%" PRIx32, static_cast<uint32_t>(rv)));
        return rv;
      }
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info, ("Lockstore opened"));
    }

    // Branch on which Felt-tier process this is. The Felt UI process
    // (parent of the spawned browsing Firefox) is the entity that
    // fetches primarySecret from the console; it cannot itself depend
    // on primarySecret to bootstrap its own profile encryption.
    // Per the design doc, Felt's own profile stays on a LocalKey
    // (`lockstore::kek::local:sqlite`); the residual exposure was
    // audited and accepted there. Only the spawned browsing Firefox
    // (where `Services.felt.isFeltBrowser()` is true) gets the
    // Password KEK keyed by primarySecret.
    bool isFeltSpawnedBrowser = false;
    {
      nsCOMPtr<nsIFelt> felt =
          do_GetService("@mozilla.org/toolkit/library/felt;1");
      if (felt) {
        (void)felt->IsFeltBrowser(&isFeltSpawnedBrowser);
      }
    }

    if (sKekRef.IsEmpty()) {
      if (isFeltSpawnedBrowser) {
        // Spawned browsing Firefox -- Password KEK keyed by
        // primarySecret. Unlock-or-create.
        if (sPrimarySecret.IsEmpty()) {
          MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
                  ("primarySecret not cached; cannot bootstrap Password KEK"));
          return NS_ERROR_NOT_AVAILABLE;
        }
        // Step 1: try unlock against the steady-state kek_ref.
        const nsCString passwordKek(KEK_REF_PASSWORD_SQLITE ""_ns);
        nsresult urv = keystore_unlock_kek(
            sHandle, &passwordKek, &sPrimarySecret, kKekCacheTimeoutMs);
        if (NS_SUCCEEDED(urv)) {
          sKekRef = passwordKek;
          MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
                  ("Password KEK unlocked (steady state)"));
        } else if (urv == NS_ERROR_NOT_AVAILABLE ||
                   urv == NS_ERROR_INVALID_ARG) {
          // Lockstore returns InvalidKekRef ("no Password record for
          // kek_ref: ...") -> NS_ERROR_INVALID_ARG when the row is
          // absent (first-ever launch), and NotFound ->
          // NS_ERROR_NOT_AVAILABLE for other recoverable absences.
          // Both mean "no KEK yet -- mint it".
          // Not-yet-created path: mint it. create_kek with the same
          // identifier is idempotent (keystore.rs:1182-1185) and caches
          // the unwrapped bytes for kKekCacheTimeoutMs.
          const nsCString kekType("password"_ns);
          const nsCString kekId("sqlite"_ns);
          nsCString minted;
          nsresult crv =
              keystore_create_kek(sHandle, &kekType, &kekId, &sPrimarySecret,
                                  kKekCacheTimeoutMs, &minted);
          if (NS_FAILED(crv)) {
            MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
                    ("keystore_create_kek(password:sqlite) failed: 0x%" PRIx32,
                     static_cast<uint32_t>(crv)));
            return crv;
          }
          sKekRef = minted;
          MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
                  ("Password KEK created: %s", sKekRef.get()));
          // First-ever-create: rotate any pre-existing local:sqlite
          // wrappings to the new Password KEK and drop the LocalKey
          // record. Soft-fails per-collection; truly fresh profiles
          // have no local:sqlite and this is a no-op.
          (void)MigrateLocalToPasswordKek();
        } else {
          // Wrong-password / I/O / other - propagate. AEAD tag failure
          // from a rotated primarySecret would surface here as
          // NS_ERROR_ABORT (LockstoreError::WrongPassword).
          MOZ_LOG(
              GetSQLiteEncryptionLog(), LogLevel::Error,
              ("keystore_unlock_kek(password:sqlite) failed: 0x%" PRIx32,
               static_cast<uint32_t>(urv)));
          return urv;
        }
      } else {
        // Felt UI process (or non-Felt dev build): no primarySecret
        // available. Use a LocalKey. create_kek with a fixed identifier
        // is get-or-create: mints `lockstore::kek::local:sqlite` on
        // first run and recovers it on every later run.
        const nsCString kekType("local"_ns);
        const nsCString kekId("sqlite"_ns);
        const nsCString empty;
        nsresult crv = keystore_create_kek(sHandle, &kekType, &kekId, &empty,
                                           /* cache_timeout_ms */ 0, &sKekRef);
        if (NS_FAILED(crv)) {
          sKekRef.Truncate();
          MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
                  ("keystore_create_kek(local:sqlite) failed: 0x%" PRIx32,
                   static_cast<uint32_t>(crv)));
          return crv;
        }
        MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
                ("LocalKey KEK in use (Felt UI / non-Felt build): %s",
                 sKekRef.get()));
      }
    }

    rv = keystore_get_dek(sHandle, &collection, &sKekRef, &dek);
    if (rv == NS_ERROR_NOT_AVAILABLE && !sPrimarySecret.IsEmpty()) {
      // The Password KEK's in-memory cache may have expired (TTL ~49d).
      // Re-unlock transparently and retry once. If the DEK still
      // returns NS_ERROR_NOT_AVAILABLE after this, the issue is
      // missing DEK (CreateIfNew path handles it below), not an
      // expired KEK.
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Debug,
              ("get_dek returned NS_ERROR_NOT_AVAILABLE; re-unlocking KEK"));
      nsresult urv = keystore_unlock_kek(sHandle, &sKekRef, &sPrimarySecret,
                                         kKekCacheTimeoutMs);
      if (NS_SUCCEEDED(urv)) {
        rv = keystore_get_dek(sHandle, &collection, &sKekRef, &dek);
      }
    }
    if (rv == NS_ERROR_NOT_AVAILABLE && aIntent == OpenIntent::CreateIfNew) {
      // First time we see this new (in-profile) database: mint an extractable
      // DEK under the shared KEK. A racing thread may have created it first,
      // in which case create_dek reports the duplicate as NS_ERROR_FAILURE --
      // benign; the get_dek below is the arbiter. LoadExisting never mints a
      // key: a missing DEK for an existing database is a hard error (handled
      // below), not a cue to create one and make the contents unreadable.
      nsresult crv = keystore_create_dek(sHandle, &collection, &sKekRef,
                                         /* extractable */ true);
      if (NS_FAILED(crv)) {
        MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Debug,
                ("create_dek returned 0x%" PRIx32 "; re-reading",
                 static_cast<uint32_t>(crv)));
      }
      rv = keystore_get_dek(sHandle, &collection, &sKekRef, &dek);
    }
    if (NS_FAILED(rv)) {
      MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
              ("get_dek failed: 0x%" PRIx32, static_cast<uint32_t>(rv)));
      // This in-profile database is keyable, so a failure here is real: a
      // locked or failing keystore, or a missing DEK for an existing database,
      // must fail the open rather than silently read or write plaintext (gcp).
      // Remap NS_ERROR_NOT_AVAILABLE so it can never be mistaken for a "not
      // encrypted" signal at the call sites.
      return rv == NS_ERROR_NOT_AVAILABLE ? NS_ERROR_FAILURE : rv;
    }
  }

  if (dek.Length() != kDekBytes) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Error,
            ("Unexpected DEK length %zu", dek.Length()));
    return NS_ERROR_UNEXPECTED;
  }
  HexEncode(dek, aOutHexKey);
  return NS_OK;
}

void ShutdownEncryptionKeystore() {
  // Unregister observer outside the mutex; ObserverService is main-thread
  // only and we need to avoid lock-order surprises.
  RefPtr<ProfileObserver> observer;
  {
    StaticMutexAutoLock lock(sStateMutex);
    observer = sObserver.forget();
  }
  if (observer) {
    nsCOMPtr<nsIObserverService> os = mozilla::services::GetObserverService();
    if (os) {
      os->RemoveObserver(observer, "profile-do-change");
      os->RemoveObserver(observer, "profile-after-change");
      os->RemoveObserver(observer, "quit-application");
    }
  }

  StaticMutexAutoLock lock(sStateMutex);
  sShuttingDown = true;
  if (sHandle) {
    MOZ_LOG(GetSQLiteEncryptionLog(), LogLevel::Info,
            ("Shutting down lockstore"));
    (void)keystore_close(sHandle);
    sHandle = nullptr;
  }
  sKekRef.Truncate();
  sCachedProfilePath.Truncate();
  sPrimarySecret.Truncate();
}

}  // namespace mozilla::storage
