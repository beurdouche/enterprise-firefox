/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Bug 1996558: the generic plaintext->encrypted profile migration and DEK
// rotation. Drives the synchronous, test-only entry points on
// mozIStorageService (the same work the startup barrier performs) and asserts:
//   - a plaintext in-profile database becomes obfsvfs-encrypted, data intact;
//   - a database under storage/private/ (ephemeral PBM) is left untouched;
//   - a DEK rotation changes the on-disk ciphertext while preserving the data.

const { Sqlite } = ChromeUtils.importESModule(
  "resource://gre/modules/Sqlite.sys.mjs"
);

const ENABLED = "security.storage.encryption.sqlite.enabled";
const TESTING = "security.storage.encryption.sqlite.testing";

function setEncryptionEnabled(on) {
  // The pref ships locked; unlock before overriding (no-op if not locked).
  Services.prefs.unlockPref(ENABLED);
  Services.prefs.setBoolPref(ENABLED, on);
}

// Classify a file by its SQLite header: the obfsvfs signature is an 8192-byte
// page size (offset 16, big-endian) with 32 reserved bytes (offset 20).
async function onDiskState(path) {
  let bytes = await IOUtils.read(path, { maxBytes: 24 });
  const magic = "SQLite format 3\0";
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic.charCodeAt(i)) {
      return "notsqlite";
    }
  }
  let pageSize = (bytes[16] << 8) | bytes[17];
  if (pageSize === 1) {
    pageSize = 65536;
  }
  return pageSize === 8192 && bytes[20] === 32 ? "encrypted" : "plaintext";
}

async function createPlaintextDb(path, withData) {
  let conn = await Sqlite.openConnection({ path });
  if (withData) {
    await conn.execute("PRAGMA user_version = 42");
    await conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)");
    await conn.execute(
      "INSERT INTO t(id, name) VALUES (1,'alpha'),(2,'beta'),(3,'gamma')"
    );
  }
  await conn.close();
}

function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

add_task(async function test_migrate_then_rotate() {
  let dbPath = PathUtils.join(PathUtils.profileDir, "migrate-test.sqlite");
  // A database under storage/private/ uses an ephemeral key, not the profile
  // DEK, so the migration must leave it alone.
  let pbmDir = PathUtils.join(
    PathUtils.profileDir,
    "storage",
    "private",
    "https+++example.com",
    "idb"
  );
  let pbmPath = PathUtils.join(pbmDir, "pbm.sqlite");

  registerCleanupFunction(async () => {
    Services.prefs.unlockPref(ENABLED);
    Services.prefs.clearUserPref(ENABLED);
    Services.prefs.clearUserPref(TESTING);
    await IOUtils.remove(dbPath, { ignoreAbsent: true });
    await IOUtils.remove(PathUtils.join(PathUtils.profileDir, "storage"), {
      ignoreAbsent: true,
      recursive: true,
    });
  });

  // 1. With encryption OFF, seed plaintext databases in the profile.
  setEncryptionEnabled(false);
  await createPlaintextDb(dbPath, /* withData */ true);
  await IOUtils.makeDirectory(pbmDir, { createAncestors: true });
  // Seed with data so the file actually has an on-disk header: an empty SQLite
  // database that is opened and closed without a write stays 0 bytes, which the
  // header check below would (correctly) classify as "notsqlite" rather than
  // "plaintext".
  await createPlaintextDb(pbmPath, /* withData */ true);

  Assert.equal(await onDiskState(dbPath), "plaintext", "seeded plaintext");
  Assert.equal(await onDiskState(pbmPath), "plaintext", "seeded PBM plaintext");

  // 2. Turn encryption ON and run the migration.
  setEncryptionEnabled(true);
  Services.prefs.setBoolPref(TESTING, true);
  Services.storage.migrateProfileToEncryptedNow();

  // 3. The ordinary profile database is encrypted; the storage/private one is
  //    untouched.
  Assert.equal(await onDiskState(dbPath), "encrypted", "profile DB migrated");
  Assert.equal(
    await onDiskState(pbmPath),
    "plaintext",
    "storage/private database excluded from migration"
  );

  // 4. Data survives the migration (reopened through obfsvfs + the lockstore).
  let conn = await Sqlite.openConnection({ path: dbPath });
  let rows = await conn.execute("SELECT name FROM t ORDER BY id");
  Assert.equal(rows.length, 3, "all rows preserved");
  Assert.equal(rows[0].getResultByName("name"), "alpha", "row value preserved");
  let uv = await conn.execute("PRAGMA user_version");
  Assert.equal(
    uv[0].getResultByName("user_version"),
    42,
    "user_version preserved"
  );
  await conn.close();

  // 5. Rotate the DEK: the on-disk ciphertext must change, the data must not.
  let before = await IOUtils.read(dbPath);
  Services.storage.rotateProfileDeksNow();
  let after = await IOUtils.read(dbPath);
  Assert.ok(!bytesEqual(before, after), "ciphertext changed after rotation");
  Assert.equal(await onDiskState(dbPath), "encrypted", "still encrypted");

  conn = await Sqlite.openConnection({ path: dbPath });
  rows = await conn.execute("SELECT name FROM t ORDER BY id");
  Assert.equal(rows.length, 3, "data intact after rotation");
  Assert.equal(rows[0].getResultByName("name"), "alpha", "value intact");
  await conn.close();
});
