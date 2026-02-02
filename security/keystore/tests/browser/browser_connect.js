/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

// Test that database connections work with enabled keystore encryption.

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  Sqlite: "resource://gre/modules/Sqlite.sys.mjs",
  IOUtils: "resource://gre/modules/IOUtils.sys.mjs",
});

add_task(async function testSecurityEnableEncryption() {
  is(
    Services.prefs.getBoolPref("security.storage.encryption.sqlite.enabled"),
    true,
    "security.storage.encryption.sqlite.enabled should be enabled"
  );

  let conn = await lazy.Sqlite.openConnection({
    path: "test.sqlite",
  });

  is(conn._connectionData._open, true, "Connection should be open");

  let res = await conn.execute("SELECT 1;");
  is(res[0].getResultByIndex(0), 1, "'SELECT 1;' should return 1");

  await conn.execute("CREATE TABLE test (value TEXT);");
  await conn.execute("INSERT INTO test (value) VALUES ('hello');");

  conn.close();

  let profileDir = await Services.dirsvc.get("ProfD", Ci.nsIFile).hostPath();

  is(
    await IOUtils.exists(profileDir + "/bikeshed/keystore.enc"),
    true,
    "bikeshed/keystore.enc should exist"
  );

  is(
    await IOUtils.exists(profileDir + "/test.sqlite.enc"),
    true,
    "test.sqlite.enc should exist"
  );

  conn = await lazy.Sqlite.openConnection({
    path: "test.sqlite",
  });

  res = await conn.execute("SELECT value FROM test;");

  let values = res.map(row => row.getResultByName("value"));
  is(values[0], "hello", "Test `value` should be `'hello'`");
});
