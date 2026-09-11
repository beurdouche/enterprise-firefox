/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

/**
 * Once the internal NSS token has been locked during a session, every path
 * that needs the primary password must log it back in with the console secret
 * rather than prompt the user, who does not know that secret.
 */

const { EnterpriseStorageEncryption } = ChromeUtils.importESModule(
  "resource://gre/modules/enterprise/EnterpriseStorageEncryption.sys.mjs"
);
const { ConsoleClient } = ChromeUtils.importESModule(
  "resource://gre/modules/enterprise/ConsoleClient.sys.mjs"
);
const { LoginHelper } = ChromeUtils.importESModule(
  "resource://gre/modules/LoginHelper.sys.mjs"
);
const { LoginManagerRustStorage } = ChromeUtils.importESModule(
  "resource://gre/modules/storage-rust.sys.mjs"
);
const { sinon } = ChromeUtils.importESModule(
  "resource://testing-common/Sinon.sys.mjs"
);

const PREF_ENABLED = "security.storage.encryption.enabled";
const SECRET = "console-managed-primary-secret";

const LoginInfo = Components.Constructor(
  "@mozilla.org/login-manager/loginInfo;1",
  "nsILoginInfo",
  "init"
);

// NSS needs a profile directory for key4.db.
do_get_profile();

const gToken = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
  Ci.nsIPKCS11Token
);
let gGetPrimarySecret;

add_setup(async function () {
  Services.prefs.setBoolPref(PREF_ENABLED, true);
  gGetPrimarySecret = sinon
    .stub(ConsoleClient, "getPrimarySecret")
    .resolves({ data: SECRET });

  Assert.ok(!gToken.hasPassword, "the test token starts without a password");
  await gToken.changePassword("", SECRET);
  Assert.ok(await EnterpriseStorageEncryption.relogin());
  Assert.ok(gToken.isLoggedIn, "the token is unlocked after setup");

  registerCleanupFunction(() => {
    sinon.restore();
    Services.prefs.clearUserPref(PREF_ENABLED);
  });
});

function serveSecret(value) {
  gGetPrimarySecret.resetHistory();
  gGetPrimarySecret.resolves({ data: value });
}

add_task(async function test_relogin_unlocks_a_locked_token() {
  await gToken.logout();
  Assert.ok(!gToken.isLoggedIn, "the token is locked");
  serveSecret(SECRET);

  Assert.ok(await EnterpriseStorageEncryption.relogin());
  Assert.ok(gToken.isLoggedIn, "relogin unlocked the token");
  Assert.equal(gGetPrimarySecret.callCount, 1, "the secret was fetched once");
});

add_task(async function test_relogin_does_not_fetch_when_unlocked() {
  Assert.ok(gToken.isLoggedIn);
  serveSecret(SECRET);

  Assert.ok(await EnterpriseStorageEncryption.relogin());
  Assert.equal(
    gGetPrimarySecret.callCount,
    0,
    "no fetch for an unlocked token"
  );
});

add_task(async function test_concurrent_relogins_share_one_fetch() {
  await gToken.logout();
  serveSecret(SECRET);

  const results = await Promise.all([
    EnterpriseStorageEncryption.relogin(),
    EnterpriseStorageEncryption.relogin(),
    EnterpriseStorageEncryption.relogin(),
  ]);
  Assert.deepEqual(results, [true, true, true]);
  Assert.ok(gToken.isLoggedIn);
  Assert.equal(gGetPrimarySecret.callCount, 1, "one fetch for three callers");
});

add_task(async function test_relogin_fails_closed() {
  await gToken.logout();

  gGetPrimarySecret.resetHistory();
  gGetPrimarySecret.rejects(new Error("console unreachable"));
  Assert.ok(!(await EnterpriseStorageEncryption.relogin()));
  Assert.ok(!gToken.isLoggedIn, "an unreachable console leaves it locked");

  serveSecret("not-the-token-password");
  Assert.ok(!(await EnterpriseStorageEncryption.relogin()));
  Assert.ok(!gToken.isLoggedIn, "a rejected secret leaves it locked");

  serveSecret(SECRET);
  Assert.ok(await EnterpriseStorageEncryption.relogin());
  Assert.ok(gToken.isLoggedIn, "a later attempt with the right secret works");
});

add_task(async function test_relogin_is_inert_when_not_managed() {
  await gToken.logout();
  serveSecret(SECRET);
  Services.prefs.setBoolPref(PREF_ENABLED, false);

  Assert.ok(!(await EnterpriseStorageEncryption.relogin()));
  Assert.ok(!gToken.isLoggedIn);
  Assert.equal(gGetPrimarySecret.callCount, 0, "no fetch when unmanaged");

  Services.prefs.setBoolPref(PREF_ENABLED, true);
  Assert.ok(await EnterpriseStorageEncryption.relogin());
});

add_task(async function test_requestReauth_relogins_instead_of_prompting() {
  await gToken.logout();
  serveSecret(SECRET);

  const { isAuthorized, telemetryEvent } = await LoginHelper.requestReauth(
    null,
    0,
    "",
    "",
    "test"
  );
  Assert.ok(isAuthorized, "reauth succeeds without a prompt");
  Assert.equal(telemetryEvent.value, "success");
  Assert.ok(gToken.isLoggedIn, "reauth unlocked the token");
  Assert.equal(gGetPrimarySecret.callCount, 1);
});

add_task(async function test_requestReauth_fails_closed() {
  await gToken.logout();
  gGetPrimarySecret.resetHistory();
  gGetPrimarySecret.rejects(new Error("console unreachable"));

  const { isAuthorized, telemetryEvent } = await LoginHelper.requestReauth(
    null,
    0,
    "",
    "",
    "test"
  );
  Assert.ok(!isAuthorized, "reauth is denied when the secret is unavailable");
  Assert.equal(telemetryEvent.value, "fail");
  Assert.ok(!gToken.isLoggedIn, "the token stays locked");

  serveSecret(SECRET);
  Assert.ok(await EnterpriseStorageEncryption.relogin());
});

add_task(async function test_rust_storage_relogins_instead_of_prompting() {
  const storage = new LoginManagerRustStorage();
  await storage.initialize();
  await storage.addLoginsAsync([
    new LoginInfo(
      "https://example.com",
      "https://example.com",
      null,
      "user",
      "pass",
      "u",
      "p"
    ),
  ]);

  await gToken.logout();
  serveSecret(SECRET);
  const logins = await storage.getAllLogins();
  Assert.equal(logins.length, 1, "logins decrypt after the token was locked");
  Assert.equal(logins[0].password, "pass");
  Assert.ok(gToken.isLoggedIn, "the store logged the token back in");
  Assert.equal(gGetPrimarySecret.callCount, 1, "the secret was fetched once");

  // An unreachable console fails the operation the way a cancelled prompt does.
  await gToken.logout();
  gGetPrimarySecret.resetHistory();
  gGetPrimarySecret.rejects(new Error("console unreachable"));
  await Assert.rejects(
    storage.getAllLogins(),
    e => e.result == Cr.NS_ERROR_ABORT,
    "an unavailable secret aborts the operation"
  );
  Assert.ok(!gToken.isLoggedIn);

  // A rejected secret is not retried forever.
  serveSecret("not-the-token-password");
  await Assert.rejects(
    storage.getAllLogins(),
    e => e.result == Cr.NS_ERROR_ABORT,
    "a rejected secret aborts the operation"
  );
  Assert.ok(!gToken.isLoggedIn);
  Assert.equal(gGetPrimarySecret.callCount, 1, "the secret was fetched once");

  serveSecret(SECRET);
  Assert.equal((await storage.getAllLogins()).length, 1);
  Assert.ok(gToken.isLoggedIn);

  await storage.removeAllLoginsAsync();
});
