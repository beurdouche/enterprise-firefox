/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Regression guard for upstream Bug 2037682, which removed the
// nsIPK11TokenDB interface and the @mozilla.org/security/pk11tokendb;1
// contract. BrowserGlue._runEnterpriseStorageEncryptionLoad must use the
// surviving @mozilla.org/security/internalkeytoken;1 contract that returns
// an nsIPKCS11Token directly.
//
// If this test starts failing, the enterprise transparent primary-password
// unlock task is broken at startup and users will see the primary-password
// prompt instead of the SDR being silently unlocked.

add_task(function test_legacy_pk11tokendb_contract_is_gone() {
  Assert.equal(
    Cc["@mozilla.org/security/pk11tokendb;1"],
    undefined,
    "The legacy @mozilla.org/security/pk11tokendb;1 contract must not " +
      "resolve. If it does, this test is moot — but BrowserGlue should " +
      "still be using the new internalkeytoken contract."
  );
});

add_task(function test_internalkeytoken_exposes_methods_used_by_browserglue() {
  const token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );

  // Every method/attribute BrowserGlue._runEnterpriseStorageEncryptionLoad
  // touches must exist on the new interface. Touching missing members
  // would either throw or return undefined; we just probe each one.
  Assert.equal(
    typeof token.needsUserInit,
    "boolean",
    "needsUserInit is exposed"
  );
  Assert.equal(typeof token.needsLogin, "function", "needsLogin is exposed");
  Assert.equal(
    typeof token.initPassword,
    "function",
    "initPassword is exposed"
  );
  Assert.equal(
    typeof token.changePassword,
    "function",
    "changePassword is exposed"
  );
  Assert.equal(
    typeof token.checkPassword,
    "function",
    "checkPassword is exposed"
  );
  Assert.equal(typeof token.isLoggedIn, "function", "isLoggedIn is exposed");
  Assert.equal(typeof token.hasPassword, "boolean", "hasPassword is exposed");
});

add_task(async function test_browserglue_does_not_reference_dead_contract() {
  const { BrowserGlue } = ChromeUtils.importESModule(
    "resource:///modules/BrowserGlue.sys.mjs"
  );
  Assert.equal(
    typeof BrowserGlue.prototype._runEnterpriseStorageEncryptionLoad,
    "function",
    "The unlock task body lives in a named method that tests can " +
      "exercise directly. If this fails, the refactor was undone — fix " +
      "by re-extracting the task body."
  );

  const body =
    BrowserGlue.prototype._runEnterpriseStorageEncryptionLoad.toString();
  Assert.ok(
    !body.includes("pk11tokendb"),
    "The unlock task body must not reference the removed " +
      "@mozilla.org/security/pk11tokendb;1 contract."
  );
  Assert.ok(
    !body.includes("nsIPK11TokenDB"),
    "The unlock task body must not reference the removed nsIPK11TokenDB " +
      "interface."
  );
  Assert.ok(
    body.includes("internalkeytoken"),
    "The unlock task body must use the @mozilla.org/security/" +
      "internalkeytoken;1 contract."
  );
  Assert.ok(
    body.includes("nsIPKCS11Token"),
    "The unlock task body must use the nsIPKCS11Token interface."
  );
});
