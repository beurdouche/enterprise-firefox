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
//
// These guards are intentionally ungated (no run-if = ["enterprise"]): they
// assert core-NSS contract resolution and that BrowserGlue references no
// removed contract, which must hold in every build -- including the default
// non-enterprise CI configuration, which is exactly where the original
// regression shipped green. Gating them would re-create that blind spot.

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

add_task(async function test_every_referenced_contract_resolves() {
  // Generalized companion to the string-match guard above: instead of pinning
  // the task to the literal "internalkeytoken", assert that EVERY XPCOM
  // contract id the task names via a Cc["@..."] literal actually resolves in
  // this build. This is rename-proof and catches the exact failure mode of
  // the original bug -- a reference to a removed or misspelled contract.
  const { BrowserGlue } = ChromeUtils.importESModule(
    "resource:///modules/BrowserGlue.sys.mjs"
  );

  // Matches Cc["@mozilla.org/...;1"] / Cc['...'] literals, capturing the
  // contract id. Only string-literal lookups are in scope; a computed
  // Cc[variable] can't be resolved statically.
  const contractRe = /Cc\[\s*(["'])(@[^"']+)\1\s*\]/g;

  const body =
    BrowserGlue.prototype._runEnterpriseStorageEncryptionLoad.toString();
  const contractIds = [...body.matchAll(contractRe)].map(match => match[2]);

  Assert.greater(
    contractIds.length,
    0,
    "The unlock task must reference at least one XPCOM contract via a " +
      "Cc[...] string literal. A zero count means the regex no longer " +
      "matches the task body -- update this guard rather than letting it " +
      "pass vacuously."
  );

  for (const id of contractIds) {
    Assert.notStrictEqual(
      Cc[id],
      undefined,
      `Contract ${id}, referenced by _runEnterpriseStorageEncryptionLoad, ` +
        `must resolve in this build. An undefined entry here is exactly the ` +
        `nsIPK11TokenDB-style dead-contract regression this guard exists to ` +
        `catch: at runtime the task would throw on .getService/.createInstance ` +
        `and the primary-password unlock would silently fail.`
    );
  }
});
