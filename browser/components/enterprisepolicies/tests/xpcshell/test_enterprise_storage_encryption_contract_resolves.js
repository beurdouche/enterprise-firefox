/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Generalized, always-on regression guard for Bug 2040374 -- the upstream
// removal of nsIPK11TokenDB / @mozilla.org/security/pk11tokendb;1 that
// silently broke enterprise transparent primary-password unlock.
//
// The original bug shipped green because the only code exercising the
// unlock task needs an enterprise build, and nothing asserted that the
// XPCOM contract it named still resolved. test_enterprise_storage_encryption
// _contracts.js now pins the task to the literal string "internalkeytoken"
// by matching the method source -- but that check is coupled to one
// hard-coded name and breaks the moment the task is legitimately moved to a
// different (valid) contract.
//
// This test instead enforces the invariant that actually failed: every
// XPCOM contract ID referenced via Cc[...] in
// BrowserGlue._runEnterpriseStorageEncryptionLoad must resolve in this
// build, whatever its name. A reference to any removed or misspelled
// contract -- the exact failure mode of the original bug -- turns this red.
// It has no enterprise gate, so it runs in every CI configuration and
// cannot fall into the blind spot that let the regression land.

const { BrowserGlue } = ChromeUtils.importESModule(
  "resource:///modules/BrowserGlue.sys.mjs"
);

// Matches Cc["@mozilla.org/...;1"] and Cc['...'] literals, capturing the
// contract id. Deliberately only matches string-literal lookups; a computed
// Cc[variable] can't be statically resolved and is out of scope here.
const CONTRACT_RE = /Cc\[\s*(["'])(@[^"']+)\1\s*\]/g;

add_task(function test_every_referenced_contract_resolves() {
  Assert.equal(
    typeof BrowserGlue.prototype._runEnterpriseStorageEncryptionLoad,
    "function",
    "The unlock task body must live in a named method this guard can read. " +
      "If this fails the refactor was undone -- re-extract the task body."
  );

  const body =
    BrowserGlue.prototype._runEnterpriseStorageEncryptionLoad.toString();
  const contractIds = [...body.matchAll(CONTRACT_RE)].map(match => match[2]);

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
