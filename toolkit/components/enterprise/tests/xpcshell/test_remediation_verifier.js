/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { RemediationVerifier, RemediationError, INTERPRETERS } =
  ChromeUtils.importESModule(
    "resource://gre/modules/enterprise/RemediationVerifier.sys.mjs"
  );
const { LocalFileSource } = ChromeUtils.importESModule(
  "resource://gre/modules/enterprise/RemediationSource.sys.mjs"
);

// Inside the fixtures' fixed validity window (2026-01-01 to 2026-01-30). The
// window is fixed rather than relative so these tests do not start failing on
// a date nobody wrote down; see sign_manifest.py.
const NOW = Date.parse("2026-01-15T00:00:00Z");

const EXPECTED = { toolId: "felt-smoketest", minVersion: "1.0.0", now: NOW };

function fixtureDir() {
  return do_get_file("remediation").path;
}

function source() {
  return new LocalFileSource(fixtureDir());
}

async function rejectsWith(promise, code) {
  let caught = null;
  try {
    await promise;
  } catch (e) {
    caught = e;
  }
  Assert.ok(caught, "verification should have been rejected");
  Assert.equal(caught.code, code, `rejected with ${code}`);
  return caught;
}

add_setup(function () {
  RemediationVerifier.testingOnly_resetCounters();
});

add_task(async function test_good_document_verifies() {
  const signed = await source().fetch("felt-smoketest");
  const verified = await RemediationVerifier.verify(signed, EXPECTED);

  Assert.ok(
    RemediationVerifier.isVerified(verified),
    "verify() brands the object it returns"
  );
  Assert.equal(
    verified.interpreter,
    INTERPRETERS.sh,
    "resolved interpreter path"
  );
  Assert.equal(verified.manifest.toolId, "felt-smoketest");
  Assert.equal(verified.origin, "local-file");

  const script = new TextDecoder().decode(verified.script);
  Assert.ok(
    script.includes("Hello World"),
    "decoded script is the Hello World payload"
  );
  Assert.ok(
    script.includes("/Applications/Zed.app"),
    "decoded script opens Zed by absolute bundle path"
  );
});

add_task(async function test_forged_object_is_not_verified() {
  const signed = await source().fetch("felt-smoketest");
  const real = await RemediationVerifier.verify(signed, EXPECTED);

  // Same shape, same values, never returned by verify().
  const forged = Object.freeze({ ...real });
  Assert.ok(
    !RemediationVerifier.isVerified(forged),
    "a structurally identical copy is not accepted"
  );
  Assert.ok(
    !RemediationVerifier.isVerified({}),
    "an empty object is not accepted"
  );
  Assert.ok(!RemediationVerifier.isVerified(null), "null is not accepted");
});

add_task(async function test_bad_signature_is_rejected() {
  const signed = await source().fetch("felt-smoketest-badsig");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "felt-smoketest-badsig",
    }),
    RemediationError.SIGNATURE_INVALID
  );
});

add_task(async function test_wrong_san_is_rejected() {
  // Same signing key, so the signature itself is cryptographically fine; only
  // the certificate's subject alternative name differs. This isolates the SAN
  // pinning from everything else.
  const signed = await source().fetch("felt-smoketest");
  const wrongSanChain =
    (await IOUtils.readUTF8(
      PathUtils.join(fixtureDir(), "remediation_wrongsan_ee.pem")
    )) +
    (await IOUtils.readUTF8(
      PathUtils.join(fixtureDir(), "remediation_int.pem")
    ));

  await rejectsWith(
    RemediationVerifier.verify(
      { ...signed, certChain: wrongSanChain },
      EXPECTED
    ),
    RemediationError.SIGNATURE_INVALID
  );
});

add_task(async function test_expired_manifest_is_rejected() {
  const signed = await source().fetch("felt-expired");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "felt-expired",
    }),
    RemediationError.MANIFEST_EXPIRED
  );
});

add_task(async function test_not_yet_valid_manifest_is_rejected() {
  const signed = await source().fetch("felt-smoketest");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      now: Date.parse("2025-01-01T00:00:00Z"),
    }),
    RemediationError.MANIFEST_NOT_YET_VALID
  );
});

add_task(async function test_tool_mismatch_is_rejected() {
  const signed = await source().fetch("felt-smoketest");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "some-other-tool",
    }),
    RemediationError.TOOL_MISMATCH
  );
});

add_task(async function test_downgrade_is_rejected() {
  // A validly signed document must not lower the bar the console set.
  const signed = await source().fetch("felt-downgrade");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "felt-downgrade",
      minVersion: "1.0.0",
    }),
    RemediationError.VERSION_DOWNGRADE
  );
});

add_task(async function test_unknown_interpreter_is_rejected() {
  const signed = await source().fetch("felt-badinterp");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "felt-badinterp",
    }),
    RemediationError.UNKNOWN_INTERPRETER
  );
});

add_task(async function test_overlong_validity_window_is_rejected() {
  // A signer must not be able to mint a document that stays replayable
  // indefinitely.
  const signed = await source().fetch("felt-toolong");
  await rejectsWith(
    RemediationVerifier.verify(signed, { ...EXPECTED, toolId: "felt-toolong" }),
    RemediationError.VALIDITY_TOO_LONG
  );
});

add_task(async function test_prototype_key_is_not_an_interpreter() {
  // "constructor" resolves to something truthy on a plain object literal. The
  // interpreter map has a null prototype so that it does not.
  Assert.equal(
    INTERPRETERS.constructor,
    undefined,
    "the interpreter map has no inherited keys"
  );

  const signed = await source().fetch("felt-protointerp");
  await rejectsWith(
    RemediationVerifier.verify(signed, {
      ...EXPECTED,
      toolId: "felt-protointerp",
    }),
    RemediationError.UNKNOWN_INTERPRETER
  );
});

add_task(async function test_replay_is_rejected_once_counter_is_spent() {
  RemediationVerifier.testingOnly_resetCounters();
  const signed = await source().fetch("felt-smoketest");

  const verified = await RemediationVerifier.verify(signed, EXPECTED);
  Assert.equal(verified.manifest.counter, 1, "fixture carries counter 1");

  RemediationVerifier.acceptCounter(
    "felt-smoketest",
    verified.manifest.counter
  );

  await rejectsWith(
    RemediationVerifier.verify(signed, EXPECTED),
    RemediationError.REPLAY_REJECTED
  );

  RemediationVerifier.testingOnly_resetCounters();
});

add_task(async function test_non_ascii_is_rejected_before_verification() {
  // XPConnect narrows ACString to Latin-1, so a manifest that is not ASCII
  // would be mangled before it is hashed. It must never reach the verifier.
  const signed = await source().fetch("felt-smoketest");
  await rejectsWith(
    RemediationVerifier.verify(
      { ...signed, manifestText: `${signed.manifestText}é` },
      EXPECTED
    ),
    RemediationError.NOT_ASCII
  );
  await rejectsWith(
    RemediationVerifier.verify(
      { ...signed, manifestText: `${signed.manifestText}\u{1f600}` },
      EXPECTED
    ),
    RemediationError.NOT_ASCII
  );
});

add_task(async function test_oversized_manifest_is_rejected() {
  const signed = await source().fetch("felt-smoketest");
  await rejectsWith(
    RemediationVerifier.verify(
      { ...signed, manifestText: "a".repeat(64 * 1024 + 1) },
      EXPECTED
    ),
    RemediationError.TOO_LARGE
  );
});

add_task(async function test_trust_anchor_is_the_xpcshell_root() {
  // The whole demo rests on this: under xpcshell we verify against the test
  // root, and nothing in the payload can change that.
  Assert.equal(
    RemediationVerifier.trustAnchor(),
    Ci.nsIX509CertDB.AppXPCShellRoot,
    "xpcshell runs resolve to the test root"
  );
});
