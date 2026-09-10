/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  createEnterpriseLogger:
    "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
  isTesting: "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
});

ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return lazy.createEnterpriseLogger("RemediationVerifier");
});

/**
 * The subject alternative name the signing certificate must be valid for. This
 * is compiled in and is never read from the payload: a payload-supplied name
 * would make every certificate under the trust anchor acceptable.
 */
const SIGNER_NAME = "remediation.enterprise-firefox.mozilla.org";

/**
 * Interpreters a manifest may name, mapped to the absolute path we actually
 * spawn. The manifest supplies the key, never the path.
 *
 * This bounds what gets exec'd, not what the script can do: a signed script can
 * exec anything the user can. It exists so the spawned program is always one we
 * chose, and so logs are unambiguous.
 */
export const INTERPRETERS = Object.freeze(
  Object.assign(Object.create(null), {
    sh: "/bin/sh",
    bash: "/bin/bash",
  })
);

const SCHEMA_VERSION = 1;
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_SCRIPT_BYTES = 256 * 1024;
// How long a signer may declare a document valid for. This is a policy the
// client imposes on the signer; notAfter and the monotonic counter are the
// controls that actually bound replay.
// TODO: Bug TBD - tighten to days once documents are console-issued. A year is
// what keeps the checked-in fixtures from becoming a dated CI failure, and is
// only tolerable while the feature is gated to non-shippable builds.
const MAX_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;

// The verifier takes ACString, and XPConnect narrows JS strings to Latin-1 on
// the way in, so anything outside this range is silently mangled before it is
// hashed. Restricting to printable ASCII plus the usual whitespace keeps what
// we verify identical to what was signed.
const MANIFEST_ASCII_RE = /^[\x20-\x7E\r\n\t]*$/;

const COUNTERS_PREF = "enterprise.posture.remediation.counters";

/** Every way verification can fail. Only these reach the posture payload. */
export const RemediationError = {
  NOT_ASCII: "not-ascii",
  TOO_LARGE: "too-large",
  SIGNATURE_INVALID: "signature-invalid",
  MALFORMED_JSON: "malformed-json",
  SCHEMA_REJECTED: "schema-rejected",
  TOOL_MISMATCH: "tool-mismatch",
  PLATFORM_MISMATCH: "platform-mismatch",
  MANIFEST_EXPIRED: "manifest-expired",
  MANIFEST_NOT_YET_VALID: "manifest-not-yet-valid",
  VALIDITY_TOO_LONG: "validity-too-long",
  REPLAY_REJECTED: "replay-rejected",
  UNKNOWN_INTERPRETER: "unknown-interpreter",
  VERSION_DOWNGRADE: "version-downgrade",
  SCRIPT_UNDECODABLE: "script-undecodable",
};

/** A refusal to run a remediation document, carrying a closed-set code. */
export class RemediationRejected extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "RemediationRejected";
    this.code = code;
  }
}

// Only verify() puts an object in here, and only _execute() reads it, so there
// is no path from a fetched payload to execution that skips verification.
const gVerified = new WeakSet();

function reject(code, message) {
  throw new RemediationRejected(code, message);
}

function readCounters() {
  try {
    const parsed = JSON.parse(
      Services.prefs.getStringPref(COUNTERS_PREF, "{}")
    );
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (e) {
    lazy.log.error(`Malformed ${COUNTERS_PREF}, treating as empty:`, e);
    return {};
  }
}

export const RemediationVerifier = {
  /**
   * The trust anchor to verify against.
   *
   * Chosen by build configuration, never by the payload and never by a pref
   * alone: the test anchor requires a build that cannot ship (a plain mozconfig
   * leaves MOZ_UPDATE_CHANNEL at "default", the same gate bypass_allowed()
   * applies to MOZ_BYPASS_FELT) as well as the testing pref.
   *
   * @returns {number} An nsIX509CertDB/nsIContentSignatureVerifier root constant.
   */
  trustAnchor() {
    if (Services.env.exists("XPCSHELL_TEST_PROFILE_DIR")) {
      return Ci.nsIX509CertDB.AppXPCShellRoot;
    }
    if (AppConstants.MOZ_UPDATE_CHANNEL === "default" && lazy.isTesting()) {
      return Ci.nsIX509CertDB.AppXPCShellRoot;
    }
    // TODO: Bug TBD - replace with a dedicated enterprise remediation root
    // before this is enabled in production. Under the shared content-signature
    // root only SIGNER_NAME separates a remediation manifest from a Remote
    // Settings collection.
    return Ci.nsIContentSignatureVerifier.ContentSignatureProdRoot;
  },

  /**
   * @typedef {object} SignedRemediation
   * @property {string} manifestText The exact bytes that were signed.
   * @property {string} signature Content-signature header value.
   * @property {string} certChain PEM chain, end entity first.
   * @property {string} origin Diagnostic label only ("local-file", "console").
   */

  /**
   * @typedef {object} VerifiedRemediation
   * @property {object} manifest The parsed, checked manifest.
   * @property {Uint8Array} script Decoded remediation script bytes.
   * @property {string} interpreter Absolute path of the interpreter to spawn.
   * @property {number} timeoutMs Clamped execution budget.
   * @property {string} origin Where the document came from.
   */

  /**
   * Verifies a signed remediation document and returns it in a form the
   * executor will accept. Rejects with a RemediationRejected carrying a
   * closed-set code.
   *
   * Nothing is parsed before the signature verifies, and nothing is written to
   * disk here: the caller receives the script as bytes it already trusts.
   *
   * @param {SignedRemediation} signed
   * @param {object} expected
   * @param {string} expected.toolId The tool this document must remediate.
   * @param {string} expected.minVersion The version bar the console set.
   * @param {number} [expected.now] Reference time, injected so the checked-in
   *   test fixtures can carry a fixed validity window instead of a window that
   *   silently expires one day.
   * @param {boolean} [expected.allowSameCounter] Accept the counter already
   *   spent for this tool, for a retry a person explicitly asked for. Never
   *   accepts an older one, so a stale document still cannot be replayed.
   * @returns {Promise<VerifiedRemediation>}
   */
  async verify(
    signed,
    { toolId, minVersion, now = Date.now(), allowSameCounter = false }
  ) {
    const { manifestText, signature, certChain, origin } = signed;

    if (
      typeof manifestText !== "string" ||
      !MANIFEST_ASCII_RE.test(manifestText)
    ) {
      reject(RemediationError.NOT_ASCII, "manifest is not printable ASCII");
    }
    if (manifestText.length > MAX_MANIFEST_BYTES) {
      reject(
        RemediationError.TOO_LARGE,
        `manifest is ${manifestText.length} bytes`
      );
    }

    let ok = false;
    try {
      ok = await Cc["@mozilla.org/security/contentsignatureverifier;1"]
        .getService(Ci.nsIContentSignatureVerifier)
        .asyncVerifyContentSignature(
          manifestText,
          signature,
          certChain,
          SIGNER_NAME,
          this.trustAnchor()
        );
    } catch (e) {
      reject(RemediationError.SIGNATURE_INVALID, `verifier threw: ${e}`);
    }
    if (!ok) {
      reject(RemediationError.SIGNATURE_INVALID, "signature did not verify");
    }

    let manifest;
    try {
      manifest = JSON.parse(manifestText);
    } catch (e) {
      reject(RemediationError.MALFORMED_JSON, `${e}`);
    }

    if (!manifest || manifest.schemaVersion !== SCHEMA_VERSION) {
      reject(
        RemediationError.SCHEMA_REJECTED,
        `schemaVersion ${manifest?.schemaVersion} is not ${SCHEMA_VERSION}`
      );
    }
    if (manifest.toolId !== toolId) {
      reject(
        RemediationError.TOOL_MISMATCH,
        `manifest is for ${manifest.toolId}, expected ${toolId}`
      );
    }
    if (manifest.platform !== AppConstants.platform) {
      reject(
        RemediationError.PLATFORM_MISMATCH,
        `manifest is for ${manifest.platform}`
      );
    }

    const notBefore = Date.parse(manifest.notBefore);
    const notAfter = Date.parse(manifest.notAfter);
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
      reject(RemediationError.SCHEMA_REJECTED, "unparseable validity window");
    }
    if (notAfter - notBefore > MAX_VALIDITY_MS) {
      reject(
        RemediationError.VALIDITY_TOO_LONG,
        `${notAfter - notBefore}ms exceeds ${MAX_VALIDITY_MS}ms`
      );
    }
    if (now < notBefore) {
      reject(RemediationError.MANIFEST_NOT_YET_VALID, manifest.notBefore);
    }
    if (now > notAfter) {
      reject(RemediationError.MANIFEST_EXPIRED, manifest.notAfter);
    }

    if (!Number.isSafeInteger(manifest.counter) || manifest.counter < 0) {
      reject(
        RemediationError.SCHEMA_REJECTED,
        "counter is not a non-negative integer"
      );
    }
    // Unattended attempts demand a strictly newer counter, which is what
    // stops a captured document being replayed at a device. A retry a person
    // asked for may re-run the current document -- they already hold the
    // privileges the script would use -- but still never an older one, so the
    // no-going-backwards property holds either way.
    const seen = readCounters()[toolId];
    if (Number.isSafeInteger(seen)) {
      const stale = allowSameCounter
        ? manifest.counter < seen
        : manifest.counter <= seen;
      if (stale) {
        reject(
          RemediationError.REPLAY_REJECTED,
          `counter ${manifest.counter} is not acceptable against ${seen}` +
            `${allowSameCounter ? " (retry)" : ""}`
        );
      }
    }

    const remediate = manifest.remediate;
    if (!remediate || typeof remediate.script !== "string") {
      reject(RemediationError.SCHEMA_REJECTED, "no remediate.script");
    }
    // INTERPRETERS has a null prototype, so "constructor" and friends are
    // simply absent rather than inherited.
    const interpreter = INTERPRETERS[remediate.interpreter];
    if (!interpreter) {
      reject(
        RemediationError.UNKNOWN_INTERPRETER,
        `${remediate.interpreter} is not a known interpreter`
      );
    }

    // A signed document must not lower the bar the console set.
    if (
      typeof manifest.targetVersion !== "string" ||
      Services.vc.compare(manifest.targetVersion, minVersion) < 0
    ) {
      reject(
        RemediationError.VERSION_DOWNGRADE,
        `targetVersion ${manifest.targetVersion} is below required ${minVersion}`
      );
    }

    let script;
    try {
      const binary = atob(remediate.script);
      if (binary.length > MAX_SCRIPT_BYTES) {
        reject(RemediationError.TOO_LARGE, `script is ${binary.length} bytes`);
      }
      script = Uint8Array.from(binary, c => c.charCodeAt(0));
    } catch (e) {
      if (e instanceof RemediationRejected) {
        throw e;
      }
      reject(RemediationError.SCRIPT_UNDECODABLE, `${e}`);
    }

    const timeoutMs = Math.min(
      Number.isFinite(remediate.timeoutMs)
        ? remediate.timeoutMs
        : MAX_TIMEOUT_MS,
      MAX_TIMEOUT_MS
    );

    const verified = Object.freeze({
      manifest,
      script,
      interpreter,
      timeoutMs,
      origin,
    });
    gVerified.add(verified);
    lazy.log.debug(
      `Verified remediation for ${toolId} (counter ${manifest.counter}, from ${origin})`
    );
    return verified;
  },

  /**
   * Whether this object came from verify(). The executor's only admission check.
   *
   * @param {object} candidate
   * @returns {boolean}
   */
  isVerified(candidate) {
    return (
      typeof candidate === "object" &&
      candidate !== null &&
      gVerified.has(candidate)
    );
  },

  /**
   * Records a manifest's counter as spent. Must be called before the script is
   * spawned, so a crash mid-execution cannot re-enable the same document.
   *
   * @param {string} toolId
   * @param {number} counter
   */
  acceptCounter(toolId, counter) {
    const counters = readCounters();
    if (Number.isSafeInteger(counters[toolId]) && counters[toolId] >= counter) {
      return;
    }
    counters[toolId] = counter;
    Services.prefs.setStringPref(COUNTERS_PREF, JSON.stringify(counters));
  },

  /** Test-only: forget every spent counter. */
  testingOnly_resetCounters() {
    if (
      !lazy.isTesting() &&
      !Services.env.exists("XPCSHELL_TEST_PROFILE_DIR")
    ) {
      throw new Error("testingOnly_resetCounters() outside testing");
    }
    Services.prefs.clearUserPref(COUNTERS_PREF);
  },
};
