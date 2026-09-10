/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Detects whether the tools the console requires are installed at an
 * acceptable version and, when they are not, runs a signed remediation script.
 *
 * State lives on the module rather than on a caller for the same reason
 * PostureMonitor's does: the Felt process actor is re-created when the content
 * process hosting the login page is recycled. It additionally has to outlive
 * sign-out, because the attempt budget is a property of the machine, not of a
 * session -- a user signing out and back in must not reset it.
 */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  createEnterpriseLogger:
    "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
  isTesting: "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
  BIN_DIRS: "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs",
  BREW_CANDIDATES:
    "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs",
  PostureToolCatalog:
    "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs",
  LocalFileSource:
    "resource://gre/modules/enterprise/RemediationSource.sys.mjs",
  RemediationVerifier:
    "resource://gre/modules/enterprise/RemediationVerifier.sys.mjs",
  Subprocess: "resource://gre/modules/Subprocess.sys.mjs",
  setTimeout: "resource://gre/modules/Timer.sys.mjs",
  clearTimeout: "resource://gre/modules/Timer.sys.mjs",
});

ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return lazy.createEnterpriseLogger("PostureRemediation");
});

const CYCLE_INTERVAL_MS = 5 * 60 * 1000;
const POST_ATTEMPT_RECHECK_MS = 30 * 1000;
const BACKOFF_BASE_MS = 5 * 60 * 1000;
const BACKOFF_FACTOR = 2;
const BACKOFF_CAP_MS = 4 * 60 * 60 * 1000;
const BACKOFF_JITTER = 0.2;
const MAX_ATTEMPTS = 6;
const TOOL_PROBE_TIMEOUT_MS = 5000;
// Longer than a plain --version: brew reads its own metadata on first run.
const BREW_PROBE_TIMEOUT_MS = 30000;
const TERM_GRACE_MS = 5000;
const MAX_CAPTURE_BYTES = 64 * 1024;

// Numbers only. A test pref must never name a program, a path that gets
// executed, or an argv: that would reintroduce exactly the injection the
// signed-document design exists to close.
const CYCLE_MS_PREF = "enterprise.posture.remediation.cycle_ms";
const BACKOFF_BASE_PREF = "enterprise.posture.remediation.backoff_base_ms";
const MAX_ATTEMPTS_PREF = "enterprise.posture.remediation.max_attempts";

// A directory of *signed documents*, which is a different kind of input from a
// program path: everything read from it still has to verify against a trust
// anchor compiled into the build, so pointing this somewhere hostile gains
// nothing without the signing key. Testing-gated regardless.
const LOCAL_SOURCE_DIR_PREF = "enterprise.posture.remediation.local_dir";

const ARTIFACT_DIR_NAME = "posture-remediation";

/**
 * How the console wants non-compliance handled.
 *
 * "warn" shows the warning, pauses long enough to read it, then launches;
 * "block" refuses to launch until every requirement is compliant. Defaults to
 * "warn", so a console that says nothing cannot lock anyone out and an admin
 * opts into the strict behaviour per fleet.
 */
export const ENFORCEMENT_PREF = "enterprise.posture.remediation.enforcement";
const ENFORCEMENT_MODES = Object.freeze(["warn", "block"]);
const DEFAULT_ENFORCEMENT = "warn";

// How long "warn" holds the browser back so the warning can actually be read.
// Long enough for one sentence; the browser is otherwise ready to go.
const WARN_DWELL_MS = 6000;
const WARN_DWELL_PREF = "enterprise.posture.remediation.warn_dwell_ms";

// How often "block" re-evaluates while holding the browser back. Short,
// because a person is watching. Attempts stay backoff-limited underneath, so
// this re-probes rather than re-installing.
const GATE_POLL_MS = 3000;
const GATE_POLL_PREF = "enterprise.posture.remediation.gate_poll_ms";

/**
 * Requirements to use when the console sends none, in the console's own wire
 * format. A development affordance: the console cannot serve required_tools
 * yet, and the login path clears an absent list, so without this there is no
 * way to exercise remediation outside the test harness.
 *
 * Gated on a build that cannot ship -- MOZ_UPDATE_CHANNEL is only "default"
 * for a plain mozconfig, the same fence bypass_allowed() puts around
 * MOZ_BYPASS_FELT -- as well as the testing pref. Setting this on a release
 * build does nothing.
 */
const SEED_REQUIREMENTS_PREF =
  "enterprise.posture.remediation.seed_requirements";

function seedingAllowed() {
  return AppConstants.MOZ_UPDATE_CHANNEL === "default" && lazy.isTesting();
}

/**
 * The tools the console requires, as a JSON string. Absent, empty or malformed
 * means "require nothing".
 */
export const REQUIRED_TOOLS_PREF = "enterprise.posture.required_tools";

/**
 * Orders rows by id. Codepoint order rather than localeCompare, because the
 * result is hashed by the posture change-gate and must not depend on locale.
 *
 * @param {{id: string}} a
 * @param {{id: string}} b
 * @returns {number}
 */
function compareById(a, b) {
  if (a.id < b.id) {
    return -1;
  }
  return a.id > b.id ? 1 : 0;
}

/** The write side of ENFORCEMENT_PREF. */
export const Enforcement = {
  /**
   * Records the console's enforcement mode. An absent or unrecognized value
   * writes the safe default rather than preserving what was there, so a
   * console that stops sending it cannot leave a fleet blocked.
   *
   * @param {string} [mode]
   * @returns {string} The value written.
   */
  write(mode) {
    const value = ENFORCEMENT_MODES.includes(mode) ? mode : DEFAULT_ENFORCEMENT;
    Services.prefs.setStringPref(ENFORCEMENT_PREF, value);
    return value;
  },
};

/** The write side of REQUIRED_TOOLS_PREF, mirroring EdrAgents. */
export const RequiredTools = {
  /**
   * Writes the console's required-tool list into this process's pref. A
   * missing list writes "[]".
   *
   * Unlike EdrAgents.write this validates and normalizes at the boundary
   * instead of storing the console's array verbatim, so every later read is
   * already trustworthy. Entries naming a tool this build does not know are
   * dropped, the way resolve_requested() filter_maps unknown EDR ids.
   *
   * @param {Array<object>} [requiredTools]
   * @returns {string} The value written, so callers can relay it.
   */
  write(requiredTools) {
    const normalized = (Array.isArray(requiredTools) ? requiredTools : [])
      .map(entry => lazy.PostureToolCatalog.validateRequirement(entry))
      .filter(Boolean)
      .sort(compareById)
      .slice(0, 32);
    const serialized = JSON.stringify(normalized);
    Services.prefs.setStringPref(REQUIRED_TOOLS_PREF, serialized);
    return serialized;
  },
};

/** Outcomes of a remediation attempt, as reported to the console. */
const Outcome = Object.freeze({
  SUCCEEDED: "succeeded",
  FAILED: "failed",
  TIMEOUT: "timeout",
});

function testNumberPref(pref, fallback) {
  if (!lazy.isTesting()) {
    return fallback;
  }
  const value = Services.prefs.getIntPref(pref, 0);
  return value > 0 ? value : fallback;
}

/**
 * Delay before attempt number `attempts + 1`. Pure and takes `now` so it can be
 * unit-tested without waiting; the jitter keeps a fleet from retrying in step.
 *
 * @param {number} attempts How many attempts have already been made.
 * @param {() => number} [random]
 * @returns {number}
 */
export function nextAttemptDelay(attempts, random = Math.random) {
  const base = testNumberPref(BACKOFF_BASE_PREF, BACKOFF_BASE_MS);
  const raw = Math.min(
    base * BACKOFF_FACTOR ** Math.max(0, attempts - 1),
    BACKOFF_CAP_MS
  );
  const jitter = 1 + (random() * 2 - 1) * BACKOFF_JITTER;
  return Math.round(raw * jitter);
}

/**
 * Compliance verdict for one tool. Pure: everything it needs is an argument.
 *
 * @param {object} options
 * @param {string|null} options.installed Normalized installed version, or null.
 * @param {string} options.required Normalized required version.
 * @param {boolean} options.supported Whether this platform can probe the tool.
 * @param {boolean} options.probeFailed Whether the probe itself errored.
 * @param {boolean} [options.packageManagerMissing] Whether the tool is managed
 *   by a package manager this device does not have.
 * @returns {string} One of
 *   compliant|missing|outdated|unknown|unsupported|check-failed|unavailable
 */
export function decideStatus({
  installed,
  required,
  supported,
  probeFailed,
  packageManagerMissing = false,
}) {
  if (!supported) {
    return "unsupported";
  }
  // Nothing can be determined *or* fixed here until an admin provisions the
  // package manager, which is a different message from a failed probe.
  if (packageManagerMissing) {
    return "unavailable";
  }
  if (probeFailed) {
    return "check-failed";
  }
  if (installed === null) {
    return "missing";
  }
  // An unparseable version must never read as "too old": a HEAD build would
  // otherwise be remediated forever.
  if (required === null) {
    return "unknown";
  }
  return Services.vc.compare(installed, required) >= 0
    ? "compliant"
    : "outdated";
}

export const PostureRemediation = {
  _records: new Map(),
  _cyclePromise: null,
  _nextCycleAt: 0,
  _paused: false,
  _published: Object.freeze([]),
  _onWarning: null,
  _userRequested: false,
  _lastWarningKey: "",

  /**
   * Applies the console's requirement list.
   *
   * Records are diffed by `${id}@${minVersion}` so a directive that repeats an
   * unchanged requirement keeps its attempt count and backoff -- otherwise a
   * console polling every minute would reset the cap every minute.
   *
   * @param {Array<{id: string, minVersion: string}>} requirements
   */
  configure(requirements) {
    const next = new Map();
    for (const { id, minVersion } of requirements ?? []) {
      const key = `${id}@${minVersion}`;
      const existing = this._records.get(id);
      next.set(
        id,
        existing?.requirementKey === key
          ? existing
          : {
              id,
              required: minVersion,
              requirementKey: key,
              installed: null,
              status: "unknown",
              attempts: 0,
              lastOutcome: null,
              lastErrorCode: null,
              lastExitCode: null,
              lastAttemptAt: null,
              blockErrorCode: null,
              documentCounter: null,
              state: "idle",
              nextAttemptAt: 0,
              blockedUntil: 0,
            }
      );
    }
    this._records = next;
    this._nextCycleAt = 0;
    this._publish();
  },

  /**
   * Re-reads REQUIRED_TOOLS_PREF and applies it. The pref was normalized by
   * RequiredTools.write(), so this only has to survive a malformed pref.
   */
  configureFromPref() {
    let parsed = [];
    try {
      const raw = Services.prefs.getStringPref(REQUIRED_TOOLS_PREF, "");
      if (raw) {
        const value = JSON.parse(raw);
        parsed = Array.isArray(value) ? value : [];
      }
    } catch (e) {
      lazy.log.error(`Malformed ${REQUIRED_TOOLS_PREF}, requiring nothing:`, e);
      parsed = [];
    }
    let requirements = parsed.filter(
      e => typeof e?.id === "string" && typeof e?.minVersion === "string"
    );
    if (!requirements.length) {
      requirements = this._seedRequirements();
    }
    this.configure(requirements);
  },

  /**
   * Development-only requirements from SEED_REQUIREMENTS_PREF. Returns nothing
   * unless seedingAllowed(), and validates through the same catalog the
   * console's list goes through, so a seeded requirement behaves identically
   * to a real one.
   *
   * @returns {Array<{id: string, minVersion: string}>}
   */
  _seedRequirements() {
    if (!seedingAllowed()) {
      return [];
    }
    try {
      const raw = Services.prefs.getStringPref(SEED_REQUIREMENTS_PREF, "");
      if (!raw) {
        return [];
      }
      const value = JSON.parse(raw);
      const seeded = (Array.isArray(value) ? value : [])
        .map(entry => lazy.PostureToolCatalog.validateRequirement(entry))
        .filter(Boolean);
      if (seeded.length) {
        lazy.log.warn(
          `Seeding ${seeded.length} requirement(s) from ` +
            `${SEED_REQUIREMENTS_PREF}. This is a development-only path and ` +
            `is unreachable in a shipping build.`
        );
      }
      return seeded;
    } catch (e) {
      lazy.log.error(
        `Malformed ${SEED_REQUIREMENTS_PREF}, seeding nothing:`,
        e
      );
      return [];
    }
  },

  /**
   * The console's enforcement mode, defaulting to "warn".
   *
   * @returns {string} "warn" or "block"
   */
  enforcement() {
    const value = Services.prefs.getStringPref(
      ENFORCEMENT_PREF,
      DEFAULT_ENFORCEMENT
    );
    return ENFORCEMENT_MODES.includes(value) ? value : DEFAULT_ENFORCEMENT;
  },

  /** Whether every configured requirement is currently compliant. */
  _allCompliant() {
    return [...this._records.values()].every(r => r.status === "compliant");
  },

  /**
   * Runs a cycle now, ignoring the normal schedule.
   *
   * The gate cannot wait for the monitor's interval: that is the console's
   * policy-poll cadence and may be a minute, which is far too long to hold a
   * sign-in. Remediation attempts stay backoff-limited inside _checkOne, so
   * forcing cycles re-probes without re-installing.
   */
  async _forceCycle() {
    this._nextCycleAt = 0;
    this.onTick();
    await this.idle();
  },

  _sleep(ms) {
    return new Promise(resolve => lazy.setTimeout(resolve, ms));
  },

  /**
   * Holds the browser launch until posture has been dealt with.
   *
   * In "warn" this evaluates once, and if the device is not compliant it
   * pauses for WARN_DWELL_MS so the person can read the message before their
   * browser appears. In "block" it holds indefinitely until compliant.
   *
   * The caller must have started PostureMonitor first, so token refreshes keep
   * running while the browser is held back. That is what makes "block"
   * recoverable: a changed directive arrives on a refresh and can relax
   * enforcement or drop the requirement. Without it a device blocked on an
   * unsatisfiable requirement could never be rescued, because the only channel
   * that delivers a new directive would be stopped.
   *
   * @param {object} options
   * @param {() => boolean} options.isCancelled Abort (sign-out, shutdown).
   * @returns {Promise<string>} Why it stopped waiting.
   */
  async awaitCompliance({ isCancelled }) {
    if (!this._records.size) {
      return "no-requirements";
    }
    if (!Services.felt.isFeltUI()) {
      return "not-felt";
    }

    await this._forceCycle();

    if (this.enforcement() !== "block") {
      if (this._allCompliant()) {
        return "compliant";
      }
      lazy.log.warn(
        "Device is not compliant; pausing so the warning can be read."
      );
      await this._sleep(testNumberPref(WARN_DWELL_PREF, WARN_DWELL_MS));
      return "warned";
    }

    lazy.log.warn("Enforcement is 'block': holding the browser back.");
    for (;;) {
      if (isCancelled()) {
        return "cancelled";
      }
      if (this._allCompliant()) {
        return "compliant";
      }
      // A directive that arrived on a token refresh can relax enforcement or
      // drop the requirement; either must release the gate.
      if (this.enforcement() !== "block") {
        return "relaxed";
      }
      if (!this._records.size) {
        return "no-requirements";
      }
      await this._sleep(testNumberPref(GATE_POLL_PREF, GATE_POLL_MS));
      await this._forceCycle();
    }
  },

  /**
   * Runs remediation now because a person asked, ignoring the backoff and any
   * refusal that is holding the tool back.
   *
   * This is the escape hatch for "block" enforcement: without it a device
   * whose document has already been spent has nothing to do but wait. It does
   * not reset the attempt cap, so it cannot be used to loop forever, and the
   * document still has to verify.
   *
   * @returns {Promise<void>}
   */
  async remediateNow() {
    if (!Services.felt.isFeltUI()) {
      return;
    }
    lazy.log.warn("Remediation requested by the user.");
    this._userRequested = true;
    for (const record of this._records.values()) {
      if (record.status !== "compliant") {
        record.nextAttemptAt = 0;
        record.blockedUntil = 0;
      }
    }
    this._paused = false;
    await this._forceCycle();
  },

  /** Whether the UI should offer a Remediate action. */
  canRemediateNow() {
    return [...this._records.values()].some(
      r =>
        r.status === "missing" ||
        r.status === "outdated" ||
        r.status === "blocked"
    );
  },

  /** Stops scheduling. Does not kill a running child; see _run(). */
  pause() {
    this._paused = true;
  },

  resume() {
    this._paused = false;
  },

  /**
   * Called from PostureMonitor.tick(). Synchronous and returns nothing on
   * purpose: it must not end up inside PostureMonitor._inFlight, which
   * logoutFirefox() and startFirefox() await on the critical path. A ten-minute
   * install must never be able to block sign-out.
   */
  onTick() {
    if (this._paused || !this._records.size || this._cyclePromise) {
      return;
    }
    if (!Services.felt.isFeltUI()) {
      return;
    }
    if (Date.now() < this._nextCycleAt) {
      return;
    }
    this._cyclePromise = this._cycle()
      .catch(e => lazy.log.error("Remediation cycle failed:", e))
      .finally(() => {
        this._cyclePromise = null;
      });
  },

  /** Resolves when no cycle is in flight. Tests only; never awaited on teardown. */
  idle() {
    return Promise.resolve(this._cyclePromise);
  },

  /**
   * The compliance snapshot for the posture payload. Synchronous, pre-sorted
   * and pre-frozen: DevicePosture.collect() runs on the login path and while
   * the browser is blocked on a token, so it must not do I/O here.
   *
   * @returns {Array<object>}
   */
  posture() {
    try {
      return this._published;
    } catch (e) {
      lazy.log.error("Could not read remediation posture:", e);
      return [];
    }
  },

  /**
   * Rebuilds the published snapshot.
   *
   * Every field here has to change only when something meaningful changed, or
   * PostureMonitor._submitIfChanged turns into _submitAlways. In particular
   * there is deliberately no `checkedAt`: a per-cycle timestamp would differ on
   * every tick and drown real changes. nextAttemptAt is withheld for the same
   * reason -- it carries jitter.
   */
  _publish() {
    const rows = [...this._records.values()]
      .map(r =>
        Object.freeze({
          id: r.id,
          required: r.required,
          installed: r.installed,
          status: r.status,
          remediation: Object.freeze({
            state: r.state,
            attempts: r.attempts,
            lastOutcome: r.lastOutcome,
            lastErrorCode: r.lastErrorCode,
            lastExitCode: r.lastExitCode,
            lastAttemptAt: r.lastAttemptAt,
            blockErrorCode: r.blockErrorCode,
            documentCounter: r.documentCounter,
          }),
        })
      )
      // The console supplies the requirement order, so without this a reshuffle
      // on their side would look like a posture change.
      .sort(compareById);
    this._published = Object.freeze(rows);
  },

  /**
   * The warning the UI should show, or null when nothing needs attention.
   *
   * Picks the first offender in id order rather than the most recently
   * updated one, so the message does not flip between tools depending on
   * which cycle finished last.
   *
   * @returns {{toolId: string, required: string, status: string, state: string}|null}
   */
  currentWarning() {
    const offender = this._published.find(
      r =>
        r.status === "missing" ||
        r.status === "outdated" ||
        r.status === "blocked" ||
        r.status === "unavailable"
    );
    if (!offender) {
      return null;
    }
    return {
      toolId: offender.id,
      required: offender.required,
      status: offender.status,
      state: offender.remediation.state,
    };
  },

  /**
   * Registers the UI callback. Only one listener, set by PostureWarning.init.
   *
   * @param {((warning: object|null) => void)|null} callback
   */
  setWarningListener(callback) {
    this._onWarning = callback;
  },

  _notifyWarning() {
    const warning = this.currentWarning();
    // Fires on transitions only. Every cycle recomputes this, and re-rendering
    // an unchanged bar would reset its dismissed state on a 5-minute tick.
    const key = warning ? JSON.stringify(warning) : "";
    if (key === this._lastWarningKey) {
      return;
    }
    this._lastWarningKey = key;
    this._onWarning?.(warning);
  },

  async _cycle() {
    const userRequested = this._userRequested;
    const now = Date.now();
    this._nextCycleAt = now + testNumberPref(CYCLE_MS_PREF, CYCLE_INTERVAL_MS);

    for (const record of this._records.values()) {
      await this._checkOne(record, Date.now());
    }
    this._publish();
    this._notifyWarning();
    // One-shot: a later unattended attempt must go back to demanding a
    // strictly newer counter.
    if (userRequested) {
      this._userRequested = false;
    }
  },

  async _checkOne(record, now) {
    const entry = lazy.PostureToolCatalog.lookup(record.id);
    const detected = entry
      ? await this._detect(entry)
      : { version: null, failed: false };

    record.installed = detected.version;
    record.status = decideStatus({
      installed: detected.version,
      required: lazy.PostureToolCatalog.normalizeVersion(record.required),
      supported: !!entry,
      probeFailed: detected.failed,
      packageManagerMissing: !!detected.packageManagerMissing,
    });

    if (record.status === "unavailable") {
      // Deliberately consumes no attempt and arms no backoff: spending the
      // budget on something that cannot work until an admin provisions the
      // package manager would lose the ability to retry once they do.
      record.state = "unavailable";
      record.lastErrorCode = "no-package-manager";
      return;
    }

    if (record.status === "compliant") {
      record.state = "idle";
      record.attempts = 0;
      record.nextAttemptAt = 0;
      return;
    }
    if (record.status !== "missing" && record.status !== "outdated") {
      record.state = "idle";
      return;
    }
    // A source we could not trust stays visible as blocked for its own backoff
    // window, rather than being recomputed away by this cycle's detection.
    if (record.blockedUntil && now < record.blockedUntil) {
      record.state = "blocked";
      record.status = "blocked";
      return;
    }
    if (record.attempts >= testNumberPref(MAX_ATTEMPTS_PREF, MAX_ATTEMPTS)) {
      record.state = "exhausted";
      return;
    }
    if (now < record.nextAttemptAt) {
      record.state = "backoff";
      return;
    }
    await this._attempt(record, now);
  },

  /**
   * Resolves a tool binary over the compiled-in directories and reads its
   * version. Never searches $PATH: Subprocess refuses relative paths, and the
   * directory list is part of the build, not of any input.
   *
   * @param {object} entry Per-platform catalog entry.
   * @returns {Promise<{version: string|null, failed: boolean}>}
   */
  async _detect(entry) {
    const { detect } = entry;
    if (detect.kind === "brewFormula") {
      return this._detectBrewFormula(detect);
    }
    let command = null;
    for (const dir of lazy.BIN_DIRS) {
      const candidate = PathUtils.join(dir, detect.bin);
      if (await IOUtils.exists(candidate)) {
        command = candidate;
        break;
      }
    }
    if (!command) {
      return { version: null, failed: false };
    }

    try {
      const { stdout } = await this._run({
        command,
        args: [...detect.args],
        timeoutMs: TOOL_PROBE_TIMEOUT_MS,
        environment: this._environment(),
      });
      const match = detect.parse.exec(stdout);
      if (!match) {
        lazy.log.warn(`Could not parse a version out of ${command}`);
        return { version: null, failed: true };
      }
      return {
        version: lazy.PostureToolCatalog.normalizeVersion(match[1]),
        failed: false,
      };
    } catch (e) {
      lazy.log.error(`Version probe for ${command} failed:`, e);
      return { version: null, failed: true };
    }
  },

  /**
   * Reads a formula's installed version from Homebrew.
   *
   * Answers a narrower question than commandVersion -- "does brew own a
   * compliant copy", not "is the tool the user would run compliant" -- which
   * is the right question for a tool brew is also expected to remediate.
   *
   * @param {object} detect Catalog entry's detect descriptor.
   * @returns {Promise<{version: string|null, failed: boolean, packageManagerMissing?: boolean}>}
   */
  async _detectBrewFormula(detect) {
    let brew = null;
    for (const candidate of lazy.BREW_CANDIDATES) {
      if (await IOUtils.exists(candidate)) {
        brew = candidate;
        break;
      }
    }
    if (!brew) {
      return { version: null, failed: false, packageManagerMissing: true };
    }

    try {
      const { exitCode, stdout } = await this._run({
        command: brew,
        args: ["list", "--versions", detect.formula],
        timeoutMs: BREW_PROBE_TIMEOUT_MS,
        environment: this._environment(),
      });
      // A formula that is not installed prints nothing and exits non-zero;
      // that is "missing", not a failed probe.
      if (exitCode !== 0) {
        return { version: null, failed: false };
      }
      return {
        version: lazy.PostureToolCatalog.parseBrewVersions(
          stdout,
          detect.formula
        ),
        failed: false,
      };
    } catch (e) {
      lazy.log.error(`brew probe for ${detect.formula} failed:`, e);
      return { version: null, failed: true };
    }
  },

  async _attempt(record, now) {
    record.state = "running";
    this._publish();

    let verified;
    try {
      const signed = await this._source().fetch(record.id);
      verified = await lazy.RemediationVerifier.verify(signed, {
        toolId: record.id,
        minVersion: record.required,
        allowSameCounter: this._userRequested,
      });
    } catch (e) {
      // A document we will not run means a broken or hostile *source*, not a
      // broken machine. It must not eat the attempt budget -- a signing outage
      // would otherwise silently exhaust it -- but it must not be retried every
      // cycle either, and the console needs to see it.
      // Deliberately leaves lastOutcome/lastErrorCode/lastExitCode alone:
      // those describe the last attempt that actually ran, and the console
      // still needs to see it. A refusal is a separate event.
      record.state = "blocked";
      record.status = "blocked";
      record.blockErrorCode = e.code ?? "fetch-failed";
      record.blockedUntil = now + nextAttemptDelay(1);
      lazy.log.error(`Refusing to remediate ${record.id}:`, e);
      return;
    }

    record.blockedUntil = 0;
    record.blockErrorCode = null;
    record.attempts += 1;
    record.lastAttemptAt = now;
    this._publish();

    // Spend the counter before spawning, so a crash mid-execution cannot
    // re-enable the same document.
    lazy.RemediationVerifier.acceptCounter(
      record.id,
      verified.manifest.counter
    );
    record.documentCounter = verified.manifest.counter;

    const result = await this._execute(verified);
    record.lastOutcome = result.outcome;
    record.lastErrorCode = result.errorCode;
    record.lastExitCode = result.exitCode;
    record.state = result.outcome === Outcome.SUCCEEDED ? "idle" : "backoff";
    record.nextAttemptAt = now + nextAttemptDelay(record.attempts);
    // Answer "did it work?" promptly rather than at the next full cycle.
    this._nextCycleAt = Math.min(
      this._nextCycleAt,
      now + POST_ATTEMPT_RECHECK_MS
    );
  },

  /**
   * Writes a verified script somewhere only this user can reach and runs it.
   *
   * The bytes were verified in memory and are never re-read from disk, and the
   * directory is created 0700 before anything is written into it, so there is
   * no window in which another local user could substitute the file. The script
   * is mode 0400 and is handed to a compiled-in interpreter rather than being
   * made executable, so no shebang is ever parsed.
   *
   * @param {object} verified A VerifiedRemediation from RemediationVerifier.
   * @returns {Promise<{outcome: string, errorCode: string|null, exitCode: number|null}>}
   */
  async _execute(verified) {
    if (!lazy.RemediationVerifier.isVerified(verified)) {
      throw new Error("refusing to execute an unverified remediation");
    }
    if (!Services.felt.isFeltUI()) {
      throw new Error("remediation may only run in Felt");
    }

    const artifactDir = PathUtils.join(PathUtils.profileDir, ARTIFACT_DIR_NAME);
    await IOUtils.makeDirectory(artifactDir, { permissions: 0o700 });

    const dir = await IOUtils.createUniqueDirectory(
      PathUtils.tempDir,
      "felt-remediation-",
      0o700
    );
    const scriptPath = PathUtils.join(dir, "remediate");
    try {
      await IOUtils.write(scriptPath, verified.script);
      // IOUtils.write has no permissions option, so the file is briefly
      // 0666 & ~umask; the 0700 directory is what closes that window.
      // setPermissions honours the umask unless told not to.
      await IOUtils.setPermissions(scriptPath, 0o400, false);

      const { exitCode, timedOut, stderr } = await this._run({
        command: verified.interpreter,
        args: [scriptPath],
        timeoutMs: verified.timeoutMs,
        workdir: dir,
        environment: this._environment({
          FELT_REMEDIATION_ARTIFACT_DIR: artifactDir,
        }),
      });

      if (timedOut) {
        return {
          outcome: Outcome.TIMEOUT,
          errorCode: "timeout",
          exitCode: null,
        };
      }
      if (exitCode !== 0) {
        // Raw stderr stays in the log: it leaks local paths and usernames, and
        // it embeds temp paths that would differ every attempt and defeat the
        // posture change-gate.
        lazy.log.error(
          `Remediation exited ${exitCode}: ${stderr.slice(0, 512)}`
        );
        return {
          outcome: Outcome.FAILED,
          errorCode: exitCode === 90 ? "no-package-manager" : "nonzero-exit",
          exitCode,
        };
      }
      return { outcome: Outcome.SUCCEEDED, errorCode: null, exitCode: 0 };
    } catch (e) {
      lazy.log.error("Could not run the remediation script:", e);
      return {
        outcome: Outcome.FAILED,
        errorCode: "spawn-failed",
        exitCode: null,
      };
    } finally {
      await IOUtils.remove(dir, { recursive: true, ignoreAbsent: true });
    }
  },

  /**
   * Spawns a child, drains both pipes concurrently and bounds the wait.
   *
   * Subprocess has no stdin option -- stdin is always a pipe -- so it is closed
   * immediately or a script that reads it would hang until the timeout. Both
   * output pipes are drained while the child runs rather than after it exits,
   * because a child that fills a pipe would otherwise block forever.
   *
   * @param {object} options
   * @param {string} options.command Absolute path of the program to spawn.
   * @param {string[]} options.args Argument vector, excluding argv[0].
   * @param {number} options.timeoutMs Upper bound before the child is killed.
   * @param {string} [options.workdir] Working directory for the child.
   * @param {object} options.environment Complete environment; not appended to.
   * @returns {Promise<{exitCode: number|null, stdout: string, stderr: string, timedOut: boolean}>}
   */
  async _run({ command, args, timeoutMs, workdir, environment }) {
    const proc = await lazy.Subprocess.call({
      command,
      arguments: args,
      workdir,
      environment,
      environmentAppend: false,
      stderr: "pipe",
    });
    await proc.stdin.close();

    let timedOut = false;
    const timer = lazy.setTimeout(() => {
      timedOut = true;
      proc.kill(TERM_GRACE_MS);
    }, timeoutMs);

    const drain = async pipe => {
      let out = "";
      let chunk;
      while ((chunk = await pipe.readString())) {
        if (out.length < MAX_CAPTURE_BYTES) {
          out += chunk;
        }
      }
      return out;
    };

    try {
      const [stdout, stderr] = await Promise.all([
        drain(proc.stdout),
        drain(proc.stderr),
      ]);
      const { exitCode } = await proc.wait();
      return { exitCode, stdout, stderr, timedOut };
    } finally {
      lazy.clearTimeout(timer);
    }
  },

  /**
   * A deterministic environment. Not a privilege boundary -- Felt runs as the
   * user, who already controls their own environment -- but probe output is
   * locale-dependent and Homebrew reads a lot of HOMEBREW_* variables, so an
   * inherited environment makes results irreproducible.
   *
   * @param {object} [extra]
   * @returns {object}
   */
  _environment(extra = {}) {
    return {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: Services.env.get("HOME"),
      USER: Services.env.get("USER"),
      LANG: "C",
      NONINTERACTIVE: "1",
      HOMEBREW_NO_ANALYTICS: "1",
      HOMEBREW_NO_COLOR: "1",
      HOMEBREW_NO_ENV_HINTS: "1",
      ...extra,
    };
  },

  _source() {
    const dir = lazy.isTesting()
      ? Services.prefs.getStringPref(LOCAL_SOURCE_DIR_PREF, "")
      : "";
    if (!dir) {
      throw new Error("no remediation source is configured");
    }
    return new lazy.LocalFileSource(dir);
  },

  /** Test-only view of the internal records. */
  testingOnly_getState() {
    if (!lazy.isTesting()) {
      throw new Error("testingOnly_getState() outside testing");
    }
    return [...this._records.values()].map(r => ({ ...r }));
  },

  /** Test-only: forget every record and schedule. */
  testingOnly_reset() {
    if (!lazy.isTesting()) {
      throw new Error("testingOnly_reset() outside testing");
    }
    this._records = new Map();
    this._nextCycleAt = 0;
    this._paused = false;
    this._published = Object.freeze([]);
  },
};
