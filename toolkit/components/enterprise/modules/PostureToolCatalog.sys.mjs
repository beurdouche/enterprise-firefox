/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * How posture probes each tool the console can require.
 *
 * Detection is compiled in and the console only selects entries by id. The
 * remediation *action* comes from a signed document, but the decision about
 * whether a machine is compliant must not: a stale or hostile document that
 * could also answer "compliant" would defeat the point of checking.
 *
 * Nothing here does I/O, holds state, or reads a pref, so it is the one file a
 * reviewer has to read to know what can be probed.
 */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

/** Absolute directories a tool binary may be resolved from, in order. */
export const BIN_DIRS = Object.freeze([
  // Homebrew prefixes first, so we report the version the user would actually
  // get rather than a shadowed system copy.
  "/opt/homebrew/bin",
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
]);

const CATALOG = Object.freeze(
  Object.assign(Object.create(null), {
    curl: Object.freeze({
      id: "curl",
      platforms: Object.freeze({
        macosx: Object.freeze({
          detect: Object.freeze({
            kind: "commandVersion",
            bin: "curl",
            args: Object.freeze(["--version"]),
            parse: /^curl (\S+)/m,
          }),
        }),
      }),
    }),
  })
);

const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const VERSION_RE = /^[0-9A-Za-z._+-]{1,32}$/;

export const PostureToolCatalog = {
  /**
   * Whether the build knows this id at all, on any platform. An id that exists
   * but has no arm for this platform still resolves, so posture can report it
   * as unsupported rather than silently dropping it.
   *
   * @param {string} id
   * @returns {boolean}
   */
  isKnownId(id) {
    return typeof id === "string" && CATALOG[id] !== undefined;
  },

  /**
   * The per-platform entry for an id, or null when the build does not know the
   * id or has no arm for the running platform.
   *
   * @param {string} id
   * @param {string} [platform]
   * @returns {object|null}
   */
  lookup(id, platform = AppConstants.platform) {
    if (!this.isKnownId(id)) {
      return null;
    }
    return CATALOG[id].platforms[platform] ?? null;
  },

  /**
   * Normalizes a console-supplied requirement, or null if it is unusable.
   *
   * @param {object} entry Raw `{ id, min_version }` from the console.
   * @returns {{id: string, minVersion: string}|null}
   */
  validateRequirement(entry) {
    if (!entry || typeof entry !== "object") {
      return null;
    }
    const { id, min_version: minVersion } = entry;
    if (typeof id !== "string" || !ID_RE.test(id) || !this.isKnownId(id)) {
      return null;
    }
    if (typeof minVersion !== "string" || !VERSION_RE.test(minVersion)) {
      return null;
    }
    return { id, minVersion };
  },

  /**
   * Rewrites a version string into something nsIVersionComparator orders the
   * way Homebrew means it, or null when it cannot be compared at all.
   *
   * The `_N` case is the reason this exists. nsVersionComparator documents
   * "any string is before no string", so `1.2.3_1` compares *less* than
   * `1.2.3` -- a formula at revision 1 would read as older than the same
   * formula at no revision, be permanently non-compliant, and loop the
   * remediator forever. Rewriting the suffix to `.N` keeps the intended order.
   *
   * A version we cannot parse returns null, which the caller must treat as
   * "unknown" rather than "too old", or a HEAD build loops the same way.
   *
   * @param {string} raw
   * @returns {string|null}
   */
  normalizeVersion(raw) {
    if (typeof raw !== "string") {
      return null;
    }
    const trimmed = raw.trim().replace(/^v/, "");
    if (!trimmed || trimmed.length > 32 || trimmed.includes("HEAD")) {
      return null;
    }
    const match = /^[0-9][0-9A-Za-z.]*(_[0-9]+)?/.exec(trimmed);
    if (!match) {
      return null;
    }
    return match[0].replace(/_([0-9]+)$/, ".$1");
  },
};
