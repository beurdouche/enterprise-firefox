/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Shows the posture-compliance warning in the FELT login window.
 *
 * Owns one message bar in the login DOM and drives it by selector off the
 * document passed to init(), the way CaptivePortal owns the portal banner. It
 * uses its own bar rather than the updates one: that element's heading is set
 * by Updates.displayLoginStateWithUpdateWarning, so sharing it would let a
 * posture warning and an update warning silently overwrite each other.
 *
 * The pending warning lives on the module, not on the document, because
 * PostureRemediation can raise one while FELT is backgrounded and windowless.
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  createEnterpriseLogger:
    "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
  PostureRemediation:
    "resource://gre/modules/enterprise/PostureRemediation.sys.mjs",
});

ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return lazy.createEnterpriseLogger("PostureWarning");
});

const BAR_SELECTOR = ".felt-posture-warning-messages";
const DETAILS_SELECTOR = ".felt-browser-error-details";

/**
 * Picks the strings for a warning. Kept here rather than in
 * PostureRemediation so the state machine never has to know about l10n ids.
 *
 * @param {object} warning From PostureRemediation.currentWarning().
 * @returns {{titleId: string, messageId: string, args: object}}
 */
function describe(warning) {
  const args = { tool: warning.toolId, version: warning.required };

  if (warning.state === "blocked") {
    return {
      titleId: "felt-warning-title-posture-blocked",
      messageId: "felt-error-warning-posture-blocked-contact-admin",
      args,
    };
  }
  if (warning.state === "exhausted") {
    return {
      titleId: "felt-warning-title-posture-remediation-failed",
      messageId: "felt-error-warning-posture-remediation-failed-contact-admin",
      args,
    };
  }
  if (warning.status === "missing") {
    return {
      titleId: "felt-warning-title-posture-tool-missing",
      messageId: "felt-error-warning-posture-tool-missing",
      args,
    };
  }
  return {
    titleId: "felt-warning-title-posture-tool-outdated",
    messageId: "felt-error-warning-posture-tool-outdated",
    args,
  };
}

export const PostureWarning = {
  _doc: null,
  _pending: null,

  /**
   * @param {Document} doc - The FELT window document.
   */
  init(doc) {
    this._doc = doc;
    lazy.PostureRemediation.setWarningListener(warning => this.set(warning));
    // Pull the current state rather than waiting for the next transition: the
    // window may well have opened after the warning was raised.
    this._pending = lazy.PostureRemediation.currentWarning();
    this._render();
    doc.defaultView.addEventListener("unload", () => this.uninit(), {
      once: true,
    });
  },

  uninit() {
    lazy.PostureRemediation.setWarningListener(null);
    this._doc = null;
  },

  /**
   * @param {object|null} warning
   */
  set(warning) {
    this._pending = warning;
    this._render();
  },

  clear() {
    this.set(null);
  },

  /**
   * Re-renders the bar. Needed because FeltErrorReport.reset() hides every bar
   * in the container, so without this the warning disappears when the user
   * submits their email and never returns if they press Back.
   */
  refresh() {
    this._render();
  },

  _render() {
    // No window: _pending keeps the warning until one opens.
    if (!this._doc) {
      return;
    }
    const bar = this._doc.querySelector(BAR_SELECTOR);
    if (!bar) {
      lazy.log.error(`No ${BAR_SELECTOR} in the FELT document`);
      return;
    }
    if (!this._pending) {
      bar.classList.add("is-hidden");
      return;
    }

    const { titleId, messageId, args } = describe(this._pending);
    this._doc.l10n.setAttributes(bar, titleId, args);
    const details = bar.querySelector(DETAILS_SELECTOR);
    if (details) {
      this._doc.l10n.setAttributes(details, messageId, args);
    }
    bar.classList.remove("is-hidden");
    lazy.log.debug(`Showing posture warning ${titleId} for ${args.tool}`);
  },

  /** Test-only view of what would be rendered. */
  testingOnly_getPending() {
    return this._pending;
  },
};
