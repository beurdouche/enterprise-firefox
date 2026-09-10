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
const BUTTON_ID = "felt-posture-remediate";
const SSO_PANE_SELECTOR = ".felt-login__sso";

/**
 * Picks the strings for a warning. Kept here rather than in
 * PostureRemediation so the state machine never has to know about l10n ids.
 *
 * @param {object} warning From PostureRemediation.currentWarning().
 * @returns {{titleId: string, messageId: string, args: object}}
 */
function describe(warning) {
  // A detector that found the offender itself (brewOutdated) names a package
  // rather than the requirement, and there is no version to quote.
  const args = {
    tool: warning.detail ?? warning.toolId,
    version: warning.required,
  };

  if (warning.state === "awaiting-action") {
    return {
      titleId: "felt-warning-title-posture-tool-outdated",
      messageId: "felt-error-warning-posture-awaiting-action",
      args,
    };
  }
  if (warning.state === "running") {
    return {
      titleId: "felt-warning-title-posture-updating",
      messageId: "felt-error-warning-posture-updating",
      args,
    };
  }
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
  if (warning.status === "unavailable") {
    return {
      titleId: "felt-warning-title-posture-unavailable",
      messageId: "felt-error-warning-posture-unavailable-contact-admin",
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
    messageId: warning.detail
      ? "felt-error-warning-posture-package-outdated"
      : "felt-error-warning-posture-tool-outdated",
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
    const button = doc.getElementById(BUTTON_ID);
    if (button) {
      button.addEventListener("click", () => this._onRemediateClicked(button));
    }
    lazy.PostureRemediation.setWarningListener(warning => this.set(warning));
    lazy.PostureRemediation.setGateListener(held => this._onGateChanged(held));
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
    lazy.PostureRemediation.setGateListener(null);
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

  /**
   * Runs remediation because the user asked. Disables the button for the
   * duration so a second click cannot start a concurrent run -- the state
   * machine is single-flight anyway, but a button that looks live while
   * nothing happens is worse than one that looks busy.
   *
   * @param {Element} button
   */
  async _onRemediateClicked(button) {
    button.disabled = true;
    try {
      await lazy.PostureRemediation.remediateNow();
    } catch (e) {
      lazy.log.error("User-requested remediation failed:", e);
    } finally {
      button.disabled = false;
      this._render();
    }
  },

  /**
   * Puts the window into a state where the warning can be seen, once we know
   * the browser is being held back.
   *
   * Submitting the email hides every message bar (FeltErrorReport.reset) and
   * swaps the card to the SSO browser. Normally Felt goes to the background
   * from there because the browser starts, so nothing ever needed to undo it.
   * Under "block" the browser is not coming, and the user would otherwise be
   * left looking at a finished SSO pane with no explanation.
   *
   * @param {boolean} held
   */
  _onGateChanged(held) {
    lazy.log.info(
      `Launch gate ${held ? "holding" : "released"}; Felt window ` +
        `${this._doc ? "present" : "absent"}`
    );
    if (!this._doc || !held) {
      return;
    }
    this._doc.querySelector(SSO_PANE_SELECTOR)?.classList.add("is-hidden");
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
    const button = this._doc.getElementById(BUTTON_ID);
    if (!this._pending) {
      lazy.log.info("Posture warning: nothing to show, hiding the bar.");
      bar.classList.add("is-hidden");
      button?.classList.add("is-hidden");
      return;
    }

    const { titleId, messageId, args } = describe(this._pending);
    this._doc.l10n.setAttributes(bar, titleId, args);
    const details = bar.querySelector(DETAILS_SELECTOR);
    if (details) {
      this._doc.l10n.setAttributes(details, messageId, args);
    }
    // The action is offered when the launch is being held back, which is the
    // case where the user has no other way forward. In warn mode the browser
    // is about to appear anyway, so a button would be pointless and would
    // likely be clicked after the bar had gone.
    const running = this._pending.state === "running";
    const offerAction =
      lazy.PostureRemediation.enforcement() === "block" &&
      lazy.PostureRemediation.canRemediateNow();
    button?.classList.toggle("is-hidden", !offerAction);
    if (button) {
      // Work in progress is the whole reason this is visible; leaving the
      // button live would invite a second click at the one moment nothing
      // would come of it.
      button.disabled = running;
    }

    bar.classList.remove("is-hidden");
    lazy.log.info(
      `Showing posture warning ${titleId} for ${args.tool}` +
        `${offerAction ? " with a remediate action" : ""}`
    );
  },

  /** Test-only view of what would be rendered. */
  testingOnly_getPending() {
    return this._pending;
  },
};
