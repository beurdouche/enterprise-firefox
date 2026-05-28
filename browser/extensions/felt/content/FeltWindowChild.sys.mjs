/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  createEnterpriseLogger:
    "resource:///modules/enterprise/EnterpriseCommon.sys.mjs",
});

ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return lazy.createEnterpriseLogger("FeltWindowChild");
});

/**
 *
 */
export class FeltWindowChild extends JSWindowActorChild {
  #tokensSent = false;
  #submitHooked = false;

  actorCreated() {
    this.processActor = ChromeUtils.domProcessChild.getActor("FeltProcess");
  }

  handleEvent(event) {
    if (event.type === "DOMContentLoaded") {
      // Two pages we care about: the SSO login form, and the SSO callback
      // that carries the token_data div. The actor's match patterns route
      // both to us; dispatch by path.
      const path = this.document.location?.pathname || "";
      if (path.endsWith("/sso/login")) {
        this.#hookPasswordCapture(this.document);
      } else {
        this.#extractAndSendTokens(event.target);
      }
      return;
    }
    if (event.type === "submit") {
      this.#capturePasswordAndForward(event);
    }
  }

  receiveMessage(message) {
    if (message.name === "ExtractTokens") {
      return this.#extractAndSendTokens(this.document);
    }
    return false;
  }

  /**
   * Attach a single submit listener to the SSO login document. We use the
   * capture phase so we see the event before any page script can clear the
   * form value. The listener stays for the lifetime of the page; on
   * subsequent submits (e.g. retries after a wrong password) the latest
   * value is what gets forwarded.
   *
   * @param {Document} doc
   */
  #hookPasswordCapture(doc) {
    if (this.#submitHooked) {
      return;
    }
    this.#submitHooked = true;
    doc.addEventListener("submit", this, /* useCapture */ true);
  }

  /**
   * Pull the password and email out of the submitted form and ship
   * them to the parent process for stretching. We deliberately do not
   * log either value, do not store them on `this`, and drop our local
   * references promptly. Failure to find a password input is silent —
   * the form may legitimately be something else.
   *
   * The actual PBKDF2 derivation happens in the parent process so the
   * raw password never crosses the actor-IPC boundary into the spawned
   * Firefox.
   *
   * @param {SubmitEvent} event
   */
  #capturePasswordAndForward(event) {
    let form = event.target;
    if (!form || form.tagName !== "FORM") {
      return;
    }
    let pw = form.querySelector('input[type="password"]');
    if (!pw || !pw.value) {
      return;
    }
    let password = pw.value;
    // Best-effort: locate the email field on the same form so we can
    // use it as the PBKDF2 salt downstream. Fall back to "" if not
    // found; the salt is still domain-separated by a fixed prefix in
    // FeltProcessParent.
    let emailInput =
      form.querySelector('input[type="email"]') ||
      form.querySelector('input[name="email"]') ||
      form.querySelector('input[name="username"]');
    let email = emailInput?.value || "";
    this.processActor.sendAsyncMessage("FeltChild:SSOPasswordCaptured", {
      password,
      email,
    });
    // Drop local references (JS GC still owns until reclamation).
    password = null;
    email = null;
  }

  #extractAndSendTokens(doc) {
    if (this.#tokensSent) {
      return true;
    }

    const tokenData = doc.querySelector("#token_data");
    if (!tokenData) {
      return false;
    }

    lazy.log.debug("FeltWindowChild: Extracting token data");
    const consoleTokenData = JSON.parse(tokenData.textContent);
    if (
      consoleTokenData &&
      "access_token" in consoleTokenData &&
      consoleTokenData.access_token !== ""
    ) {
      lazy.log.debug("FeltWindowChild: Sending token data to start Firefox");
      this.#tokensSent = true;
      this.processActor.sendAsyncMessage(
        "FeltChild:StartFirefox",
        consoleTokenData
      );
      return true;
    }
    return false;
  }
}
