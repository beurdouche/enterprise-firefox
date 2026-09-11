/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  ConsoleClient: "resource://gre/modules/enterprise/ConsoleClient.sys.mjs",
});

function getInternalKeyToken() {
  return Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
}

// PK11_CheckUserPassword logs the token out before checking the password, so
// this must only ever be called with the console secret.
function loginWithSecret(secret) {
  const sdr = Cc["@mozilla.org/security/sdr;1"].getService(
    Ci.nsISecretDecoderRing
  );
  return sdr.login(secret) && getInternalKeyToken().isLoggedIn;
}

export const EnterpriseStorageEncryption = {
  _secretPromise: null,
  _reloginPromise: null,

  /**
   * Whether the internal token's password is the console-managed primary
   * secret in this process.
   */
  isManaged() {
    return (
      AppConstants.MOZ_ENTERPRISE &&
      Services.prefs.getBoolPref(
        "security.storage.encryption.enabled",
        false
      ) &&
      !Services.felt?.isFeltUI()
    );
  },

  async init() {
    if (this.isManaged()) {
      await this.load();
    }
  },

  /**
   * Fetches the primary secret from the console. Concurrent callers share a
   * single request and the secret is not retained once they have it.
   *
   * @returns {Promise<string>} the primary secret
   */
  fetchPrimarySecret() {
    if (!this._secretPromise) {
      // The API returns { data: "secret_value" }.
      this._secretPromise = lazy.ConsoleClient.getPrimarySecret()
        .then(payload => {
          const secret = payload?.data;
          if (!secret) {
            throw new Error("No primary secret in payload");
          }
          return secret;
        })
        .finally(() => {
          this._secretPromise = null;
        });
    }
    return this._secretPromise;
  },

  /**
   * Logs the internal token back in with the console secret after it was
   * locked during the session. Never prompts the user.
   *
   * @returns {Promise<boolean>} whether the token can be used without a
   *   password prompt
   */
  async relogin() {
    if (!this.isManaged()) {
      return false;
    }
    const token = getInternalKeyToken();
    if (!token.hasPassword || token.isLoggedIn) {
      return true;
    }
    if (!this._reloginPromise) {
      this._reloginPromise = (async () => {
        try {
          return loginWithSecret(await this.fetchPrimarySecret());
        } catch (e) {
          console.error("EnterpriseStorageEncryption.relogin: failed", e);
          return false;
        }
      })().finally(() => {
        this._reloginPromise = null;
      });
    }
    return this._reloginPromise;
  },

  async load() {
    // A managed browser that cannot unlock its encrypted storage must not
    // keep running: it would prompt for a primary secret the user does not
    // know, or operate against a profile it cannot decrypt. Fail the launch
    // with a dedicated exit code (Bug 2021342), mirroring the launcher-side
    // abort in FeltProcessParent.
    const fail = (msg, e) => {
      console.error(
        `EnterpriseStorageEncryption.load: ${msg}${e ? ": " + e : ""}`
      );
      Services.startup.quit(
        Ci.nsIAppStartup.eForceQuit,
        Ci.nsIFelt.FeltEncryptionExitCode_SdrTokenUnlockFailed
      );
    };

    let primarySecret;
    try {
      primarySecret = await this.fetchPrimarySecret();
    } catch (e) {
      fail("Failed to get primary secret", e);
      return;
    }

    let pk11token;
    try {
      pk11token = getInternalKeyToken();
    } catch (e) {
      fail("Error getting PK11 token", e);
      return;
    }

    // Ensure the internal token's password is the primarySecret.
    if (!pk11token.hasPassword) {
      try {
        await pk11token.changePassword("", primarySecret);
      } catch (e) {
        fail("Failed to set the primary secret on the token", e);
        return;
      }
    }

    // changePassword does not authenticate the session, so log in
    // explicitly and verify.
    try {
      if (!loginWithSecret(primarySecret)) {
        fail("Internal token not logged in after unlock");
      }
    } catch (e) {
      fail("SDR login failed", e);
    }
  },
};
