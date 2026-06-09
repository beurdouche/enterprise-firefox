#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from felt_tests import PRIMARY_SECRET, FeltTests


class FeltBrowserStorageEncryption(FeltTests):
    # Enable the enterprise SQLite-encryption pref in the child profile's
    # user.js BEFORE the child browser launches (written by
    # _apply_marionette_and_local_prefs_to_child_profile), so the condition on
    # BrowserGlue's EnterpriseStorageEncryption.load idle task
    # (MOZ_ENTERPRISE && security.storage.encryption.enabled) is already true
    # when the startup idle tasks are scheduled. Setting it over Marionette
    # after launch would be too late.
    EXTRA_CHILD_PREFS = {
        "security.storage.encryption.enabled": True,
    }

    def await_child_startup_idle_tasks(self):
        """Block until the child browser has finished its startup idle tasks,
        which is where EnterpriseStorageEncryption.load runs."""
        self._child_driver.set_context("chrome")
        try:
            self._child_driver.execute_async_script(
                """
                const callback = arguments[arguments.length - 1];
                const { BrowserInitState } = ChromeUtils.importESModule(
                    "resource:///modules/BrowserGlue.sys.mjs"
                );
                BrowserInitState.startupIdleTaskPromise.then(() => callback(true));
                """,
            )
        finally:
            self._child_driver.set_context("content")

    def get_child_token_state(self, secret):
        """Read the internal-key-token state via the surviving
        @mozilla.org/security/internalkeytoken;1 / nsIPKCS11Token contract.

        The removed @mozilla.org/security/pk11tokendb;1 / nsIPK11TokenDB
        contract must never be used here: it throws
        NS_ERROR_FACTORY_NOT_REGISTERED in this tree (that removal is the very
        bug under test)."""
        self._child_driver.set_context("chrome")
        try:
            return self._child_driver.execute_script(
                """
                const secret = arguments[0];
                const token = Cc[
                    "@mozilla.org/security/internalkeytoken;1"
                ].createInstance(Ci.nsIPKCS11Token);
                // checkPassword() logs the token out on a wrong password but
                // does not change hasPassword, so this snapshot is consistent.
                let checkOk = null;
                let checkError = null;
                try {
                    checkOk = token.checkPassword(secret);
                } catch (e) {
                    checkError = String(e);
                }
                return {
                    hasPassword: token.hasPassword,
                    needsLogin: token.needsLogin(),
                    needsUserInit: token.needsUserInit,
                    checkOk,
                    checkError,
                };
                """,
                script_args=[secret],
            )
        finally:
            self._child_driver.set_context("content")

    def get_child_storage_encryption_errors(self):
        """Return any console messages emitted by EnterpriseStorageEncryption.load.

        Logged for diagnostics only; the token-state assertions are the
        authoritative behavioral check (console-API capture in
        getMessageArray is best-effort)."""
        self._child_driver.set_context("chrome")
        try:
            return self._child_driver.execute_script(
                """
                const msgs = Services.console.getMessageArray() || [];
                return msgs
                    .map(m => (m.message !== undefined ? m.message : String(m)))
                    .filter(s => s.includes("EnterpriseStorageEncryption.load"));
                """
            )
        finally:
            self._child_driver.set_context("content")

    def run_storage_encryption_startup(self):
        # Connect to the FELT-launched child browser (the real enterprise
        # Firefox that runs BrowserGlue's startup idle tasks).
        self.connect_child_browser(capabilities={"unhandledPromptBehavior": "ignore"})
        self.await_child_startup_idle_tasks()

        errors = self.get_child_storage_encryption_errors()
        state = self.get_child_token_state(PRIMARY_SECRET)
        self._logger.info(f"EnterpriseStorageEncryption.load messages: {errors}")
        self._logger.info(f"internal key token state: {state}")

        # The transparent unlock must have configured a primary secret on the
        # internal key token. hasPassword is the canonical "a primary password
        # is set" check (PK11_NeedLogin && !PK11_NeedUserInit) and is
        # independent of current login state.
        assert state["checkError"] is None, (
            f"checkPassword threw unexpectedly: {state['checkError']}"
        )
        assert state["hasPassword"], (
            "Internal key token should have a primary secret configured after "
            "the transparent-unlock startup task ran"
        )
        # The configured secret must be exactly the one the console served,
        # proving the startup task drove the unlock end-to-end.
        assert state["checkOk"] is True, (
            "checkPassword(primarySecret) should be true: the transparent "
            "unlock must have set the token password to the served secret"
        )
