#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import os
import sys
import time

sys.path.append(os.path.dirname(__file__))

from base_test import Environment
from felt_tests import FeltTests

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "remediation")

# Unsatisfiable, so the device can never become compliant on its own. Under
# "block" that means the browser is held back indefinitely, which is exactly
# the situation the Fix now button and the relax-by-directive path exist for.
SEEDED = [{"id": "curl", "min_version": "999.0.0"}]


class FeltPostureBlock(FeltTests):
    """"block" enforcement: the browser must not launch while the device is
    non-compliant, the user must be offered a way to act, and an admin must be
    able to rescue the device by changing the directive."""

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        # The browser is deliberately never started, so the shared teardown
        # must not go looking for it.
        self._manually_closed_child = True

    def test_posture_block(self):
        driver = self.get_driver(Environment.FELT)
        driver.set_prefs(
            {
                "enterprise.felt_tests.should_not_close_window": True,
                "enterprise.posture.remediation.local_dir": FIXTURE_DIR,
                "enterprise.posture.remediation.cycle_ms": 250,
                "enterprise.posture.remediation.gate_poll_ms": 500,
                "enterprise.posture.remediation.seed_requirements": json.dumps(
                    SEEDED
                ),
            },
            default_branch=True,
        )

        # Sent by the console, not set as a pref: an absent enforcement field
        # deliberately resets to "warn", so a pref would be overwritten at
        # login. That also means this exercises the real directive path.
        self.posture_enforcement.value = "block"

        # Leave a spent counter behind, as a reused ./mach run profile would.
        # Without the seeded path clearing it, this session's first attempt
        # would be refused as a replay and the user would be met with
        # "couldn't be verified" and nothing having been tried.
        self._felt_script(
            """
            const [resolve] = arguments;
            Services.prefs.setStringPref(
              "enterprise.posture.remediation.counters",
              JSON.stringify({ curl: 5 })
            );
            resolve(true);
            """
        )

        super().run_felt_base()

        self.run_browser_is_held_back()
        self.run_warning_is_not_occluded()
        self.run_fix_now_is_offered()
        attempts = self.run_fix_now_retries()
        self.run_relaxing_the_directive_releases_the_gate(attempts)

    def _felt_script(self, script):
        driver = self.get_driver(Environment.FELT)
        driver.set_context("chrome")
        return driver.execute_async_script(script)

    def _browser_ready(self):
        return self._felt_script(
            """
            const [resolve] = arguments;
            const { isFeltFirefoxWindowReady } = ChromeUtils.importESModule(
              "chrome://felt/content/FeltProcessParent.sys.mjs"
            );
            resolve(!!isFeltFirefoxWindowReady());
            """
        )

    def _record(self):
        records = json.loads(
            self._felt_script(
                """
                const [resolve] = arguments;
                const { PostureRemediation } = ChromeUtils.importESModule(
                  "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
                );
                resolve(JSON.stringify(PostureRemediation.testingOnly_getState()));
                """
            )
            or "[]"
        )
        return next((r for r in records if r["id"] == "curl"), None)

    def run_browser_is_held_back(self):
        """The whole point: no browser for a non-compliant device."""
        # Give the gate several cycles to have done everything it is going to.
        for _ in range(10):
            time.sleep(0.5)
            assert not self._browser_ready(), (
                "the browser must not launch while enforcement is 'block' and "
                f"the device is non-compliant: {self._record()}"
            )
        record = self._record()
        assert record, "curl should be configured"
        assert record["status"] != "compliant", record

        # The stale counter planted above must have been cleared by the seeded
        # path, or nothing would have been attempted at all.
        assert record["attempts"] >= 1, (
            "a spent counter from a previous session should not stop this one "
            f"from attempting: {record}"
        )
        assert record["blockErrorCode"] != "replay-rejected", (
            f"the stale counter should have been cleared: {record}"
        )
        self._logger.info(f"held back with: {record}")

    def run_warning_is_not_occluded(self):
        """The warning has to be somewhere the user can actually see it.

        Submitting the email hides every message bar and swaps the card to the
        SSO browser. Felt normally goes to the background from there because
        the browser starts, so nothing undid it; under "block" that left the
        user staring at a finished SSO pane. Asserting the bar's is-hidden
        class is not enough -- it was already absent when this was broken --
        so this pins the pane being put away."""
        state = json.loads(
            self._felt_script(
                """
                const [resolve] = arguments;
                const sso = document.querySelector(".felt-login__sso");
                const bar = document.querySelector(".felt-posture-warning-messages");
                resolve(JSON.stringify({
                  ssoHidden: sso.classList.contains("is-hidden"),
                  barHidden: bar.classList.contains("is-hidden"),
                }));
                """
            )
        )
        assert state["ssoHidden"], (
            "the spent SSO pane should be put away once the gate holds, or the "
            f"warning is rendered behind it: {state}"
        )
        assert not state["barHidden"], state
        self._logger.info(f"warning not occluded: {state}")

    def run_fix_now_is_offered(self):
        """A blocked user needs something to press."""
        state = json.loads(
            self._felt_script(
                """
                const [resolve] = arguments;
                const bar = document.querySelector(".felt-posture-warning-messages");
                const btn = document.getElementById("felt-posture-remediate");
                const { PostureRemediation } = ChromeUtils.importESModule(
                  "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
                );
                document.l10n.translateElements([bar, btn].filter(Boolean)).then(() => {
                  resolve(JSON.stringify({
                    barHidden: bar.classList.contains("is-hidden"),
                    hasButton: !!btn,
                    buttonHidden: btn ? btn.classList.contains("is-hidden") : null,
                    label: btn ? btn.getAttribute("label") : null,
                    enforcement: PostureRemediation.enforcement(),
                    canRemediate: PostureRemediation.canRemediateNow(),
                  }));
                }, e => resolve(JSON.stringify({ error: String(e) })));
                """
            )
        )
        assert "error" not in state, state
        assert not state["barHidden"], f"the warning should be visible: {state}"
        assert state["hasButton"], f"the Fix now button should exist: {state}"
        assert not state["buttonHidden"], (
            f"the button must be offered while blocked: {state}"
        )
        assert state["label"], (
            f"the button label did not resolve, so its Fluent id is missing: {state}"
        )
        self._logger.info(f"fix-now offered: {state}")

    def run_fix_now_retries(self):
        """Clicking it re-runs the current document.

        The counter is already spent by the gate's first attempt, so an
        unattended retry would be refused as a replay. A user-requested one is
        allowed to re-run the same document -- never an older one -- which is
        what makes the button do something rather than report replay-rejected.
        """
        before = self._record()["attempts"]

        self._felt_script(
            """
            const [resolve] = arguments;
            document.getElementById("felt-posture-remediate").click();
            resolve(true);
            """
        )

        for _ in range(40):
            record = self._record()
            if record["attempts"] > before:
                break
            time.sleep(0.5)
        else:
            assert False, f"Fix now did not run anything: {self._record()}"

        assert record["lastExitCode"] == 0, (
            f"the user-requested run should have executed cleanly: {record}"
        )
        assert record["blockErrorCode"] != "replay-rejected", (
            f"a user-requested retry must not be refused as a replay: {record}"
        )
        self._logger.info(f"fix-now ran: attempts {before} -> {record['attempts']}")
        return record["attempts"]

    def run_relaxing_the_directive_releases_the_gate(self, attempts):
        """An admin must be able to rescue a device that cannot comply.

        This is what makes 'block' safe to ship: the gate keeps token refreshes
        running, so a directive that relaxes enforcement arrives and releases
        the launch. Simulated here by writing the pref the directive writes."""
        assert not self._browser_ready(), "still expected to be held back"

        self._felt_script(
            """
            const [resolve] = arguments;
            Services.prefs.setStringPref(
              "enterprise.posture.remediation.enforcement", "warn");
            resolve(true);
            """
        )

        for _ in range(60):
            if self._browser_ready():
                break
            time.sleep(0.5)
        else:
            assert False, (
                "relaxing enforcement should have released the gate; "
                f"state: {self._record()}"
            )

        record = self._record()
        assert record["attempts"] >= attempts, (
            f"the attempt budget should not have been reset: {record}"
        )
        self._logger.info("gate released after enforcement relaxed")
        self.connect_child_browser()
        self._manually_closed_child = False
