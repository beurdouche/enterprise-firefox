#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import os
import sys
import time

sys.path.append(os.path.dirname(__file__))

import requests
from base_test import Environment
from felt_tests import FeltTests

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "remediation")

# Unsatisfiable on every host, so the machine is deterministically
# non-compliant and the remediation path always runs. The signed fixture
# declares the same targetVersion, because the verifier refuses a document
# that would lower the bar the console set.
REQUIRED_TOOLS = [{"id": "curl", "min_version": "999.0.0"}]


class FeltPostureRemediation(FeltTests):
    """End to end: detect a non-compliant tool, verify a signed remediation
    document, run it, and report the outcome to the console.

    The remediation payload is the signed script itself, so a pass exercises
    fetch -> verify -> write -> execute -> report rather than any one piece."""

    def test_posture_remediation(self):
        driver = self.get_driver(Environment.FELT)
        driver.set_prefs(
            {
                # Device posture is collected in the FELT chrome context, and
                # remediation runs there too.
                "enterprise.felt_tests.should_not_close_window": True,
                "enterprise.posture.remediation.local_dir": FIXTURE_DIR,
                # Numbers only. A test pref must never name a program or argv.
                "enterprise.posture.remediation.cycle_ms": 250,
                "enterprise.posture.remediation.backoff_base_ms": 500,
            },
            default_branch=True,
        )
        # Has to be set before login: the directive rides the SSO callback.
        self.posture_required_tools.value = json.dumps(REQUIRED_TOOLS)

        super().run_felt_base()
        # The shared teardown drives the managed browser, so it has to be
        # connected even though every assertion here runs in the FELT context.
        self.connect_child_browser()

        self.run_directive_reaches_felt()
        state = self.run_remediation_runs()
        self.run_artifact_written()
        self.run_replay_is_refused()
        self.run_warning_is_shown()
        self.run_reported_to_console()
        self.run_change_gate_is_not_defeated()
        return state

    def _felt_script(self, script):
        driver = self.get_driver(Environment.FELT)
        driver.set_context("chrome")
        return driver.execute_async_script(script)

    def _remediation_state(self):
        return self._felt_script(
            """
            const [resolve] = arguments;
            const { PostureRemediation } = ChromeUtils.importESModule(
              "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
            );
            resolve(JSON.stringify(PostureRemediation.testingOnly_getState()));
            """
        )

    def _await_record(self, predicate, what, tries=60):
        for _ in range(tries):
            records = json.loads(self._remediation_state() or "[]")
            record = next((r for r in records if r["id"] == "curl"), None)
            if record and predicate(record):
                return record
            time.sleep(0.5)
        assert False, f"timed out waiting for {what}; last state: {records}"

    def run_directive_reaches_felt(self):
        """The console's required_tools list is normalized into the pref."""
        raw = self._felt_script(
            """
            const [resolve] = arguments;
            resolve(Services.prefs.getStringPref(
              "enterprise.posture.required_tools", ""));
            """
        )
        assert json.loads(raw) == [{"id": "curl", "minVersion": "999.0.0"}], (
            f"required_tools pref should be normalized, got {raw}"
        )

    def run_remediation_runs(self):
        """A verified signed script is actually spawned and reaped."""
        record = self._await_record(
            lambda r: r["attempts"] >= 1 and r["lastExitCode"] is not None,
            "a remediation attempt to complete",
        )
        assert record["status"] in ("outdated", "blocked"), (
            f"curl 999.0.0 is unsatisfiable, so status should not be compliant: {record}"
        )
        # A non-null exit code is the load-bearing assertion: it can only be set
        # by a child that was spawned and waited on.
        assert record["lastExitCode"] == 0, (
            f"the signed script should have exited cleanly: {record}"
        )
        assert record["lastOutcome"] == "succeeded", record
        assert record["documentCounter"] == 1, (
            f"the manifest's counter should be recorded: {record}"
        )
        self._logger.info(f"Remediation ran: {record}")
        return record

    def run_artifact_written(self):
        """The script's side effect landed where the script put it."""
        content = self._felt_script(
            """
            const [resolve] = arguments;
            const path = PathUtils.join(
              PathUtils.profileDir, "posture-remediation", "hello-world.txt");
            IOUtils.readUTF8(path).then(resolve, () => resolve(null));
            """
        )
        assert content == "Hello World\n", (
            f"the signed script should have written Hello World, got {content!r}"
        )

    def run_replay_is_refused(self):
        """The counter is spent, so the same document must not run twice.

        The fixture carries counter 1 and the tool stays non-compliant, so the
        next cycle re-fetches the same document and has to refuse it. This is
        the anti-rollback check working end to end."""
        record = self._await_record(
            lambda r: r["state"] == "blocked",
            "the spent document to be refused on the next cycle",
        )
        assert record["blockErrorCode"] == "replay-rejected", (
            f"a spent counter should be reported as a replay: {record}"
        )
        assert record["attempts"] == 1, (
            f"a refused document must not consume the attempt budget: {record}"
        )
        # The refusal must not erase the attempt that did run.
        assert record["lastOutcome"] == "succeeded", (
            f"the earlier successful attempt should still be reported: {record}"
        )
        assert record["lastExitCode"] == 0, record

    def run_warning_is_shown(self):
        """The user is told, in the FELT login window.

        Reads the rendered heading rather than the l10n id, so a missing or
        misspelled Fluent string fails here instead of quietly showing an
        empty bar."""
        rendered = json.loads(
            self._felt_script(
                """
                const [resolve] = arguments;
                const bar = document.querySelector(".felt-posture-warning-messages");
                if (!bar) {
                  resolve(JSON.stringify({ error: "no bar in the document" }));
                } else {
                  document.l10n.translateElements([bar]).then(() => {
                    const details = bar.querySelector(".felt-browser-error-details");
                    resolve(JSON.stringify({
                      hidden: bar.classList.contains("is-hidden"),
                      headingId: bar.getAttribute("data-l10n-id"),
                      heading: bar.getAttribute("heading"),
                      message: details ? details.textContent : null,
                    }));
                  }, e => resolve(JSON.stringify({ error: String(e) })));
                }
                """
            )
        )
        assert "error" not in rendered, rendered
        assert not rendered["hidden"], f"the posture warning should be visible: {rendered}"
        assert rendered["headingId"].startswith("felt-warning-title-posture-"), rendered
        assert rendered["heading"], (
            f"heading did not resolve, so the Fluent id is missing: {rendered}"
        )
        assert "curl" in (rendered["message"] or ""), (
            f"the message should name the tool: {rendered}"
        )
        # It must be its own bar: sharing the updates one would let the two
        # clobber each other's heading.
        updates_heading = self._felt_script(
            """
            const [resolve] = arguments;
            const bar = document.querySelector(".felt-updates-warning-messages");
            resolve(bar ? String(bar.getAttribute("heading")) : "missing");
            """
        )
        assert updates_heading in ("null", "missing", ""), (
            f"the posture warning leaked into the updates bar: {updates_heading!r}"
        )
        self._logger.info(f"Felt UI warning: {rendered}")

    def _device_posture(self):
        r = requests.get(f"http://localhost:{self.console_port}/sso/get_device_posture")
        return r.json()

    def run_reported_to_console(self):
        """The whole loop is only proven once the console sees the result."""
        for _ in range(60):
            posture = self._device_posture() or {}
            rows = posture.get("toolCompliance") or []
            row = next((r for r in rows if r["id"] == "curl"), None)
            if row and row["remediation"]["attempts"] >= 1:
                break
            time.sleep(0.5)
        else:
            assert False, "console never received a toolCompliance row for curl"

        assert row["required"] == "999.0.0", row
        assert row["installed"], f"the installed curl version should be reported: {row}"
        assert row["status"] in ("outdated", "blocked"), row
        assert row["remediation"]["lastExitCode"] == 0, row
        # Raw stderr must never reach the console: it leaks local paths and
        # would differ every attempt.
        assert "lastError" not in row["remediation"], row
        self._logger.info(f"Console received: {row}")

    def run_change_gate_is_not_defeated(self):
        """Posture submission is change-gated, so a field that moves every
        cycle would turn every tick into a token refresh. With a 250ms cycle
        over this window there are many cycles but only a handful of genuine
        state transitions."""
        r = requests.get(
            f"http://localhost:{self.console_port}/sso/get_device_posture_history"
        )
        history = r.json() or []
        distinct = {
            json.dumps(entry.get("toolCompliance"), sort_keys=True)
            for entry in history
            if entry
        }
        assert len(distinct) <= 8, (
            f"toolCompliance changed {len(distinct)} times across {len(history)} "
            "submissions; something in the payload moves on every cycle"
        )
        self._logger.info(
            f"{len(distinct)} distinct toolCompliance values over {len(history)} submissions"
        )
