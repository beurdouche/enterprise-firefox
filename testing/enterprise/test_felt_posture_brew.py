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

# bash is present in every Homebrew installation this runs on, and a floor of
# 1.0.0 is satisfied by any of them. That is the point: this exercises the
# brew detector through the real stack while guaranteeing the remediation path
# never fires, so the test cannot install or upgrade anything on the machine
# running it.
REQUIRED_TOOLS = [{"id": "bash", "min_version": "1.0.0"}]


class FeltPostureBrew(FeltTests):
    """Homebrew-backed detection, and the invariant that a tool which needs
    nothing done to it is left alone."""

    def test_posture_brew_detection(self):
        driver = self.get_driver(Environment.FELT)
        driver.set_prefs(
            {
                "enterprise.felt_tests.should_not_close_window": True,
                "enterprise.posture.remediation.cycle_ms": 250,
            },
            default_branch=True,
        )
        self.posture_required_tools.value = json.dumps(REQUIRED_TOOLS)

        super().run_felt_base()
        self.connect_child_browser()

        record = self.run_detects_via_brew()
        self.run_no_remediation_attempted(record)
        self.run_warning_matches_status(record)

    def _felt_script(self, script):
        driver = self.get_driver(Environment.FELT)
        driver.set_context("chrome")
        return driver.execute_async_script(script)

    def _record(self):
        raw = self._felt_script(
            """
            const [resolve] = arguments;
            const { PostureRemediation } = ChromeUtils.importESModule(
              "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
            );
            resolve(JSON.stringify(PostureRemediation.testingOnly_getState()));
            """
        )
        records = json.loads(raw or "[]")
        return next((r for r in records if r["id"] == "bash"), None)

    def run_detects_via_brew(self):
        """The brew detector produces a verdict."""
        for _ in range(60):
            record = self._record()
            if record and record["status"] != "unknown":
                break
            time.sleep(0.5)
        else:
            assert False, f"brew detection never produced a verdict: {self._record()}"

        # Either outcome is a pass: "unavailable" is the correct answer on a
        # machine without Homebrew, and asserting it here keeps the test honest
        # on a runner that has none.
        assert record["status"] in ("compliant", "unavailable"), (
            f"bash >= 1.0.0 should be compliant, or unavailable without brew: {record}"
        )
        if record["status"] == "compliant":
            assert record["installed"], (
                f"a compliant tool should report the version brew has: {record}"
            )
        else:
            assert record["lastErrorCode"] == "no-package-manager", record
            assert record["state"] == "unavailable", record
        self._logger.info(f"brew detection: {record}")
        return record

    def run_no_remediation_attempted(self, record):
        """Nothing is installed or upgraded when nothing needs to be.

        This is the invariant that keeps the test from mutating the machine,
        and it is also the behaviour that matters: a compliant fleet must not
        be running package-manager commands on a five-minute timer. An
        unavailable tool must not burn the attempt budget either, or the
        retry is lost once an admin provisions brew."""
        for _ in range(6):
            current = self._record()
            assert current["attempts"] == 0, (
                f"remediation must not run for a {record['status']} tool: {current}"
            )
            assert current["lastAttemptAt"] is None, current
            assert current["documentCounter"] is None, current
            time.sleep(0.5)

    def run_warning_matches_status(self, record):
        """A compliant tool shows no warning; an unmanageable one says so."""
        rendered = json.loads(
            self._felt_script(
                """
                const [resolve] = arguments;
                const bar = document.querySelector(".felt-posture-warning-messages");
                document.l10n.translateElements([bar]).then(() => {
                  resolve(JSON.stringify({
                    hidden: bar.classList.contains("is-hidden"),
                    headingId: bar.getAttribute("data-l10n-id"),
                    heading: bar.getAttribute("heading"),
                  }));
                }, e => resolve(JSON.stringify({ error: String(e) })));
                """
            )
        )
        assert "error" not in rendered, rendered

        if record["status"] == "compliant":
            assert rendered["hidden"], (
                f"a compliant device should show no warning: {rendered}"
            )
        else:
            assert not rendered["hidden"], rendered
            assert rendered["headingId"] == "felt-warning-title-posture-unavailable", (
                rendered
            )
            assert rendered["heading"], (
                f"heading did not resolve, so the Fluent id is missing: {rendered}"
            )
        self._logger.info(f"warning state: {rendered}")
