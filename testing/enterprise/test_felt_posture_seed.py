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

SEEDED = [{"id": "curl", "min_version": "999.0.0"}]


class FeltPostureSeed(FeltTests):
    """The development seeding pref, which is the only way to exercise
    remediation from ./mach run until the console can send required_tools.

    The console deliberately sends nothing here. That matters: the login path
    clears an absent list, so this also pins that the seed survives the clear
    rather than being wiped at sign-in."""

    def test_posture_seed(self):
        driver = self.get_driver(Environment.FELT)
        driver.set_prefs(
            {
                "enterprise.felt_tests.should_not_close_window": True,
                "enterprise.posture.remediation.local_dir": FIXTURE_DIR,
                "enterprise.posture.remediation.cycle_ms": 250,
                "enterprise.posture.remediation.seed_requirements": json.dumps(
                    SEEDED
                ),
            },
            default_branch=True,
        )
        # Note what is NOT set: posture_required_tools. The console sends no
        # directive at all, exactly as the real one does today.

        super().run_felt_base()
        self.connect_child_browser()

        self.run_console_sent_nothing()
        self.run_seed_drove_remediation()

    def _felt_script(self, script):
        driver = self.get_driver(Environment.FELT)
        driver.set_context("chrome")
        return driver.execute_async_script(script)

    def run_console_sent_nothing(self):
        """The pref the console writes is empty, so anything that happens
        afterwards can only have come from the seed."""
        raw = self._felt_script(
            """
            const [resolve] = arguments;
            resolve(Services.prefs.getStringPref(
              "enterprise.posture.required_tools", ""));
            """
        )
        assert json.loads(raw or "[]") == [], (
            f"the console should have written an empty list, got {raw}"
        )

    def run_seed_drove_remediation(self):
        """A seeded requirement behaves exactly like a console-sent one."""
        for _ in range(60):
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
            record = next((r for r in records if r["id"] == "curl"), None)
            if record and record["lastExitCode"] is not None:
                break
            time.sleep(0.5)
        else:
            assert False, f"the seed never produced a remediation: {records}"

        assert record["required"] == "999.0.0", record
        assert record["installed"], f"curl should have been detected: {record}"
        assert record["lastExitCode"] == 0, (
            f"the signed script should have run and been reaped: {record}"
        )
        assert record["attempts"] == 1, record
        self._logger.info(f"seeded remediation: {record}")
