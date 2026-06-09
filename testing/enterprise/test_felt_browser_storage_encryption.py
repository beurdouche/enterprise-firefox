#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import sys

sys.path.append(os.path.dirname(__file__))

from felt_browser_storage_encryption import FeltBrowserStorageEncryption


class FeltBrowserStorageEncryptionTest(FeltBrowserStorageEncryption):
    def test_transparent_primary_password_unlock(self):
        # Drive the full FELT login flow first so the child browser holds a
        # valid access token; ConsoleClient.getPrimarySecret() must
        # authenticate against the mock console's /api/browser/key endpoint.
        super().run_felt_base()
        self.run_storage_encryption_startup()
