/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Phase 2 Enterprise vault routing — small helper that UI surfaces
// (bookmark edit panel, about:addons, library context menus, the
// synced-tabs panel, form-history manager) use to read and write
// per-record vault tags.
//
// The actual storage lives in `Weave.Service.vaultTagStore`. This
// module hides the Weave dependency behind lazy getters so the UI
// surfaces don't pay the cost of loading Sync if vault routing is
// off.

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  Weave: "resource://services-sync/main.sys.mjs",
});

const VAULT_ROUTING_PREF = "services.sync.vault.routing.enabled";

export const VaultRouting = {
  /**
   * True on MOZ_ENTERPRISE builds when the pref is on. UI surfaces
   * should branch on this before showing any vault chrome.
   */
  get isEnabled() {
    return (
      AppConstants.MOZ_ENTERPRISE &&
      Services.prefs.getBoolPref(VAULT_ROUTING_PREF, false)
    );
  },

  /**
   * Read the current vault tag for a record. Returns "personal" for
   * any untagged or unknown record (the safer-tier default).
   * Returns null when routing is off or the tag store isn't ready.
   */
  getVault(engineName, recordId) {
    if (!this.isEnabled) {
      return null;
    }
    const store = lazy.Weave?.Service?.vaultTagStore;
    if (!store) {
      return "personal";
    }
    return store.get(engineName, recordId).vault;
  },

  /**
   * Persist a vault choice for a record. Marks the record dirty so
   * the engine's next sync run emits a tombstone in the old
   * collection (if any) and an upload to the new one. No-op when
   * routing is off.
   */
  setVault(engineName, recordId, vault) {
    if (!this.isEnabled) {
      return;
    }
    if (vault !== "personal" && vault !== "enterprise") {
      return;
    }
    const store = lazy.Weave?.Service?.vaultTagStore;
    if (!store) {
      return;
    }
    store.set(engineName, recordId, vault);
  },
};
