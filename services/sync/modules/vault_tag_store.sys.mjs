/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Phase 2 Enterprise vault routing for engines that don't have an
// inline place to store the per-record vault tag (bookmarks, history,
// tabs, forms, prefs, addons, storage.sync).
//
// Sensitive engines (passwords, addresses, credit cards) carry the
// vault tag on the local record itself — LoginInfo.vault for
// passwords, entry.vault for autofill records — because they own
// their local storage and can extend the schema cheaply.
//
// The bridged engines own their local storage in Rust (places.sqlite,
// places.sqlite tabs tables, webext storage, etc.). Adding `vault` to
// those schemas would require coordinated changes to the
// application-services crates. To keep the routing at the JS-bridge
// layer (the chosen design constraint), we hold the vault tag in a
// parallel JSON-backed store, keyed by (engine name, record id).
//
// Records that have never been tagged read as "personal" by
// convention — same default as the sensitive-engine path — so the
// safer trust property applies to pre-Phase-2 records on disk.

import { JSONFile } from "resource://gre/modules/JSONFile.sys.mjs";
import { Utils } from "resource://services-sync/util.sys.mjs";

const VALID_VAULTS = ["personal", "enterprise"];

function normaliseVault(value) {
  return VALID_VAULTS.includes(value) ? value : "personal";
}

/**
 * Persistent record-vault map.
 *
 * Shape on disk:
 *   {
 *     "engineName": {
 *       "recordId": {
 *         vault: "personal" | "enterprise",
 *         vaultLastSynced: "personal" | "enterprise" | ""
 *       },
 *       ...
 *     },
 *     ...
 *   }
 *
 * The store is shared across all engines that opt in via
 * `_vaultAwareViaTagStore` (see SyncEngine). One process-wide
 * instance lives on `Service.vaultTagStore` and is loaded
 * asynchronously on first use.
 */
export class VaultTagStore {
  constructor() {
    this._file = new JSONFile({
      path: Utils.jsonFilePath("vaultTags"),
    });
    // Records the user re-tagged since the last sync, per engine. Used
    // by engines to discover re-tag candidates without walking the
    // entire local store on every sync.
    this._dirty = new Map();
  }

  async load() {
    await this._file.load();
    if (!this._file.data || typeof this._file.data !== "object") {
      this._file.data = {};
    }
  }

  // Returns { vault, vaultLastSynced } for a record. Both default to
  // safe values ("personal" and "" respectively) when no tag has been
  // recorded yet.
  get(engineName, recordId) {
    const engine = this._file.data?.[engineName];
    const entry = engine?.[recordId];
    return {
      vault: normaliseVault(entry?.vault),
      vaultLastSynced:
        VALID_VAULTS.includes(entry?.vaultLastSynced) ||
        entry?.vaultLastSynced === ""
          ? entry.vaultLastSynced
          : "",
    };
  }

  // Update the vault tag for a record. Bumps the dirty marker for
  // engines to surface as a re-tag candidate on the next sync.
  set(engineName, recordId, vault) {
    if (!VALID_VAULTS.includes(vault)) {
      return;
    }
    if (!this._file.data[engineName]) {
      this._file.data[engineName] = {};
    }
    const entry = this._file.data[engineName][recordId] || {};
    if (entry.vault === vault) {
      return;
    }
    entry.vault = vault;
    if (entry.vaultLastSynced === undefined) {
      entry.vaultLastSynced = "";
    }
    this._file.data[engineName][recordId] = entry;
    this._markDirty(engineName, recordId);
    this._file.saveSoon();
  }

  // Engine-internal: record which vault the BSO landed in on the
  // wire. Does not bump the dirty marker.
  setLastSynced(engineName, recordId, vault) {
    if (vault !== "" && !VALID_VAULTS.includes(vault)) {
      return;
    }
    if (!this._file.data[engineName]) {
      this._file.data[engineName] = {};
    }
    const entry = this._file.data[engineName][recordId] || {};
    entry.vaultLastSynced = vault;
    if (entry.vault === undefined) {
      entry.vault = "personal";
    }
    this._file.data[engineName][recordId] = entry;
    this._file.saveSoon();
  }

  // Remove a record's tag — call when the underlying record is
  // deleted locally. Does not bump the dirty marker (the engine
  // will discover the deletion via its normal change-tracking).
  delete(engineName, recordId) {
    const engine = this._file.data?.[engineName];
    if (!engine || !(recordId in engine)) {
      return;
    }
    delete engine[recordId];
    this._clearDirty(engineName, recordId);
    this._file.saveSoon();
  }

  // All record ids currently tagged for an engine. Used by the engine
  // to walk re-tag candidates when no inline dirty bit exists on the
  // local record.
  ids(engineName) {
    return Object.keys(this._file.data?.[engineName] || {});
  }

  // Records the user re-tagged since the last sync of this engine.
  getDirty(engineName) {
    return new Set(this._dirty.get(engineName) || []);
  }

  clearDirty(engineName, recordId) {
    this._clearDirty(engineName, recordId);
  }

  _markDirty(engineName, recordId) {
    let set = this._dirty.get(engineName);
    if (!set) {
      set = new Set();
      this._dirty.set(engineName, set);
    }
    set.add(recordId);
  }

  _clearDirty(engineName, recordId) {
    const set = this._dirty.get(engineName);
    if (set) {
      set.delete(recordId);
      if (!set.size) {
        this._dirty.delete(engineName);
      }
    }
  }
}
