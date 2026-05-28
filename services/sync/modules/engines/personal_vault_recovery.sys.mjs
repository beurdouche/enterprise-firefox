/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import {
  Store,
  SyncEngine,
  Tracker,
} from "resource://services-sync/engines.sys.mjs";
import { CryptoWrapper } from "resource://services-sync/record.sys.mjs";
import { Utils } from "resource://services-sync/util.sys.mjs";
import { SCORE_INCREMENT_XLARGE } from "resource://services-sync/constants.sys.mjs";

const RECORD_GUID = "personal-vault-recovery-v1";
const STORAGE_FILENAME = "personal-vault-recovery.json";

export function PersonalVaultRecoveryRec(collection, id) {
  CryptoWrapper.call(this, collection, id);
}
PersonalVaultRecoveryRec.prototype = {
  _logName: "Sync.Record.PersonalVaultRecovery",
};
Object.setPrototypeOf(
  PersonalVaultRecoveryRec.prototype,
  CryptoWrapper.prototype
);
Utils.deferGetSet(PersonalVaultRecoveryRec, "cleartext", ["payload"]);

async function readLocal() {
  const path = PathUtils.join(
    PathUtils.profileDir,
    STORAGE_FILENAME
  );
  try {
    const json = await IOUtils.readJSON(path);
    return json;
  } catch (e) {
    if (DOMException.isInstance(e) && e.name === "NotFoundError") {
      return null;
    }
    throw e;
  }
}

async function writeLocal(record) {
  const path = PathUtils.join(
    PathUtils.profileDir,
    STORAGE_FILENAME
  );
  await IOUtils.writeJSON(path, record);
}

async function deleteLocal() {
  const path = PathUtils.join(
    PathUtils.profileDir,
    STORAGE_FILENAME
  );
  try {
    await IOUtils.remove(path);
  } catch (e) {
    if (!DOMException.isInstance(e) || e.name !== "NotFoundError") {
      throw e;
    }
  }
}

export function PersonalVaultRecoveryStore(name, engine) {
  Store.call(this, name, engine);
}
PersonalVaultRecoveryStore.prototype = {
  async getAllIDs() {
    const local = await readLocal();
    if (!local) {
      return {};
    }
    return { [RECORD_GUID]: true };
  },

  async changeItemID(_oldID, _newID) {
    // Single-record engine: GUID is fixed.
  },

  async itemExists(id) {
    if (id !== RECORD_GUID) {
      return false;
    }
    const local = await readLocal();
    return local !== null;
  },

  async createRecord(id, collection) {
    const record = new PersonalVaultRecoveryRec(collection, id);
    if (id !== RECORD_GUID) {
      record.deleted = true;
      return record;
    }
    const local = await readLocal();
    if (!local) {
      record.deleted = true;
      return record;
    }
    record.payload = local;
    return record;
  },

  async create(record) {
    return this.update(record);
  },

  async update(record) {
    if (record.id !== RECORD_GUID) {
      return;
    }
    if (record.payload) {
      await writeLocal(record.payload);
    }
  },

  async remove(record) {
    if (record.id === RECORD_GUID) {
      await deleteLocal();
    }
  },

  async wipe() {
    await deleteLocal();
  },
};
Object.setPrototypeOf(PersonalVaultRecoveryStore.prototype, Store.prototype);

export function PersonalVaultRecoveryTracker(name, engine) {
  Tracker.call(this, name, engine);
}
PersonalVaultRecoveryTracker.prototype = {
  modified: false,

  onStart() {
    Tracker.prototype.onStart.call(this);
  },

  onStop() {
    Tracker.prototype.onStop.call(this);
  },

  markChanged() {
    this.modified = true;
    this.score += SCORE_INCREMENT_XLARGE;
  },
};
Object.setPrototypeOf(
  PersonalVaultRecoveryTracker.prototype,
  Tracker.prototype
);

export function PersonalVaultRecoveryEngine(service) {
  SyncEngine.call(this, "PersonalVaultRecovery", service);
}
PersonalVaultRecoveryEngine.prototype = {
  _storeObj: PersonalVaultRecoveryStore,
  _trackerObj: PersonalVaultRecoveryTracker,
  _recordObj: PersonalVaultRecoveryRec,
  version: 1,

  // Sync this engine before any personal-tier engines, since
  // personal-tier engines depend on the local KEK that this engine
  // restores. Lower number = earlier.
  syncPriority: 1,

  allowSkippedRecord: false,

  async getChangedIDs() {
    let changedIDs = {};
    if (this._tracker.modified) {
      changedIDs[RECORD_GUID] = 0;
    }
    return changedIDs;
  },
};
Object.setPrototypeOf(
  PersonalVaultRecoveryEngine.prototype,
  SyncEngine.prototype
);

/**
 * Facade used by FxAccountsKeys to fetch / upload the personal-vault
 * recovery record without having to know about the SyncEngine plumbing.
 * Reads come straight from the local on-disk copy (which the engine
 * keeps in sync with the server); writes update the local copy and
 * tag the tracker so the next sync uploads.
 */
export const PersonalVaultRecoverySync = {
  /// Returns the latest recovery payload object, or `null` if none.
  async fetchLatest() {
    return readLocal();
  },

  /// Writes a fresh recovery payload locally and schedules an upload
  /// on the next sync.
  async upload(record) {
    await writeLocal(record);
    try {
      const { Service } = ChromeUtils.importESModule(
        "resource://services-sync/service.sys.mjs"
      );
      const engine = Service.engineManager?.get("PersonalVaultRecovery");
      if (engine?._tracker) {
        engine._tracker.markChanged();
      }
    } catch (_) {
      // Sync may not be active in the current profile; the local
      // write still wins and any future sync run will pick it up
      // via getAllIDs.
    }
  },
};
