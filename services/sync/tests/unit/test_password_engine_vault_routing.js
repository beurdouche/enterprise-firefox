// Vault routing unit tests for PasswordEngine. The Phase 1 enterprise
// build wraps the NSS softoken in a way that breaks Services.logins
// in xpcshell (tracked separately), so we test the vault-filter logic
// directly against the engine by stubbing the store's `storage` shim.
// This keeps the assertions focused on the Phase 2 code paths
// (`_getChangedIDs`, `_createRecord`, engine URL, `_collectionName`).

const { Service } = ChromeUtils.importESModule(
  "resource://services-sync/service.sys.mjs"
);

function fakeLogin(guid, origin, vault, counter = 1, vaultLastSynced = "") {
  // Minimal nsILoginInfo + nsILoginMetaInfo shape that PasswordStore
  // and the engine inspect. Properties are intentionally direct
  // assignments so the JS code (which reads .vault, .guid, etc) sees
  // them; QueryInterface returns the object unchanged.
  const login = {
    guid,
    origin,
    formActionOrigin: null,
    httpRealm: null,
    username: "user-" + guid,
    password: "pw-" + guid,
    usernameField: "",
    passwordField: "",
    timeCreated: Date.now(),
    timeLastUsed: Date.now(),
    timePasswordChanged: Date.now(),
    timesUsed: 1,
    syncCounter: counter,
    everSynced: false,
    unknownFields: null,
    vault,
    vaultLastSynced,
    QueryInterface: ChromeUtils.generateQI([
      "nsILoginInfo",
      "nsILoginMetaInfo",
    ]),
  };
  return login;
}

function stubStorage(engine, logins) {
  const deletedGUIDs = new Set();
  const storage = {
    async getAllLogins() {
      return logins.map(l => Object.assign({}, l));
    },
    async searchLoginsAsync({ guid } = {}) {
      const match = logins.find(l => l.guid === guid);
      return match ? [Object.assign({}, match)] : [];
    },
    async loginIsDeletedAsync(guid) {
      return deletedGUIDs.has(guid);
    },
    resetSyncCounter() {},
    async getLastSync() {
      return 0;
    },
    async setLastSync() {},
  };
  // Replace the engine's lazily-constructed _store with a minimal
  // double that points at the stubbed storage. We keep the real
  // engine class so the methods under test (_getChangedIDs,
  // _createRecord, engineURL) run unchanged.
  Object.defineProperty(engine, "_store", {
    configurable: true,
    value: {
      storage,
      async createRecord(id, collection) {
        const { LoginRec } = ChromeUtils.importESModule(
          "resource://services-sync/engines/passwords.sys.mjs"
        );
        const rec = new LoginRec(collection, id);
        const login = logins.find(l => l.guid === id);
        if (!login || deletedGUIDs.has(id)) {
          rec.deleted = true;
          return rec;
        }
        // Mirror PasswordStore.createRecord's re-tag tombstone branch
        // so the stub honors the same contract the engine relies on.
        const activeVault = engine._activeVault;
        if (
          activeVault &&
          (login.vault || "personal") !== activeVault &&
          (login.vaultLastSynced || "") === activeVault
        ) {
          rec.deleted = true;
          return rec;
        }
        rec.hostname = login.origin;
        rec.formSubmitURL = login.formActionOrigin;
        rec.httpRealm = login.httpRealm;
        rec.username = login.username;
        rec.password = login.password;
        rec.usernameField = login.usernameField;
        rec.passwordField = login.passwordField;
        rec.vault = login.vault || "personal";
        rec.timeCreated = login.timeCreated;
        rec.timePasswordChanged = login.timePasswordChanged;
        return rec;
      },
    },
  });
}

add_task(async function setup() {
  await Service.engineManager.unregister("addons");
  await Service.engineManager.unregister("extension-storage");
});

add_task(async function test_changed_ids_filters_by_active_vault() {
  const engine = Service.engineManager.get("passwords");
  const logins = [
    fakeLogin("personal-guid", "https://personal.example", "personal"),
    fakeLogin("enterprise-guid", "https://enterprise.example", "enterprise"),
    fakeLogin("untagged-guid", "https://untagged.example", ""),
  ];
  stubStorage(engine, logins);

  try {
    engine._activeVault = null;
    let all = await engine.pullAllChanges();
    Assert.ok("personal-guid" in all, "all: personal in");
    Assert.ok("enterprise-guid" in all, "all: enterprise in");
    Assert.ok("untagged-guid" in all, "all: untagged in");

    engine._activeVault = "personal";
    let onlyPersonal = await engine.pullAllChanges();
    Assert.ok("personal-guid" in onlyPersonal, "personal pass: personal in");
    Assert.ok(
      "untagged-guid" in onlyPersonal,
      "personal pass: untagged defaults to personal"
    );
    Assert.ok(
      !("enterprise-guid" in onlyPersonal),
      "personal pass: enterprise excluded"
    );

    engine._activeVault = "enterprise";
    let onlyEnterprise = await engine.pullAllChanges();
    Assert.ok(
      "enterprise-guid" in onlyEnterprise,
      "enterprise pass: enterprise in"
    );
    Assert.ok(
      !("personal-guid" in onlyEnterprise),
      "enterprise pass: personal excluded"
    );
    Assert.ok(
      !("untagged-guid" in onlyEnterprise),
      "enterprise pass: untagged excluded"
    );
  } finally {
    engine._activeVault = null;
  }
});

add_task(async function test_create_record_uses_active_vault_collection() {
  const engine = Service.engineManager.get("passwords");
  const login = fakeLogin("rec-guid", "https://example.test", "enterprise");
  stubStorage(engine, [login]);

  try {
    engine._activeVault = null;
    let baseRecord = await engine._createRecord(login.guid);
    Assert.equal(
      baseRecord.collection,
      engine.name,
      "no active vault → record.collection is base name"
    );

    engine._activeVault = "personal";
    let personalRecord = await engine._createRecord(login.guid);
    Assert.equal(
      personalRecord.collection,
      `${engine.name}-personal`,
      "personal pass → record.collection suffixed"
    );

    engine._activeVault = "enterprise";
    let enterpriseRecord = await engine._createRecord(login.guid);
    Assert.equal(
      enterpriseRecord.collection,
      `${engine.name}-enterprise`,
      "enterprise pass → record.collection suffixed"
    );

    Assert.equal(
      enterpriseRecord.cleartext.vault,
      "enterprise",
      "record cleartext carries the stored vault tag"
    );
  } finally {
    engine._activeVault = null;
  }
});

add_task(async function test_engine_url_tracks_active_vault() {
  const engine = Service.engineManager.get("passwords");

  try {
    engine._activeVault = null;
    let baseURL = engine.engineURL;
    Assert.ok(
      baseURL.endsWith(engine.name),
      `base engineURL ends with engine name (${baseURL})`
    );

    engine._activeVault = "personal";
    Assert.ok(
      engine.engineURL.endsWith(`${engine.name}-personal`),
      `personal engineURL has personal suffix (${engine.engineURL})`
    );

    engine._activeVault = "enterprise";
    Assert.ok(
      engine.engineURL.endsWith(`${engine.name}-enterprise`),
      `enterprise engineURL has enterprise suffix (${engine.engineURL})`
    );
  } finally {
    engine._activeVault = null;
  }
});

add_task(async function test_retag_emits_tombstone_in_previous_vault() {
  const engine = Service.engineManager.get("passwords");
  // Login was last synced under Personal, but the user has flipped
  // its vault to Enterprise. syncCounter > 0 since the local edit.
  const login = fakeLogin(
    "retag-guid",
    "https://retag.example",
    "enterprise",
    /* counter */ 1,
    /* vaultLastSynced */ "personal"
  );
  stubStorage(engine, [login]);

  try {
    // Personal pass: surfaces the record as a tombstone for the old
    // collection (passwords-personal).
    engine._activeVault = "personal";
    let personalChanges = await engine.pullAllChanges();
    Assert.ok(
      "retag-guid" in personalChanges,
      "personal pass: re-tagged record surfaces in changes"
    );
    Assert.equal(
      personalChanges["retag-guid"].deleted,
      true,
      "personal pass: re-tagged record flagged as deleted (tombstone)"
    );
    Assert.equal(
      personalChanges["retag-guid"].retagTombstone,
      true,
      "personal pass: retagTombstone marker present so trackRemainingChanges skips counter decrement"
    );

    // _createRecord during the personal pass must emit a tombstone
    // BSO (deleted=true) so the server-side BSO in
    // passwords-personal is removed on this sync run.
    let personalRecord = await engine._createRecord("retag-guid");
    Assert.equal(
      personalRecord.deleted,
      true,
      "personal pass: createRecord returns a tombstone for the re-tag"
    );
    Assert.equal(
      personalRecord.collection,
      `${engine.name}-personal`,
      "personal pass: tombstone targets the old vault's collection"
    );

    // Enterprise pass: surfaces the record as a normal upload.
    engine._activeVault = "enterprise";
    let enterpriseChanges = await engine.pullAllChanges();
    Assert.ok(
      "retag-guid" in enterpriseChanges,
      "enterprise pass: re-tagged record surfaces in changes"
    );
    Assert.equal(
      enterpriseChanges["retag-guid"].deleted,
      false,
      "enterprise pass: real upload, not a tombstone"
    );
    Assert.equal(
      enterpriseChanges["retag-guid"].retagTombstone,
      false,
      "enterprise pass: no retagTombstone marker; counter decrements normally"
    );

    let enterpriseRecord = await engine._createRecord("retag-guid");
    Assert.equal(
      enterpriseRecord.deleted,
      undefined,
      "enterprise pass: createRecord returns a live record"
    );
    Assert.equal(
      enterpriseRecord.cleartext.vault,
      "enterprise",
      "enterprise pass: record carries the new vault tag"
    );
    Assert.equal(
      enterpriseRecord.collection,
      `${engine.name}-enterprise`,
      "enterprise pass: real upload targets the new vault's collection"
    );
  } finally {
    engine._activeVault = null;
  }
});

add_task(async function test_no_retag_when_vault_matches_last_synced() {
  // Sanity: a record whose vault matches vaultLastSynced is a steady-state
  // upload, not a re-tag. Make sure the personal pass excludes a personal
  // record from tombstone surfacing.
  const engine = Service.engineManager.get("passwords");
  const login = fakeLogin(
    "steady-guid",
    "https://steady.example",
    "personal",
    /* counter */ 1,
    /* vaultLastSynced */ "personal"
  );
  stubStorage(engine, [login]);

  try {
    engine._activeVault = "personal";
    let changes = await engine.pullAllChanges();
    Assert.ok(
      "steady-guid" in changes,
      "personal pass: steady-state record surfaces"
    );
    Assert.equal(
      changes["steady-guid"].deleted,
      false,
      "personal pass: steady-state record is not a tombstone"
    );
    Assert.equal(
      changes["steady-guid"].retagTombstone,
      false,
      "personal pass: no retagTombstone marker"
    );

    engine._activeVault = "enterprise";
    let enterpriseChanges = await engine.pullAllChanges();
    Assert.ok(
      !("steady-guid" in enterpriseChanges),
      "enterprise pass: steady-state personal record excluded"
    );
  } finally {
    engine._activeVault = null;
  }
});
