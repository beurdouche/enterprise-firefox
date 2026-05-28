// VaultTagStore unit tests. The store is the JS-bridge-layer
// alternative to inline `LoginInfo.vault`/`AutofillRecord.vault`
// storage. Used by bookmarks/history/tabs/forms/prefs/addons/
// extension-storage where the local record can't carry the tag.

const { VaultTagStore } = ChromeUtils.importESModule(
  "resource://services-sync/vault_tag_store.sys.mjs"
);

async function freshStore() {
  // Each test gets its own profile dir, so the JSONFile path is
  // already isolated. Load resets in-memory state.
  const store = new VaultTagStore();
  await store.load();
  return store;
}

add_task(async function test_default_personal_for_missing_record() {
  const store = await freshStore();
  const r = store.get("bookmarks", "never-tagged");
  Assert.equal(r.vault, "personal", "missing record defaults to personal");
  Assert.equal(r.vaultLastSynced, "", "missing record has no synced vault");
});

add_task(async function test_set_and_get_round_trip() {
  const store = await freshStore();
  store.set("history", "h-1", "enterprise");
  const r = store.get("history", "h-1");
  Assert.equal(r.vault, "enterprise", "set then get returns the stored vault");

  store.set("history", "h-1", "personal");
  Assert.equal(
    store.get("history", "h-1").vault,
    "personal",
    "subsequent set overwrites"
  );
});

add_task(async function test_invalid_vault_is_ignored() {
  const store = await freshStore();
  store.set("addons", "a-1", "personal");
  store.set("addons", "a-1", "shadow-realm");
  Assert.equal(
    store.get("addons", "a-1").vault,
    "personal",
    "invalid vault value is rejected; previous value sticks"
  );
});

add_task(async function test_dirty_set_tracks_user_retag() {
  const store = await freshStore();
  store.set("bookmarks", "b-1", "personal");
  store.set("bookmarks", "b-2", "enterprise");

  const dirty = store.getDirty("bookmarks");
  Assert.ok(dirty.has("b-1"), "b-1 in dirty set after set()");
  Assert.ok(dirty.has("b-2"), "b-2 in dirty set after set()");

  store.clearDirty("bookmarks", "b-1");
  Assert.ok(
    !store.getDirty("bookmarks").has("b-1"),
    "b-1 cleared from dirty set"
  );
  Assert.ok(store.getDirty("bookmarks").has("b-2"), "b-2 still dirty");
});

add_task(async function test_setLastSynced_does_not_bump_dirty() {
  const store = await freshStore();
  store.setLastSynced("tabs", "t-1", "enterprise");
  Assert.equal(
    store.get("tabs", "t-1").vaultLastSynced,
    "enterprise",
    "vaultLastSynced persisted"
  );
  Assert.ok(
    !store.getDirty("tabs").has("t-1"),
    "setLastSynced does NOT bump the dirty set (engine-internal)"
  );
});

add_task(async function test_setLastSynced_empty_clears_marker() {
  const store = await freshStore();
  store.setLastSynced("tabs", "t-2", "personal");
  Assert.equal(store.get("tabs", "t-2").vaultLastSynced, "personal");
  store.setLastSynced("tabs", "t-2", "");
  Assert.equal(
    store.get("tabs", "t-2").vaultLastSynced,
    "",
    "empty value clears vaultLastSynced"
  );
});

add_task(async function test_delete_removes_record_and_dirty() {
  const store = await freshStore();
  store.set("forms", "f-1", "personal");
  Assert.ok(store.getDirty("forms").has("f-1"));
  store.delete("forms", "f-1");
  Assert.equal(
    store.get("forms", "f-1").vault,
    "personal",
    "deleted record falls back to the personal default"
  );
  Assert.ok(
    !store.getDirty("forms").has("f-1"),
    "delete also clears the dirty marker"
  );
});

add_task(async function test_ids_lists_tagged_records_per_engine() {
  const store = await freshStore();
  store.set("prefs", "p-1", "personal");
  store.set("prefs", "p-2", "enterprise");
  store.set("addons", "a-1", "personal");

  const prefsIds = store.ids("prefs").sort();
  Assert.deepEqual(prefsIds, ["p-1", "p-2"], "prefs ids");
  Assert.deepEqual(store.ids("addons"), ["a-1"], "addons ids");
  Assert.deepEqual(store.ids("history"), [], "history empty");
});

add_task(async function test_engines_isolated_from_each_other() {
  const store = await freshStore();
  store.set("bookmarks", "shared-id", "personal");
  store.set("history", "shared-id", "enterprise");

  Assert.equal(
    store.get("bookmarks", "shared-id").vault,
    "personal",
    "bookmarks entry independent"
  );
  Assert.equal(
    store.get("history", "shared-id").vault,
    "enterprise",
    "history entry independent"
  );
});
