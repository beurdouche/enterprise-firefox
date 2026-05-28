// AutofillRecord vault round-trip unit tests. The autofill sync
// engine (addresses + credit cards) carries the Phase 2 Enterprise
// `vault` tag as a sibling of `entry` on each record. This test
// verifies the toEntry/fromEntry/deferGetSet plumbing in
// FormAutofillSync.sys.mjs:
//
//   - vault === "personal"/"enterprise" survives toEntry → fromEntry.
//   - Missing/unset vault on incoming records defaults to "personal".
//   - vault lives at the record level (record.vault) and is also
//     visible through record.cleartext.vault for the wire envelope.

const { AutofillRecord } = ChromeUtils.importESModule(
  "resource://autofill/FormAutofillSync.sys.mjs"
);

function makeRecord(guid, vault, extra = {}) {
  const rec = new AutofillRecord("addresses", guid);
  rec.fromEntry({ guid, vault, ...extra });
  return rec;
}

add_task(function test_personal_vault_round_trips() {
  const rec = makeRecord("guid-personal", "personal", {
    name: "Personal Person",
    "address-level2": "Cambridge",
  });

  Assert.equal(rec.vault, "personal", "record.vault set from entry");
  Assert.equal(
    rec.cleartext.vault,
    "personal",
    "record.cleartext.vault visible to encryption envelope"
  );

  const entry = rec.toEntry();
  Assert.equal(entry.vault, "personal", "toEntry carries vault tag");
  Assert.equal(entry.guid, "guid-personal", "toEntry carries guid");
  Assert.equal(entry.name, "Personal Person", "toEntry carries profile data");
});

add_task(function test_enterprise_vault_round_trips() {
  const rec = makeRecord("guid-enterprise", "enterprise", {
    "cc-name": "Enterprise Card",
  });

  Assert.equal(rec.vault, "enterprise", "record.vault set from entry");
  Assert.equal(
    rec.cleartext.vault,
    "enterprise",
    "record.cleartext.vault visible"
  );

  const entry = rec.toEntry();
  Assert.equal(entry.vault, "enterprise", "toEntry carries vault tag");
});

add_task(function test_unknown_vault_defaults_to_personal() {
  const rec = new AutofillRecord("addresses", "guid-untagged");
  rec.fromEntry({ guid: "guid-untagged", name: "No Vault" });

  Assert.equal(
    rec.vault,
    "personal",
    "missing vault in entry defaults to personal (safer tier)"
  );

  const entry = rec.toEntry();
  Assert.equal(
    entry.vault,
    "personal",
    "toEntry stamps default personal when source had none"
  );
});

add_task(function test_invalid_vault_defaults_to_personal() {
  const rec = new AutofillRecord("addresses", "guid-bogus");
  // A spoofed/corrupt remote record might carry junk in `vault`.
  rec.fromEntry({ guid: "guid-bogus", vault: "shadow-realm" });

  Assert.equal(
    rec.vault,
    "personal",
    "non-personal/enterprise vault values fall back to personal"
  );

  const entry = rec.toEntry();
  Assert.equal(
    entry.vault,
    "personal",
    "toEntry never emits unknown vault values"
  );
});

add_task(function test_guid_stripped_from_entry_on_fromEntry() {
  // FormAutofillSync removes guid from entry storage because the GUID
  // is already on the record. Ensure that contract still holds with
  // vault present.
  const rec = makeRecord("guid-strip", "personal");
  Assert.equal(rec.id, "guid-strip", "record id set");
  Assert.ok(
    !("guid" in rec.entry),
    "guid removed from entry to avoid duplication"
  );
  Assert.equal(rec.entry.vault, "personal", "vault stays on entry");
});
