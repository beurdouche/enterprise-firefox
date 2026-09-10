/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { PostureToolCatalog } = ChromeUtils.importESModule(
  "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs"
);
const { decideStatus, nextAttemptDelay, PostureRemediation } =
  ChromeUtils.importESModule(
    "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
  );

const { Enforcement } = ChromeUtils.importESModule(
  "resource://gre/modules/enterprise/PostureRemediation.sys.mjs"
);

const SEED_PREF = "enterprise.posture.remediation.seed_requirements";
const ENFORCEMENT_PREF = "enterprise.posture.remediation.enforcement";
const SEED_ENFORCEMENT_PREF = "enterprise.posture.remediation.seed_enforcement";
const TESTING_PREF = "enterprise.is_testing";

const norm = v => PostureToolCatalog.normalizeVersion(v);

add_task(function test_homebrew_revision_suffix_orders_correctly() {
  // The regression this normalization exists for. nsVersionComparator
  // documents "any string is before no string", so untouched, 1.2.3_1 sorts
  // *below* 1.2.3 -- a formula at revision 1 would read as older than the same
  // formula at no revision and be remediated forever.
  Assert.equal(
    Services.vc.compare("1.2.3_1", "1.2.3"),
    -1,
    "raw comparison is backwards, which is why normalizeVersion exists"
  );
  Assert.greater(
    Services.vc.compare(norm("1.2.3_1"), norm("1.2.3")),
    0,
    "normalized, a revision bump is newer"
  );
  Assert.equal(norm("1.2.3_1"), "1.2.3.1");
});

add_task(function test_normalize_version_shapes() {
  Assert.equal(norm("8.7.1"), "8.7.1");
  Assert.equal(norm("v1.2.3"), "1.2.3", "a leading v is stripped");
  Assert.equal(norm(" 1.7 "), "1.7", "surrounding whitespace is ignored");
  Assert.equal(norm("1.7.1 (x86_64)"), "1.7.1", "trailing junk is dropped");

  // Unparseable must be null so the caller reports "unknown" rather than
  // "outdated"; a HEAD build would otherwise loop the remediator.
  Assert.equal(norm("HEAD-abc1234"), null);
  Assert.equal(norm(""), null);
  Assert.equal(norm("not-a-version"), null);
  Assert.equal(norm("9".repeat(33)), null, "absurdly long is rejected");
  Assert.equal(norm(null), null);
  Assert.equal(norm(42), null);
});

add_task(function test_parse_brew_versions() {
  const parse = (out, formula) =>
    PostureToolCatalog.parseBrewVersions(out, formula);

  Assert.equal(parse("bash 5.3.15\n", "bash"), "5.3.15");
  Assert.equal(
    parse("", "jq"),
    null,
    "a formula that is not installed prints nothing"
  );
  Assert.equal(
    parse("python@3.14 3.14.6 3.14.7\n", "python@3.14"),
    "3.14.7",
    "a multi-keg formula reports its newest version"
  );
  Assert.equal(
    parse("python@3.14 3.14.7\nbash 5.3.15\n", "bash"),
    "5.3.15",
    "only the requested formula's line is read"
  );
  Assert.equal(
    parse("bash 5.3.15\n", "jq"),
    null,
    "a different formula is not mistaken for the one asked about"
  );
  Assert.equal(
    parse("jq 1.7_1\n", "jq"),
    "1.7.1",
    "brew revision suffixes are normalized on the way in"
  );
  Assert.equal(parse(null, "jq"), null);
});

add_task(function test_decide_status_truth_table() {
  const base = {
    installed: "1.0.0",
    required: "1.0.0",
    supported: true,
    probeFailed: false,
  };

  Assert.equal(decideStatus(base), "compliant", "equal versions are compliant");
  Assert.equal(
    decideStatus({ ...base, installed: "2.0.0" }),
    "compliant",
    "newer than required is compliant: brew installs latest, so exact-match would never converge"
  );
  Assert.equal(decideStatus({ ...base, installed: "0.9.0" }), "outdated");
  Assert.equal(decideStatus({ ...base, installed: null }), "missing");
  Assert.equal(
    decideStatus({ ...base, required: null }),
    "unknown",
    "an unparseable requirement is never 'outdated'"
  );
  Assert.equal(decideStatus({ ...base, supported: false }), "unsupported");
  Assert.equal(decideStatus({ ...base, probeFailed: true }), "check-failed");
  Assert.equal(
    decideStatus({ ...base, packageManagerMissing: true }),
    "unavailable",
    "no package manager is a different message from a failed probe"
  );
  Assert.equal(
    decideStatus({ ...base, packageManagerMissing: true, probeFailed: true }),
    "unavailable",
    "a missing package manager outranks a failed probe"
  );
  Assert.equal(
    decideStatus({ ...base, supported: false, packageManagerMissing: true }),
    "unsupported",
    "an unsupported platform still outranks everything"
  );
  Assert.equal(
    decideStatus({ ...base, supported: false, probeFailed: true }),
    "unsupported",
    "an unsupported platform outranks a failed probe"
  );
});

add_task(function test_backoff_is_monotonic_and_capped() {
  const noJitter = () => 0.5;
  const delays = [1, 2, 3, 4, 5, 6, 7, 8].map(n =>
    nextAttemptDelay(n, noJitter)
  );

  for (let i = 1; i < delays.length; i++) {
    Assert.greaterOrEqual(
      delays[i],
      delays[i - 1],
      `attempt ${i + 1} waits at least as long as attempt ${i}`
    );
  }
  Assert.equal(delays[0], 5 * 60 * 1000, "first retry is five minutes");
  Assert.lessOrEqual(
    delays[delays.length - 1],
    4 * 60 * 60 * 1000,
    "delay is capped at four hours"
  );
});

add_task(function test_backoff_jitter_stays_in_band() {
  const low = nextAttemptDelay(1, () => 0);
  const high = nextAttemptDelay(1, () => 1);
  const base = 5 * 60 * 1000;

  Assert.equal(low, Math.round(base * 0.8), "jitter floor is -20%");
  Assert.equal(high, Math.round(base * 1.2), "jitter ceiling is +20%");
});

add_task(function test_catalog_lookup_rejects_prototype_keys() {
  Assert.equal(PostureToolCatalog.lookup("constructor"), null);
  Assert.equal(PostureToolCatalog.lookup("__proto__"), null);
  Assert.equal(PostureToolCatalog.lookup("toString"), null);
  Assert.ok(!PostureToolCatalog.isKnownId("constructor"));
  Assert.ok(!PostureToolCatalog.isKnownId("hasOwnProperty"));
});

add_task(function test_brew_catalog_entries() {
  for (const id of ["jq", "bash"]) {
    Assert.ok(PostureToolCatalog.isKnownId(id), `${id} is a known tool`);
    const entry = PostureToolCatalog.lookup(id, "macosx");
    Assert.equal(entry.detect.kind, "brewFormula", `${id} is brew-managed`);
    Assert.equal(entry.detect.formula, id);
  }

  const { BREW_CANDIDATES } = ChromeUtils.importESModule(
    "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs"
  );
  for (const candidate of BREW_CANDIDATES) {
    Assert.ok(candidate.startsWith("/"), `${candidate} is absolute`);
    Assert.ok(candidate.endsWith("/brew"), `${candidate} names brew`);
  }
});

add_task(function test_catalog_known_entry() {
  Assert.ok(PostureToolCatalog.isKnownId("curl"));
  const entry = PostureToolCatalog.lookup("curl", "macosx");
  Assert.ok(entry, "curl has a macOS arm");
  Assert.equal(entry.detect.kind, "commandVersion");
  Assert.ok(
    entry.detect.parse.test("curl 8.7.1 (aarch64-apple-darwin)"),
    "the parse regex matches real curl output"
  );

  Assert.equal(
    PostureToolCatalog.lookup("curl", "win"),
    null,
    "an id with no arm for the platform resolves to null"
  );
  Assert.ok(
    PostureToolCatalog.isKnownId("curl"),
    "...but stays a known id, so posture can report it as unsupported"
  );
});

add_task(function test_validate_requirement() {
  Assert.deepEqual(
    PostureToolCatalog.validateRequirement({
      id: "curl",
      min_version: "1.0.0",
    }),
    {
      id: "curl",
      minVersion: "1.0.0",
    }
  );

  const rejected = [
    null,
    {},
    { id: "curl" },
    { id: "unknown-tool", min_version: "1.0.0" },
    { id: "../../bin/sh", min_version: "1.0.0" },
    { id: "curl", min_version: "; rm -rf /" },
    { id: "curl", min_version: "9".repeat(33) },
    { id: 42, min_version: "1.0.0" },
    { id: "constructor", min_version: "1.0.0" },
  ];
  for (const entry of rejected) {
    Assert.equal(
      PostureToolCatalog.validateRequirement(entry),
      null,
      `rejected ${JSON.stringify(entry)}`
    );
  }
});

add_task(function test_bin_dirs_are_absolute() {
  const { BIN_DIRS } = ChromeUtils.importESModule(
    "resource://gre/modules/enterprise/PostureToolCatalog.sys.mjs"
  );
  for (const dir of BIN_DIRS) {
    Assert.ok(dir.startsWith("/"), `${dir} is absolute`);
  }
});

add_task(function test_seed_requires_the_testing_gate() {
  // The seed injects requirements the console never sent, so it must be
  // unreachable unless explicitly enabled.
  Services.prefs.setStringPref(
    SEED_PREF,
    JSON.stringify([{ id: "curl", min_version: "1.0.0" }])
  );
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref(SEED_PREF);
    Services.prefs.clearUserPref(TESTING_PREF);
  });

  Services.prefs.setBoolPref(TESTING_PREF, false);
  Assert.deepEqual(
    PostureRemediation._seedRequirements(),
    [],
    "a set seed pref does nothing without the testing gate"
  );

  Services.prefs.setBoolPref(TESTING_PREF, true);
  Assert.deepEqual(
    PostureRemediation._seedRequirements(),
    [{ id: "curl", minVersion: "1.0.0" }],
    "with the gate open the seed is normalized like a console directive"
  );
});

add_task(function test_seed_is_validated_like_a_console_directive() {
  Services.prefs.setBoolPref(TESTING_PREF, true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref(SEED_PREF);
    Services.prefs.clearUserPref(TESTING_PREF);
  });

  // Unknown ids, junk versions and path-shaped ids go through the same
  // catalog validation the console's list does, so the seed cannot widen
  // what a requirement is allowed to name.
  Services.prefs.setStringPref(
    SEED_PREF,
    JSON.stringify([
      { id: "curl", min_version: "1.0.0" },
      { id: "definitely-not-a-tool", min_version: "1.0.0" },
      { id: "../../bin/sh", min_version: "1.0.0" },
      { id: "curl", min_version: "; rm -rf /" },
    ])
  );
  Assert.deepEqual(PostureRemediation._seedRequirements(), [
    { id: "curl", minVersion: "1.0.0" },
  ]);

  Services.prefs.setStringPref(SEED_PREF, "not json at all");
  Assert.deepEqual(
    PostureRemediation._seedRequirements(),
    [],
    "a malformed seed pref seeds nothing rather than throwing"
  );
});

add_task(function test_enforcement_defaults_to_warn() {
  registerCleanupFunction(() => Services.prefs.clearUserPref(ENFORCEMENT_PREF));

  Services.prefs.clearUserPref(ENFORCEMENT_PREF);
  Assert.equal(
    PostureRemediation.enforcement(),
    "warn",
    "an unset pref must not block anyone"
  );

  // A console that sends nothing, or something we do not understand, must not
  // be able to leave a fleet blocked.
  for (const bogus of ["", "BLOCK", "enforce", "true", "1", "warnn"]) {
    Services.prefs.setStringPref(ENFORCEMENT_PREF, bogus);
    Assert.equal(
      PostureRemediation.enforcement(),
      "warn",
      `${JSON.stringify(bogus)} falls back to warn`
    );
  }

  Services.prefs.setStringPref(ENFORCEMENT_PREF, "block");
  Assert.equal(PostureRemediation.enforcement(), "block");
  Services.prefs.setStringPref(ENFORCEMENT_PREF, "warn");
  Assert.equal(PostureRemediation.enforcement(), "warn");
});

add_task(function test_enforcement_write_normalizes() {
  registerCleanupFunction(() => Services.prefs.clearUserPref(ENFORCEMENT_PREF));

  Assert.equal(Enforcement.write("block"), "block");
  Assert.equal(Services.prefs.getStringPref(ENFORCEMENT_PREF), "block");

  // Absent overwrites rather than preserving: a console that stops sending
  // the field releases a blocked fleet instead of stranding it.
  Assert.equal(
    Enforcement.write(undefined),
    "warn",
    "an omitted mode resets to the safe default"
  );
  Assert.equal(Services.prefs.getStringPref(ENFORCEMENT_PREF), "warn");

  Enforcement.write("block");
  Assert.equal(Enforcement.write("nonsense"), "warn");
  Assert.equal(Services.prefs.getStringPref(ENFORCEMENT_PREF), "warn");
});

add_task(async function test_gate_releases_without_requirements() {
  PostureRemediation.testingOnly_reset();
  Assert.equal(
    await PostureRemediation.awaitCompliance({ isCancelled: () => false }),
    "no-requirements",
    "nothing required means nothing to wait for"
  );
});

add_task(function test_seed_enforcement_requires_the_testing_gate() {
  // "block" is what leaves a person without a browser, so the development
  // seed for it must be as unreachable as the requirements seed.
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref(SEED_ENFORCEMENT_PREF);
    Services.prefs.clearUserPref(ENFORCEMENT_PREF);
    Services.prefs.clearUserPref(TESTING_PREF);
  });
  Services.prefs.setStringPref(SEED_ENFORCEMENT_PREF, "block");

  Services.prefs.setBoolPref(TESTING_PREF, false);
  Assert.equal(
    Enforcement.write(undefined),
    "warn",
    "the seed must not apply without the testing gate"
  );

  Services.prefs.setBoolPref(TESTING_PREF, true);
  Assert.equal(
    Enforcement.write(undefined),
    "block",
    "with the gate open, an omitted directive falls back to the seed"
  );

  // A console that does send a mode still wins: the seed only fills a gap.
  Assert.equal(
    Enforcement.write("warn"),
    "warn",
    "an explicit directive is not overridden by the seed"
  );

  Services.prefs.setStringPref(SEED_ENFORCEMENT_PREF, "nonsense");
  Assert.equal(
    Enforcement.write(undefined),
    "warn",
    "an unusable seed falls back to the safe default"
  );
});
