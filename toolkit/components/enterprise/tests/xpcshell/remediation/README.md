# Signed remediation fixtures

Test data for `test_remediation_verifier.js`. Each fixture is a signed
remediation document in three parts, mirroring what the enterprise console will
serve:

| File | Contents |
|---|---|
| `<id>.manifest.json` | The exact ASCII bytes that were signed |
| `<id>.sig` | `p384ecdsa=<base64url>` — the Content-Signature header value |
| `<id>.chain.pem` | End-entity certificate followed by the intermediate |

## Certificates

`remediation_ee.pem` chains to `remediation_int.pem`, which chains to the
in-tree `xpcshell signed apps test root`. The end entity is valid for
`remediation.enterprise-firefox.mozilla.org`, which `RemediationVerifier` pins
as `SIGNER_NAME`.

`remediation_wrongsan_ee.pem` uses the **same key** but a different subject
alternative name, so a document signed for the good chain still verifies
cryptographically against it and fails only the name check. That is what lets
`test_wrong_san_is_rejected` isolate SAN pinning.

Regenerate after editing any `.certspec`:

```
./mach generate-test-certs \
  toolkit/components/enterprise/tests/xpcshell/remediation/remediation_int.pem.certspec \
  toolkit/components/enterprise/tests/xpcshell/remediation/remediation_ee.pem.certspec \
  toolkit/components/enterprise/tests/xpcshell/remediation/remediation_wrongsan_ee.pem.certspec
```

## Manifests

Signing needs `pykey`, so run the script through mach. Regenerate all five after
editing `hello_world.sh` or the manifest schema:

```
M="./mach python --virtualenv generate-test-certs toolkit/components/enterprise/tests/xpcshell/remediation/sign_manifest.py"

$M --tool-id felt-smoketest        --script hello_world.sh --counter 1
$M --tool-id felt-smoketest-badsig --script hello_world.sh --counter 1 --corrupt-signature
$M --tool-id felt-expired          --script hello_world.sh --counter 1 --not-before 2020-01-01T00:00:00Z
$M --tool-id felt-downgrade        --script hello_world.sh --counter 1 --target-version 0.5.0
$M --tool-id felt-badinterp        --script hello_world.sh --counter 1 --interpreter python
$M --tool-id felt-protointerp      --script hello_world.sh --counter 1 --interpreter constructor
```

`felt-protointerp` names `constructor` as its interpreter: on a plain object
literal that lookup returns something truthy, so it pins the interpreter map's
null prototype.

## Why the validity window is a fixed date

The window is `2026-01-01` to `2026-01-30`, written into the fixture rather than
computed from the generation date. Two constraints meet here: the verifier
clamps a document's validity to 30 days, so the window cannot simply be made
enormous; and a window relative to generation time would turn these into tests
that fail on a date nobody wrote down.

So the fixtures pin the window and the tests inject a reference `now` inside it
(`RemediationVerifier.verify(signed, { now })`). Injecting the clock is the same
approach `cache_is_usable` takes in `toolkit/components/felt/rust/src/edr_checker.rs`.

## Note on `pysign.py`

These fixtures deliberately do **not** call
`security/manager/ssl/tests/unit/test_content_signing/pysign.py`. That script
still does `str(base64.b64encode(sig))`, which was correct under Python 2 but
under Python 3 emits a literal `b'...'` wrapper around the signature. Its
checked-in `test.txt.signature` predates the migration and is clean, so the bug
is latent. `sign_manifest.py` implements the same scheme correctly.
