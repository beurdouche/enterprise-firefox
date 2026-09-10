#!/usr/bin/env python3
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Builds and signs a remediation manifest for the Felt posture remediation tests.

Writes <tool-id>.manifest.json, <tool-id>.sig and <tool-id>.chain.pem next to the
certificates in this directory. Run it through mach so pykey is importable:

    ./mach python --virtualenv generate-test-certs \\
        toolkit/components/enterprise/tests/xpcshell/remediation/sign_manifest.py \\
        --tool-id felt-smoketest --script hello_world.sh

Regenerate the certificates first if a .certspec changed:

    ./mach generate-test-certs \\
        toolkit/components/enterprise/tests/xpcshell/remediation/remediation_int.pem.certspec \\
        toolkit/components/enterprise/tests/xpcshell/remediation/remediation_ee.pem.certspec

The signature is ECDSA P-384 over SHA-384 of b"Content-Signature:\\x00" + manifest,
base64url encoded -- the scheme ContentSignatureVerifier.cpp implements. Note this
does NOT reuse security/manager/ssl/tests/unit/test_content_signing/pysign.py: that
script still does str(base64.b64encode(sig)) and so emits a literal b'...' wrapper
under Python 3.
"""

import argparse
import base64
import datetime
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
TOPSRCDIR = HERE.parents[4]
sys.path.append(str(TOPSRCDIR / "security" / "manager" / "tools"))

import pykey  # noqa: E402

SCHEMA_VERSION = 1


def sign(data: bytes) -> str:
    key = pykey.ECCKey("secp384r1")
    sig = key.signRaw(b"Content-Signature:\x00" + data, pykey.HASH_SHA384)
    return base64.b64encode(sig).decode("ascii").replace("+", "-").replace("/", "_")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool-id", required=True)
    parser.add_argument("--target-version", default="1.0.0")
    parser.add_argument("--platform", default="macosx")
    parser.add_argument("--script", required=True, help="path relative to this directory")
    parser.add_argument("--interpreter", default="sh")
    parser.add_argument("--counter", type=int, default=1)
    # Fixed, not relative to now: the window has to stay inside the verifier's
    # MAX_VALIDITY clamp, and a fixture generated relative to its build date
    # would be a test that fails on a day nobody wrote down. Tests inject a
    # reference time inside this window instead.
    parser.add_argument("--not-before", default="2026-01-01T00:00:00Z")
    parser.add_argument("--valid-days", type=int, default=29)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument(
        "--corrupt-signature",
        action="store_true",
        help="flip a byte in the signature, for the negative test fixture",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="where to write the three files; defaults to this directory. "
        "The certificates are always read from this directory.",
    )
    args = parser.parse_args()
    out_dir = pathlib.Path(args.out_dir).resolve() if args.out_dir else HERE
    out_dir.mkdir(parents=True, exist_ok=True)

    script_bytes = (HERE / args.script).read_bytes()
    not_before = datetime.datetime.strptime(
        args.not_before, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=datetime.timezone.utc)
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "toolId": args.tool_id,
        "targetVersion": args.target_version,
        "platform": args.platform,
        "notBefore": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notAfter": (not_before + datetime.timedelta(days=args.valid_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "counter": args.counter,
        "remediate": {
            "interpreter": args.interpreter,
            "script": base64.b64encode(script_bytes).decode("ascii"),
            "timeoutMs": args.timeout_ms,
        },
    }

    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    text.encode("ascii")  # the verifier rejects anything else; fail loudly here

    signature = sign(text.encode("ascii"))
    if args.corrupt_signature:
        flipped = "A" if signature[0] != "A" else "B"
        signature = flipped + signature[1:]

    chain = (HERE / "remediation_ee.pem").read_text() + (
        HERE / "remediation_int.pem"
    ).read_text()

    (out_dir / f"{args.tool_id}.manifest.json").write_text(text)
    # The full Content-Signature header value, as the console would send it.
    (out_dir / f"{args.tool_id}.sig").write_text(f"p384ecdsa={signature}\n")
    (out_dir / f"{args.tool_id}.chain.pem").write_text(chain)
    print(f"wrote {args.tool_id}.manifest.json, .sig and .chain.pem in {out_dir}")


if __name__ == "__main__":
    main()
