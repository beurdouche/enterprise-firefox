#!/bin/sh
# Demo remediation payload, for the signed document under
# testing/enterprise/remediation-demo/.
#
# Deliberately kept out of the automated fixtures: `brew update` touches the
# network and rewrites Homebrew's formula index, which is not something a test
# run should do to the machine it runs on.
#
# Two visible effects, so it is obvious the signed script really executed:
#   1. writes Hello World and opens it in Zed
#   2. refreshes the Homebrew index
#
# Exit 90 is the "no package manager" convention the client reports without
# consuming the attempt budget.
set -eu

artifact="${FELT_REMEDIATION_ARTIFACT_DIR}/hello-world.txt"
printf 'Hello World\n' > "$artifact"
if [ -d /Applications/Zed.app ]; then
  /usr/bin/open -a /Applications/Zed.app "$artifact"
else
  /usr/bin/open -t "$artifact"
fi

brew=""
for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$candidate" ]; then
    brew="$candidate"
    break
  fi
done
[ -n "$brew" ] || { echo "no brew in either default prefix" >&2; exit 90; }

exec "$brew" update
