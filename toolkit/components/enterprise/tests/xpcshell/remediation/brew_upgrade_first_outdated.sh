#!/bin/sh
# Demo remediation payload: upgrade the first formula Homebrew reports as out
# of date.
#
# The formula is resolved here, at run time, rather than baked into the signed
# document or passed in from the client. Two reasons: the document stays valid
# as the machine's outdated set changes, and nothing dynamic has to be
# interpolated into a command line.
#
# Deliberately kept out of the automated fixtures: this upgrades real software
# on the machine it runs on, which is not something a test run should do.
#
# Exit 90 is the "no package manager" convention the client reports without
# consuming the attempt budget.
set -eu

brew=""
for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$candidate" ]; then
    brew="$candidate"
    break
  fi
done
[ -n "$brew" ] || { echo "no brew in either default prefix" >&2; exit 90; }

# No HOMEBREW_NO_AUTO_UPDATE here, unlike the client's detection probe: with a
# stale index there may be nothing newer to install and the upgrade would
# never converge.
first=$("$brew" outdated --quiet | head -1)
if [ -z "$first" ]; then
  echo "nothing outdated" >&2
  exit 0
fi

echo "upgrading $first" >&2
exec "$brew" upgrade "$first"
