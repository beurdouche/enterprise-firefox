#!/bin/sh
# Milestone 2 remediation payload: bring a Homebrew formula up to date.
#
# Runs unprivileged as the signed-in user, which is all Felt can do -- it has
# no way to elevate. The brew prefixes are written out here rather than taken
# from $PATH or $HOMEBREW_PREFIX, both of which are caller-controlled input
# naming a program to run.
#
# Exit 90 is the "no package manager" convention: the client reports it without
# consuming the attempt budget, since it cannot succeed until an administrator
# provisions Homebrew.
set -eu
FORMULA="jq"

brew=""
for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$candidate" ]; then
    brew="$candidate"
    break
  fi
done
[ -n "$brew" ] || { echo "no brew in either default prefix" >&2; exit 90; }

# install fails when the formula is already present and upgrade fails when it
# is absent, so choose by what is actually on the machine rather than trusting
# either to be a no-op. HOMEBREW_NO_AUTO_UPDATE is deliberately *not* set: with
# a stale index there is nothing newer to install and upgrade never converges.
if "$brew" list --versions "$FORMULA" >/dev/null 2>&1; then
  exec "$brew" upgrade "$FORMULA"
else
  exec "$brew" install "$FORMULA"
fi
