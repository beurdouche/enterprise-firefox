#!/bin/sh
# Milestone 1 remediation payload: proves a verified signed script ran, with a
# visible effect. FELT_REMEDIATION_ARTIFACT_DIR is set by the executor.
set -eu
artifact="${FELT_REMEDIATION_ARTIFACT_DIR}/hello-world.txt"
printf 'Hello World\n' > "$artifact"
if [ -d /Applications/Zed.app ]; then
  /usr/bin/open -a /Applications/Zed.app "$artifact"
else
  /usr/bin/open -t "$artifact"
fi
