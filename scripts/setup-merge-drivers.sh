#!/usr/bin/env bash
# Register the git merge drivers referenced by .gitattributes (one-time, per clone).
#
# The generated inventory reports (reports/audit/current_state.*) are marked `merge=ours` so
# concurrent PRs never textually conflict on them; they are regenerated against the merged tree
# afterwards. `merge=ours` uses git's built-in `true` no-op driver, which must be registered in
# local config (it cannot be committed). Run this after cloning:
#
#     scripts/setup-merge-drivers.sh
set -euo pipefail

git config merge.ours.driver true
echo "registered merge driver: merge.ours.driver=true (keeps ours for generated inventory reports)"
