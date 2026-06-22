# Emergency freeze procedure

When the Merge Governor (or any observer) detects a freeze trigger, **stop all merges**
and raise a `steward:freeze` issue immediately. Containment precedes convenience.

## Freeze triggers

- Default branch changed unexpectedly (away from the agreed canonical `main`).
- Direct push to a protected branch, or force-push / history rewrite on one.
- Required branch protection or a required check removed or made non-blocking.
- A GitHub Action changed from a pinned ref to a mutable tag, or a production image
  changed from a digest to a mutable tag.
- A secret committed or exposed (never paste the secret value into the issue).
- Authorization bypass introduced; ownership verification weakened; production approval
  count reduced; audit/evidence made optional; Shadow-verification disabled.
- Unknown administrator / GitHub App added; workflow permissions widened unexpectedly;
  self-hosted runner added without review.
- A worker targets a third-party asset, or a change could expose vulnerable users or
  private content.
- Capability status inflated without evidence; repository history rewritten; multiple
  competing canonical branches appear.

## Freeze issue contents

- Time detected (UTC) and how.
- The commit / settings change (link, not secret values).
- Actor where visible.
- Affected branches and PRs.
- Immediate containment taken.
- Evidence links.
- The specific owner decision required to lift the freeze.

## Lifting a freeze

Only after the owner-required decision is recorded, the trigger is remediated through a
reviewed PR, and the full security suite is re-run green. Document the resolution in the
freeze issue and the merge ledger.

## Stop conditions (request owner direction rather than guessing)

Both branches contain incompatible security-critical implementations; the authoritative
crypto/authz model is unclear; a branch contains unexplained binaries/secrets/generated
artifacts; required human reviewers do not exist; branch protection blocks a lawful
merge; required checks are unavailable/contradictory; a change appears to enable
offensive use outside verified owned assets; a merge would erase unique history; a
repository setting changed unexpectedly; evidence of compromise.

Partial reconciliation with a precise blocked report is preferable to an unsafe merge.
