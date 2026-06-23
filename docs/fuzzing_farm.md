# Guardian Continuous Fuzzing Farm

> **Sovereign plane, Wave 3, system #14.** CI fuzzing of the security-critical parsers — crypto
> envelopes, attachments, tokens, evidence formats — so Guardian finds the crash in the lab
> before an attacker finds it in production ([`sovereign_ops_plane.md`](sovereign_ops_plane.md);
> upstream: ClusterFuzzLite / AFL++ / Atheris / Jazzer). First slice in
> [`core/fuzzing/`](../core/fuzzing).

The [`FuzzFarm`](../core/fuzzing/farm.py) turns a noisy crash stream into durable knowledge:

- **Dedup by signature** — a thousand inputs that hit the same bug collapse to one `UniqueCrash`
  (keeping the worst severity seen and the first input as the seed).
- **A regression seed per unique crash** — so the bug can never silently return.
- **Gate** — `fuzz-gate` exits non-zero if the campaign found any new unique crash.

```bash
guardian fuzz fuzzing/invisable-fuzz-campaign.yaml
#   ✗ critical crash      fuzz:crypto-envelope  ×3  seed sha256:1111aaaa
#   regression seeds minted (3): crypto_envelope must not crash on seed sha256:1111…
guardian fuzz-gate fuzzing/invisable-fuzz-campaign.yaml   # exits non-zero on any new crash
```

**Metadata-only:** crash inputs are referenced by hash, never inlined — a malicious corpus entry
never becomes content the model ingests. `from_clusterfuzz()` fails closed (an empty report is
not "no crashes"). It adjudicates a fuzzer's output and asserts no authority (level 3).
