# Tool-manifest gateway (`core/tools`)

Build-order step 5 replaces the hard-coded capability→tool-name map
(`core.router.CAPABILITY_MAP`) with **signed, versioned manifests**, **one-use
capability tokens**, and a **bounded executor** that refuses unknown capabilities with a
structured result instead of throwing.

```
capability ─▶ ToolRegistry.resolve(capability, environment)
                 │  verify signature (fail closed in staging/prod), check env allow-list
                 ▼
             ToolManifest  (pinned image_digest, schemas, network/fs/resource limits)
                 │
ToolExecutor.execute(case_id, args, environment, approved)
   1. resolve manifest          (unknown/forged/disallowed → structured ToolRefusal)
   2. enforce requires_approval
   3. mint a ONE-USE CapabilityToken bound to case + tool digest + args hash + env + budget
   4. consume the token (single use, expiry-checked)
   5. run under the manifest's limits via a pluggable ToolRunner
                 ▼
             ToolExecution(tool, image_digest, token_id, output, output_hash, truncated)
```

## What a manifest pins (§13)

`capability`, `tool`, `manifest_version`, `image_digest` (sha256 of the pinned image),
`input_schema` / `output_schema`, `allowed_environments`, `requires_approval`,
`network` (`deny_all` by default), `filesystem` (input read-only, output ephemeral), and
`limits` (cpu / memory / runtime / output bytes). Manifests are HMAC-signed
(`GUARDIAN_MANIFEST_KEY`); in a staging/production posture an unsigned/forged manifest is
**refused** — the dev default key is never accepted there.

## One-use capability tokens

`issue_token` binds a token to the exact call: case id, tool digest, args hash, input
artifact hashes, environment, network policy, resource budget and an expiry. The token is
re-verified against that binding and **consumed once** (`TokenStore`), so it cannot
authorise a different call, be replayed, or outlive its window.

## Structured refusals, never exceptions

Unknown/hallucinated capability, forged signature, environment not allowed, approval
required, token rejected — each returns a `ToolRefusal(reason=…)`. A model that asks for a
tool that doesn't exist gets a clean refusal, not a crash.

## Fail-closed execution

The default `DryRunRunner` does **not** execute a real container: isolated execution needs
a configured sandbox backend, so without one the executor degrades to a bounded dry-run
plan rather than shelling out. A real sandbox runner slots in behind the `ToolRunner`
interface, and the `output_hash` + `image_digest` feed straight into evidence provenance.

## Status

The gateway is implemented and tested. Migrating the reasoning-graph collectors and the
legacy `ToolRouter` onto manifests, adding the JSON input/output schema files, and wiring a
real sandbox runner are follow-ups; `CAPABILITY_MAP` stays in place until then.
