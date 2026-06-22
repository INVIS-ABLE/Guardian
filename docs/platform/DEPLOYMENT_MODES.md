# Deployment Modes

*Phase 0 deliverable. Maps to `core.tenancy.DeploymentMode`.*

Each tenant declares a deployment mode. The mode drives **egress, data residency,
model-provider, and key-management** policy. Default-deny applies: a mode never
*grants* network/data freedom — it constrains it.

| Mode (`DeploymentMode`) | Control plane | Workers | Egress posture | Typical customer |
|--------------------------|---------------|---------|----------------|------------------|
| `single_tenant_self_hosted` | Customer-hosted | Customer-hosted | Closed by default; explicit allowlist | Security-conscious SME, charity |
| `multi_tenant_saas` | Guardian-hosted, tenant-partitioned | Guardian-hosted | Per-tenant egress policy; strict isolation | Startups, SMEs |
| `private_cloud` | Customer's cloud account | Customer's cloud | Customer VPC controls | Enterprise |
| `managed_dedicated` | Guardian-operated, single-tenant | Dedicated | Contractual residency | Regulated org |
| `air_gapped` | Customer-hosted, offline | Customer-hosted | **No external egress**; local-only models | Public sector, defence |
| `hybrid` | Guardian-hosted control plane | Customer-hosted workers | Workers never send raw data out; only signed results return | Enterprise with data-residency rules |

## Cross-cutting requirements

- **Bring-your-own-model / bring-your-own-scanner / customer-managed keys** are
  first-class options, strongest in `air_gapped` and `hybrid`.
- **Sensitive analysis stays local** where the mode requires it; external model
  providers are opt-in per tenant and never see privacy-forbidden classes
  (`core/evidence/models.py` `PRIVACY_FORBIDDEN`).
- **Air-gapped** must function with the in-memory evidence store, in-Python policy
  fallback, and offline RAG — all of which already exist (`README.md`, `core/`).
- **Hybrid** workers return only schema-validated, normalised findings and signed
  evidence digests through the untrusted-output gateway; raw target data and secrets
  never leave the customer boundary.

## How a mode is enforced (target design)

1. Tenant's `deployment_mode` selects an **egress profile** (`isolation/egress.py`)
   and a **data-residency policy** (per DATA_CLASSIFICATION_AND_RESIDENCY.md).
2. The signed execution plan records the mode; workers inherit the egress profile.
3. The untrusted-output gateway enforces that only allowed data classes cross the
   boundary for that mode.

The mode is recorded on the `Tenant` today; binding it to egress/residency
enforcement is Phase C of the migration.
