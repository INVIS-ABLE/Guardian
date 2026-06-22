# Exception Process

Every deviation from a security control is an **exception** and must be recorded here (or in
the risk register) before it takes effect. No silent exceptions.

## Required fields (all mandatory)

| Field | Meaning |
| ----- | ------- |
| Owner | The accountable person (not a team). |
| Justification | Why the control cannot be met now. |
| Compensating controls | What reduces the risk in the meantime. |
| Expiry date | When the exception automatically lapses. |
| Review date | When it is re-evaluated before expiry. |
| Evidence | Link to PR/issue/ticket and any supporting analysis. |
| Approver | Someone **other than the requester** who approved it. |

## Rules

- An exception with no expiry is invalid — it is denied by default.
- The approver must be distinct from the requester (separation of duties).
- Production-affecting exceptions require two distinct approvers (mirrors the production
  two-person rule).
- On expiry the exception lapses automatically; continued deviation requires a new,
  re-justified exception.
- Exceptions are auditable evidence and are retained.

## Register

| ID | Control | Owner | Justification | Compensating | Approver | Expiry | Review | Evidence |
| -- | ------- | ----- | ------------- | ------------ | -------- | ------ | ------ | -------- |
| _none yet_ | | | | | | | | |
