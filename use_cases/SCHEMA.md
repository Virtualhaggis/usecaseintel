# Use Case YAML schema

Each `.yml` file in `use_cases/<kill_chain>/` describes ONE detection use case
implemented as a Splunk CIM SPL query and/or a Defender Advanced Hunting KQL
query. The conceptual detection idea is shared; the per-platform implementation
lives in the same file so reviewers can verify both versions match semantically.

## Required fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Stable identifier; convention `UC_<UPPER_SNAKE>` |
| `title` | string | One-line human description |
| `kill_chain` | string | One of `recon`, `weapon`, `delivery`, `exploit`, `install`, `c2`, `actions` |
| `confidence` | string | `High` / `Medium` / `Low` |
| `description` | string (literal block) | Multi-paragraph rationale |
| `implementations` | string[] | Subset of `[splunk, defender]` |
| `mitre_attack` | object[] | Each `{id: T1234[.NNN], name: 'Display Name'}` |
| `data_models.splunk` | string[] | Splunk CIM dataset paths |
| `data_models.defender` | string[] | Defender XDR table names |

## Conditional fields

- `splunk_spl` (literal block) — required if `splunk` is in `implementations`.
  Must use canonical CIM paths (`from datamodel=Endpoint.Processes`) and field
  references (`Processes.dest`). Validate with `python pipeline/validate.py`.
- `defender_kql` (literal block) — required if `defender` is in
  `implementations`. Must use Defender XDR Advanced Hunting tables and columns.

See any existing `UC_*.yml` for examples.
