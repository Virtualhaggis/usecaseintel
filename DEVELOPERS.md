# Developer docs — Clankerusecase pipeline

> These are the internal build/pipeline docs. For what the project is and how to
> use it, see [`README.md`](./README.md) or the live site at
> [clankerusecase.com](https://clankerusecase.com/).

## Pipeline overview (formerly "THN Threat Atlas")

Pulls the latest 10 articles from [The Hacker News](https://thehackernews.com/),
extracts security indicators + ATT&CK techniques + kill chain phases, and
auto-generates Splunk SPL (CIM-conformant) and Microsoft Defender Advanced
Hunting KQL detections per article.

## File map

```
thn-usecases/
  generate.py           ← Build the static site (index.html)
  sync.py               ← Pull authoritative sources -> registry.json
  validate.py           ← Verify generate.py SPL + ATT&CK refs are spec-valid
  data_sources/
    registry.json       ← Built by sync.py (CIM datasets, ESCU detections, ATT&CK)
    cim_spec_fields.json ← Hand-curated CIM 8.5 spec fields not seen in ESCU
    defender_spec_tables.json ← Hand-curated Defender XDR schema (Microsoft Learn)
    sync_log.json       ← Last sync metadata
    validation_report.json ← Last validation result
  CHANGELOG.md          ← Auto-appended by sync.py on each run
  index.html            ← The generated site
```

## Workflow

```
+-------------+       +----------+       +---------------+
| sync.py     |  -->  | registry |  -->  | validate.py   |
| (weekly)    |       | .json    |       | (every build) |
+-------------+       +----------+       +---------------+
                            |
                            v
                      +-------------+
                      | generate.py | --> index.html
                      | (daily)     |
                      +-------------+
```

### 1) `sync.py` — pull authoritative sources

Pulls (no auth required, all public):
- **Splunk Security Content (ESCU)** — `splunk/security_content` develop branch
  tarball. Source of truth for what CIM datasets/fields are *actually* used in
  production Splunk detection content.
- **MITRE ATT&CK enterprise-attack STIX bundle** — `mitre-attack/attack-stix-data`
  master. Canonical list of all current technique IDs + names + tactics.

Builds `data_sources/registry.json` with:
- `cim_datasets` — `{full_path: [field_names]}` derived from real ESCU SPL.
- `escu_detections` — slim copy of every ESCU TTP/Anomaly/Hunting detection.
- `attack_techniques` — `{TID: {name, kill_chain_phases, deprecated}}`.
- `attack_tactics` — `{shortname: long_name}`.

Run weekly (or on demand):
```
py sync.py
```

### 2) `validate.py` — verify SPL **and** KQL templates

Splunk SPL checks (per `UseCase`):
- Extracts `from datamodel=X.Y` and `nodename="X.Y"` references.
- Extracts `Y.field_name` references.
- Checks dataset path exists in ESCU usage OR `cim_spec_fields.json` allowlist.
- Checks every field is valid against the same union.

Defender KQL checks (per `UseCase`):
- Identifies every Defender XDR table referenced (`DeviceProcessEvents`, `EmailEvents`, `AADSignInEventsBeta`, etc.).
- Extracts column references in `| where Col`, `| project ...` (alias-aware).
- Validates against the union of "observed in `microsoft/Microsoft-365-Defender-Hunting-Queries`" and the hand-curated `defender_spec_tables.json` schema allowlist.
- Flags Defender-shaped table names that aren't in the schema (e.g. typos).

ATT&CK checks:
- Every technique ID exists in the current MITRE catalog and isn't deprecated.

Failure modes:
- **Errors** (exit 1) — unknown CIM dataset/field, unknown Defender table, missing/deprecated ATT&CK ID.
- **Warnings** — column name not found in any referenced Defender table (likely typo or alias issue).
- **Infos** — spec-valid identifier never used in production corpus (still passes).

Run:
```
py validate.py
```

### 3) `generate.py` — build the site

Pulls last 10 RSS articles, runs the rule engine, renders the HTML:
```
py generate.py
```

Query-output behaviour worth knowing:

- **Quality-review feedback loop (closed).** Pending UC suggestions from
  `quality_review.py` (`intel/quality_suggestions.jsonl`) are folded into
  every fresh LLM UC prompt. Articles whose UCs are already cached get a
  bounded number of suggestion-driven regenerations per run —
  `USECASEINTEL_SUGGESTION_REGEN_BUDGET` (default 10). Each cache entry is
  stamped with a digest of the suggestions it consumed, so the same
  feedback never triggers a second regeneration.
- **Sentinel KQL auto-derivation.** Any use case that ships Defender KQL
  but no Sentinel KQL (template + bespoke UCs, and LLM UCs that left the
  field empty) gets a mechanically derived Sentinel variant
  (`Timestamp` → `TimeGenerated`, M365 Defender connector tables only).
  Queries touching non-streamable tables (`DeviceTvm*`, `AADSignInEventsBeta`,
  …) are left without a Sentinel variant rather than shipping a broken one.
- **Article-aware KQL knowledge.** UC prompts carry the slim knowledge base
  plus only the `knowledge/kql_examples.md` / `kql_tables.md` sections that
  match the article's TTP shape (phishing → email-click few-shot +
  EmailEvents recipe, ransomware → shadow-copy example, …). Keeps the May
  2026 token reduction while restoring the targeted few-shots that
  `validate_kql_knowledge.py` asserts (4/4 prompt-shape tests green).
- **Quality regeneration of cached UCs.** Cache entries whose stored queries
  still carry schema/syntax validation issues get one fresh LLM pass —
  bounded per run by `USECASEINTEL_QUALITY_REGEN_BUDGET` (default 5),
  stamped so a failed regen is never retried under the same cache key.
- **Spec-valid Sigma + compiled Elastic rules.** `rule_packs/sigma/*.yml`
  now carry deterministic UUID ids (Sigma spec) and YAML-safe quoting, so
  they parse in standard pysigma/sigma-cli tooling. Each Sigma rule is also
  compiled to a Lucene query via pySigma's elasticsearch backend and shipped
  as a Kibana detection rule in `rule_packs/elastic/<uc>.json` (disabled by
  default, hunting-grade).
- Regression checks for all of the above live in `_smoke_pipeline_changes.py`.

## Authoritative documentation

These are the upstream references the pipeline keeps us aligned with:

### Splunk
- [Splunk CIM 8.5 — Overview](https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/overview-of-the-splunk-common-information-model)
- [CIM Endpoint data model](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- [SPL Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Search Macros](https://help.splunk.com/en/splunk-enterprise/search/searchsyntax/9.5/searchmacros)
- [Splunk Security Content (ESCU)](https://github.com/splunk/security_content) — gold-standard production SPL
- [research.splunk.com](https://research.splunk.com) — searchable detection catalog
- [Splunk contentctl](https://github.com/splunk/contentctl) — Splunk's own validation CLI
- [CIM Add-on on Splunkbase](https://splunkbase.splunk.com/app/1621)

### Microsoft Defender / Sentinel
- [Defender XDR Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft 365 Defender Hunting Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [Azure Sentinel community detections](https://github.com/Azure/Azure-Sentinel)

### Cross-platform
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/techniques/enterprise/)
- [MITRE attack-stix-data (canonical JSON)](https://github.com/mitre-attack/attack-stix-data)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma) — vendor-neutral detection format

## Updating

When the CIM spec changes (8.5 → 8.6 etc.), update the `cim_spec_fields.json`
allowlist by hand from the latest [Splunk CIM docs](https://help.splunk.com/en/data-management/common-information-model)
data-model pages.

ESCU and ATT&CK refresh automatically on `sync.py` runs. Diff is appended to
`CHANGELOG.md` so drift is visible.

## Scheduling — running this on autopilot

Two batch wrappers are included:

| Script | What it does | Suggested cadence |
|---|---|---|
| `run_daily.bat` | validate → generate → digest (writes `daily_digest.md`) | daily, e.g. 08:00 |
| `run_weekly.bat` | sync → daily | weekly, e.g. Mon 06:00 |

Both write to `logs\<flow>_YYYY-MM-DD.log`.

`digest.py` produces:
- `daily_digest.md` — markdown summary of new articles since last run + all High/Critical
- `data_sources/last_run.json` — state for the next-run diff
- Optional webhook POST when `WEBHOOK_URL` env var is set (for Slack/Teams/email-relay)

### Register with Windows Task Scheduler

Run **as your user** (no admin needed) in an elevated `cmd` or PowerShell:

```
schtasks /create /tn "THN Daily" /tr "C:\Users\mckec\Downloads\DexCore 1.1.9\thn-usecases\run_daily.bat" /sc daily /st 08:00 /f

schtasks /create /tn "THN Weekly Sync" /tr "C:\Users\mckec\Downloads\DexCore 1.1.9\thn-usecases\run_weekly.bat" /sc weekly /d MON /st 06:00 /f
```

Optional — set the webhook URL system-wide before registering:

```
setx WEBHOOK_URL "https://hooks.example.com/your-webhook"
```

Verify:

```
schtasks /query /tn "THN Daily"
schtasks /query /tn "THN Weekly Sync"
```

Run on demand:

```
schtasks /run /tn "THN Daily"
```

Remove later:

```
schtasks /delete /tn "THN Daily" /f
schtasks /delete /tn "THN Weekly Sync" /f
```
