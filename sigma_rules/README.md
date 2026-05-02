# Sigma rules

Platform-neutral detections in Sigma format
([sigmahq.io](https://sigmahq.io)). Each rule mirrors a curated UC
under `use_cases/` (one rule per UC where the detection fits Sigma's
event-shape model).

## What's here

Every YAML in this tree:
- Has a stable `id` (UUID) so a rule can be referenced from outside the
  repo.
- Carries `attack.t<id>` tags for ATT&CK technique enrichment.
- Validates against `pysigma` via `python sigma_export.py <rule>`.
- Compiles to at least one backend — Defender XDR KQL, Sentinel KQL,
  Splunk SPL, Elastic Lucene, etc.

## What's NOT here

Some UCs encode logic Sigma can't represent natively:
- **Threshold detections** (`> 200 file renames in 1m`) — Sigma has no
  built-in count operator.
- **Statistical detections** (beaconing, DNS-tunnel TXT-volume) — same.
- **Cross-table joins** (phishing email click → endpoint process spawn) —
  Sigma is single-event-shape.

For those, the curated UC's `defender_kql` / `sentinel_kql` / `splunk_spl`
remain the source of truth. The cheat-sheet's "compile to..." button is
only offered when a Sigma equivalent exists.

## Compile a rule

```
python sigma_export.py sigma_rules/exploit/UC_OFFICE_CHILD.yml --to kql
python sigma_export.py sigma_rules/exploit/UC_OFFICE_CHILD.yml --to spl
python sigma_export.py sigma_rules/exploit/UC_OFFICE_CHILD.yml --to lucene
```

Backends are loaded lazily — `pip install pysigma-backend-<target>`
before the first compile.
