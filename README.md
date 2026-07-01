# Clankerusecase — Threat-led detection library

**[▶ Browse the live library at clankerusecase.com](https://clankerusecase.com/)**

Ready-to-tune SOC detections, generated continuously from current threat intel
and mapped to MITRE ATT&CK. Every use case ships in **Microsoft Defender KQL,
Sentinel KQL, Sigma, Splunk SPL, Datadog, CrowdStrike Falcon LogScale, and AWS
CloudWatch Logs Insights** — schema-validated before it's published.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Detections](https://img.shields.io/badge/detections-7%2C800%2B-blue)
![Formats](https://img.shields.io/badge/formats-KQL%20%7C%20Sigma%20%7C%20SPL%20%7C%20Datadog%20%7C%20Falcon%20%7C%20CloudWatch-informational)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ These are **starting points**, not drop-in production rules. Test in
> staging, tune allowlists to your environment, then promote. See
> [limitations](https://clankerusecase.com/about.html).

## What you get

- **7,800+ detections** across 700+ ATT&CK techniques, refreshed every ~2 hours.
- **Threat-led**, not generic — each detection ties back to a public report
  (BleepingComputer, The Hacker News, Microsoft, Cisco Talos, ESET, Unit 42,
  SentinelLabs, Securelist, Lab52, CISA KEV, GitHub Security Advisories).
- **Seven query languages per use case** — copy the one your stack speaks.
- **Machine-readable IOC feeds** you can wire straight into a SIEM:
  - [`intel/iocs.csv`](https://clankerusecase.com/intel/iocs.csv) ·
    [`iocs.json`](https://clankerusecase.com/intel/iocs.json) ·
    [`iocs.stix.json`](https://clankerusecase.com/intel/iocs.stix.json) (STIX 2.1) ·
    [`splunk_lookup_iocs.csv`](https://clankerusecase.com/intel/splunk_lookup_iocs.csv) ·
    [`iocs.rss.xml`](https://clankerusecase.com/intel/iocs.rss.xml) (RSS)
- **Sigma + Elastic rule packs** in `rule_packs/` (deterministic UUIDs,
  pySigma-parseable; Elastic rules compiled via pySigma's ES backend).

## Who it's for

SOC analysts, detection engineers, and CTI teams who want to go from
*"I just read about this campaign"* to *"here's the query I run"* in one click —
without hand-writing the same logic seven times.

## How to use it

1. **Browse** [clankerusecase.com](https://clankerusecase.com/) — filter by
   platform, ATT&CK technique, threat actor, or search a CVE/malware name.
2. **Copy** the query in your SIEM's language.
3. **Tune** allowlists and thresholds for your environment, validate against
   your own telemetry, then deploy.
4. Prefer automation? Pull the [IOC feeds](https://clankerusecase.com/intel/iocs.json)
   or [RSS](https://clankerusecase.com/intel/iocs.rss.xml) directly.

## How it's built & what's validated

Threat-intel articles are parsed for IOCs + ATT&CK techniques, an LLM drafts
detections, and every query is **schema/syntax-validated** before publish
(Defender/Sentinel via Microsoft's Kusto.Language grammar against a 58-table /
1,600+ column schema; Splunk structurally; Sigma via pySigma). A safety denylist
blocks dangerous constructs (`outputlookup`, `sendemail`, `externaldata`, …).

**What it does NOT do:** run queries against live telemetry, measure real-world
false-positive rates, or guarantee performance. Full methodology + honest
limitations: **[clankerusecase.com/about.html](https://clankerusecase.com/about.html)**.

## Contributing

Found a bad detection? **[Open an issue](https://github.com/Virtualhaggis/usecaseintel/issues/new)**
— corrections feed straight back into the generation pipeline.

## Development

Pipeline internals, validators, and scheduling are documented in
[`DEVELOPERS.md`](./DEVELOPERS.md).

## License

MIT — see [`LICENSE`](./LICENSE). Detections provided as-is, no warranty.
Built by [Virtualhaggis](https://clankerusecase.com/about.html).
