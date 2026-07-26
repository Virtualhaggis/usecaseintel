# Rule packs — auto-generated SIEM-native exports

Generated: 2026-07-26T07:32:11Z

This directory contains per-platform versions of every internal use case
in the catalogue. Drop-in for the named SIEM, but **always disabled by
default** — review each rule against your environment before enabling.

| Directory | Format | Notes |
|---|---|---|
| `splunk/savedsearches.conf` | Splunk app config | Stanzas with full SPL embedded as comments. Enable per environment. |
| `sentinel/<uc>.json` | ARM template | Microsoft Sentinel analytics rule. Deploy with `az deployment group create`. |
| `sigma/<uc>.yml` | Sigma | Universal interchange — convert with sigma-cli to your SIEM dialect. |
| `elastic/<uc>.json` | Kibana detection rule | Lucene query compiled from the Sigma rule via pySigma. Keyword-seeded hunting logic — tune before enabling. |

Tier-aware defaults:
- `alerting` UCs schedule hourly, severity High
- `hunting` UCs schedule daily, severity Low

All exports include `tier`, `fp_rate_estimate`, `mitre_attack` annotations.
