# Rule packs — auto-generated SIEM-native exports

Generated: 2026-06-12T04:33:27Z

This directory contains per-platform versions of every internal use case
in the catalogue. Drop-in for the named SIEM, but **always disabled by
default** — review each rule against your environment before enabling.

| Directory | Format | Notes |
|---|---|---|
| `splunk/savedsearches.conf` | Splunk app config | Stanzas with full SPL embedded as comments. Enable per environment. |
| `sentinel/<uc>.json` | ARM template | Microsoft Sentinel analytics rule. Deploy with `az deployment group create`. |
| `sigma/<uc>.yml` | Sigma | Universal interchange — convert with sigma-cli to your SIEM dialect (incl. Elastic). |

Elastic-native rules are not exported yet — a previous version shipped
placeholder stubs, which was worse than nothing. Until the KQL->ECS/EQL
port lands, compile the Sigma rules to your Elastic dialect via sigma-cli.

Tier-aware defaults:
- `alerting` UCs schedule hourly, severity High
- `hunting` UCs schedule daily, severity Low

All exports include `tier`, `fp_rate_estimate`, `mitre_attack` annotations.
