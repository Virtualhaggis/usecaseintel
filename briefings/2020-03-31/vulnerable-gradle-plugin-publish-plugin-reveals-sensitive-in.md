# [CRIT] Vulnerable Gradle plugin-publish plugin reveals sensitive information

**Source:** Snyk
**Published:** 2020-03-31
**Article:** https://snyk.io/blog/vulnerable-gradle-plugin/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
March 31, 2020
0 mins read Just a few days ago, on March 27, a security vulnerability was disclosed and published — CVE-2020-7599 — on Gradle's plugin-publish plugin. It affects all versions of the package below 0.11.0. The vulnerability was found on March 4 by Danny Thomas, Developer Productivity at Netflix, and reported to Gradle straight away.
Sensitive information The issue found in this package is a so-called “Insertion of Sensitive Inform…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-7599`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Gradle plugin-publish run with verbose logging leaks pre-signed AWS URL (CVE-2020-7599)

`UC_3093_1` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*publishPlugins*" OR Processes.process="*plugin-publish*" OR Processes.process="*com.gradle.plugin-publish*") AND (Processes.process="*--info*" OR Processes.process="*--debug*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("publishPlugins","plugin-publish","com.gradle.plugin-publish")
| where ProcessCommandLine has_any ("--info","--debug")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-7599`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
