# [CRIT] Finding YAML Deserialization with Snyk Code

**Source:** Snyk
**Published:** 2023-02-23
**Article:** https://snyk.io/blog/finding-yaml-injection-with-snyk-code/

## Threat Profile

Snyk Blog In this article
Written by Calum Hutton 
February 23, 2023
0 mins read I conducted some research to try and identify YAML Injection issues in open-source projects using Snyk Code. Though the vulnerability itself is not a new one, the potential impact of YAML Injection is high, which made it a good candidate for research. This research led to the discovery of several issues in open-source projects written in Python, PHP and Ruby. This article focuses on the issue found in geokit-rails v…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-26153`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Ruby/Rails app server spawning a Unix shell (post-deserialization RCE)

`UC_1816_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("ruby","puma","unicorn","passenger","thin","rails")) AND (Processes.process_name IN ("sh","bash","dash")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ruby","puma","unicorn","passenger","thin","rails")
| where FileName in~ ("sh","bash","dash")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-26153`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
