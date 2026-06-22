# [CRIT] Kernel privilege escalation: how Kubernetes container isolation impacts privilege escalation attacks

**Source:** Snyk
**Published:** 2020-12-03
**Article:** https://snyk.io/blog/kernel-privilege-escalation/

## Threat Profile

Snyk Blog In this article
Written by Kamil Potrec 
December 3, 2020
0 mins read During the day, I spend my time analyzing Terraform code, Kubernetes object configuration files, and identifying common security issues. When the sun sets, I put on my hoodie, fire up Linux VMs and debuggers to look under the hood of technologies that make up the cloud native ecosystem.
In this post, we will explore how Kubernetes container isolation impacts privilege escalation attacks. We will use common kernel exp…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2017-7308`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Kernel privilege escalation: how Kubernetes container isolation impacts privileg

`UC_2940_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Kernel privilege escalation: how Kubernetes container isolation impacts privileg ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/dev/exploit*" OR Filesystem.file_path="*/etc/shadow*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Kernel privilege escalation: how Kubernetes container isolation impacts privileg
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/dev/exploit", "/etc/shadow"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2017-7308`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
