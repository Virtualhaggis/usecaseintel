# [HIGH] Building Java container images using Jib

**Source:** Snyk
**Published:** 2021-08-17
**Article:** https://snyk.io/blog/building-java-container-images-using-jib/

## Threat Profile

Snyk Blog In this article
Written by Eric Smalling 
August 17, 2021
0 mins read Suppose you’ve been working with container images for more than a minute. In that case, you’re probably familiar with those ubiquitous documents that describe, layer-by-layer, the steps needed to construct an image: Dockerfiles. Did you know that there is a growing set of tools for building OCI compliant images without Dockerfiles? In this article, we will look at Jib , a 100% Java-based tool that can build highly op…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `da844eca910f44e825c72121f4ec9700b3c9eec8d4c2407f926cdad0799b33e8`
- **SHA1:** `960d768e9739ffb8e9a503c9ad3f6dad86ac68b1`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Building Java container images using Jib

`UC_2799_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Building Java container images using Jib ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/java/o*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Building Java container images using Jib
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/java/o"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `da844eca910f44e825c72121f4ec9700b3c9eec8d4c2407f926cdad0799b33e8`, `960d768e9739ffb8e9a503c9ad3f6dad86ac68b1`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
