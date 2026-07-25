# [HIGH] Container image formats under the hood

**Source:** Snyk
**Published:** 2020-11-18
**Article:** https://snyk.io/blog/container-image-formats/

## Threat Profile

Snyk Blog In this article
Written by Agata Krajewska 
November 18, 2020
0 mins read Over the last few years, following Docker's release, containers have become more and more the standard mechanism for software delivery.
We see a growing number of container-based solutions and while innovation in the space is obviously welcomed, there is a requirement for establishing certain standards around format and runtime .
Because of the rapid growth of Docker project, Docker images became a standard for m…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `46076a325f0de3f745254638b8b0f0de343685b34e7ca6ec5cd0b6b7930eb7fa`
- **SHA256:** `468327b5cd7ce539db695bd0ef05dae8a4ff77b02870a8e823ed74dedad4bd55`
- **SHA256:** `56def654ec22f857f480cdcc640c474e2f84d4be2e549a9d16eaba3f397596e9`
- **SHA256:** `8bf067b107a6f7444876e33c6ed85652355f679ac98ebab97ab3ebad63f0dff3`
- **SHA256:** `afa93a8ce255ca452ca8c88f4b5c821a466cf0a3e0148a31d0d97dfdb91d9aef`
- **SHA256:** `33a51d09088285451e7a7525d4bd64fc15563264afe5a91ef84a8b3042018899`
- **SHA256:** `171857c49d0f5e2ebf623e6cb36a8bcad585ed0c2aa99c87a055df034c1e5848`
- **SHA256:** `419640447d267f068d2f84a093cb13a56ce77e130877f5b8bdb4294f4a90a84f`
- **SHA256:** `61e52f862619ab016d3bcfbd78e5c7aaaa1989b4c295e6dbcacddd2d7b93e1f5`
- **SHA256:** `45c6f8f1b2fe15adaa72305616d69a6cd641169bc8b16886756919e7c01fa48b`
- **SHA256:** `e80b8affb2361dc632c1fa8fcbf6b6514f750eb6ef99b7e7f825a55f849bfd89`
- **SHA256:** `01a2038b20d165ab7df81934f9849bdfbc59bd6f6322c5d11e341504f66ec266`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Container image formats under the hood

`UC_3252_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Container image formats under the hood ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Container image formats under the hood
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46076a325f0de3f745254638b8b0f0de343685b34e7ca6ec5cd0b6b7930eb7fa`, `468327b5cd7ce539db695bd0ef05dae8a4ff77b02870a8e823ed74dedad4bd55`, `56def654ec22f857f480cdcc640c474e2f84d4be2e549a9d16eaba3f397596e9`, `8bf067b107a6f7444876e33c6ed85652355f679ac98ebab97ab3ebad63f0dff3`, `afa93a8ce255ca452ca8c88f4b5c821a466cf0a3e0148a31d0d97dfdb91d9aef`, `33a51d09088285451e7a7525d4bd64fc15563264afe5a91ef84a8b3042018899`, `171857c49d0f5e2ebf623e6cb36a8bcad585ed0c2aa99c87a055df034c1e5848`, `419640447d267f068d2f84a093cb13a56ce77e130877f5b8bdb4294f4a90a84f` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
