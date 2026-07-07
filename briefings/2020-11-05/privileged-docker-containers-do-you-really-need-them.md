# [MED] Privileged Docker containers—do you really need them?

**Source:** Snyk
**Published:** 2020-11-05
**Article:** https://snyk.io/blog/privileged-docker-containers/

## Threat Profile

Snyk Blog In this article
Written by Matt Jarvis 
November 5, 2020
0 mins read This week, I dropped down a rabbit hole when doing some testing with Podman around why running a certain container in a rootless configuration required the --privileged flag. Quite rightly, my colleague Eric Smalling asked why it should require the flag.
Ultimately --privileged is shorthand for granting All The Things, and whilst you may think this doesn’t matter that much when running rootless, it does somewhat break…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Privileged Docker containers—do you really need them?

`UC_3237_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Privileged Docker containers—do you really need them? ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/containers/registries.conf*" OR Filesystem.file_path="*/etc/docker/registry/config.yml*" OR Filesystem.file_path="*/etc/selinux*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Privileged Docker containers—do you really need them?
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/containers/registries.conf", "/etc/docker/registry/config.yml", "/etc/selinux"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
