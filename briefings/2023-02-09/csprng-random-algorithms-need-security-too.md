# [MED] CSPRNG: Random algorithms need security too!

**Source:** Snyk
**Published:** 2023-02-09
**Article:** https://snyk.io/blog/csprng-random-algorithms-need-security-too/

## Threat Profile

Snyk Blog In this article
Written by Michael Biocchi 
February 9, 2023
0 mins read If I throw a coin high up in the air, I know the outcome — it will either be heads or tails. However, I can’t predict which it will be. I will certainly be able to guess with a 50% chance, but I can’t be 100% certain. If I were to roll a die, my certainty becomes less (1 in 6). However, I still know what the output could be.
Computers are great at many things, especially predictability. They are deterministic and …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — CSPRNG: Random algorithms need security too!

`UC_1862_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — CSPRNG: Random algorithms need security too! ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/random*" OR Filesystem.file_path="*/dev/urandom*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — CSPRNG: Random algorithms need security too!
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/random", "/dev/urandom"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
