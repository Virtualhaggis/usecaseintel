# [HIGH] A year-old dormant malicious remote code execution vulnerability discovered in Webmin

**Source:** Snyk
**Published:** 2019-08-20
**Article:** https://snyk.io/blog/a-year-old-dormant-malicious-remote-code-execution-vulnerability-discovered-in-webmin/

## Threat Profile

Snyk Blog In this article
Written by Hayley Denbraver 
August 20, 2019
0 mins read On August 17, 2019, the Webmin team announced the release of Webmin 1.930 and Usermin 1.780. These releases address a newly discovered remote command execution vulnerability found in Webmin versions 1.890 through 1.920. This vulnerability has been present for more than a year and was introduced by a malicious third party .
Webmin is an interface for system administration for Unix. As the name suggests, it is web-b…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — A year-old dormant malicious remote code execution vulnerability discovered in W

`UC_3187_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A year-old dormant malicious remote code execution vulnerability discovered in W ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/webmin/miniserv.conf*" OR Filesystem.file_path="*/etc/webmin/restart*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A year-old dormant malicious remote code execution vulnerability discovered in W
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/webmin/miniserv.conf", "/etc/webmin/restart"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
