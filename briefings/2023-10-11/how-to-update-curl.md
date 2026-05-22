# [HIGH] How to update cURL

**Source:** Snyk
**Published:** 2023-10-11
**Article:** https://snyk.io/blog/how-to-update-curl/

## Threat Profile

Snyk Blog In this article
Written by Micah Silverman 
Brian Clark 
Eric Smalling 
October 11, 2023
0 mins read On October 3, 2023, the curl team preannounced a pending fix for a high-severity vulnerability, which impacts both libcurl and curl . 
Snyk products help you identify and fix vulnerable packages and containers, but this vulnerability impacts curl , a command-line tool that many developers use on a daily basis. It's also distributed with many operating systems, so we thought it would be …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — How to update cURL

`UC_1337_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — How to update cURL ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("curl.exe") OR Processes.process_path="*C:\Users\bc*" OR Processes.process_path="*\Users\bc*" OR Processes.process_path="*\Windows\System32\curl.exe*" OR Processes.process_path="*C:\ProgramData\chocolatey\bin*" OR Processes.process_path="*\ProgramData\chocolatey\bin\curl.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\bc*" OR Filesystem.file_path="*\Users\bc*" OR Filesystem.file_path="*\Windows\System32\curl.exe*" OR Filesystem.file_path="*C:\ProgramData\chocolatey\bin*" OR Filesystem.file_path="*\ProgramData\chocolatey\bin\curl.exe*" OR Filesystem.file_path="*/opt/homebrew*" OR Filesystem.file_path="*/opt/homebrew/opt/curl/bin*" OR Filesystem.file_path="*/home/ubuntu/bin/curl*" OR Filesystem.file_name IN ("curl.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — How to update cURL
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("curl.exe") or FolderPath has_any ("C:\Users\bc", "\Users\bc", "\Windows\System32\curl.exe", "C:\ProgramData\chocolatey\bin", "\ProgramData\chocolatey\bin\curl.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\bc", "\Users\bc", "\Windows\System32\curl.exe", "C:\ProgramData\chocolatey\bin", "\ProgramData\chocolatey\bin\curl.exe", "/opt/homebrew", "/opt/homebrew/opt/curl/bin", "/home/ubuntu/bin/curl") or FileName in~ ("curl.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
