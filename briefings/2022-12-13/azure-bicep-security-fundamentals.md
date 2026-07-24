# [MED] Azure Bicep security fundamentals

**Source:** Snyk
**Published:** 2022-12-13
**Article:** https://snyk.io/blog/azure-bicep-security-fundamentals/

## Threat Profile

Snyk Blog In this article
Written by Mark Johnson 
December 13, 2022
0 mins read This post was written by Snyk Ambassador, Mark Johnson ( @tazmainiandevil ). Get inside access to Snyk by  signing up to become a Snyk Ambassador . 
Azure Bicep is getting more popular by the day and is rapidly becoming the replacement for Azure Resource Manager (ARM) templates. In this post, I am going to go over some security fundamentals when using Bicep. If you are not familiar with Bicep then I recommend taking…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Storage account key retrieval (listKeys) inside an ARM/Bicep deployment — secret-in-output leak vector

`UC_1880_1` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.command="Microsoft.Storage/storageAccounts/listKeys/action" All_Changes.status="Succeeded" by All_Changes.user All_Changes.src All_Changes.object All_Changes.result
| `drop_dm_object_name("All_Changes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

### Article-specific behavioural hunt — Azure Bicep security fundamentals

`UC_1880_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Azure Bicep security fundamentals ```
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
// Article-specific bespoke detection — Azure Bicep security fundamentals
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


## Why this matters

Severity classified as **MED** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
