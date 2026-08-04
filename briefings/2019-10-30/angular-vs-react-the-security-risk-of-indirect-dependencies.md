# [HIGH] Angular vs React: the security risk of indirect dependencies

**Source:** Snyk
**Published:** 2019-10-30
**Article:** https://snyk.io/blog/angular-vs-react-the-security-risk-of-indirect-dependencies/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
October 30, 2019
0 mins read Welcome to Snyk's State of JavaScript frameworks security report 2019.
In this section, we review the security risk of the indirect independencies for both Angular and React, and then we also review the direct dependencies, first for Angular and then for React.
Download the Report here !
The modules reviewed in this part do not represent a complete list of vulnerable React and Angular modules; some modules may have spec…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1567.002** — Exfiltration to Cloud Storage / Web Service
- **T1056.003** — Web Portal Capture
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Form-skimmer exfil to js-metrics.com (malicious angular-bmap / ng-ui-library npm versions)

`UC_3475_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*js-metrics.com*" OR Web.url="*/minjs.php?pl=*" OR Web.dest="js-metrics.com") by Web.src Web.dest Web.url Web.http_user_agent Web.app | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "js-metrics.com" or RemoteUrl has "/minjs.php"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Install of malicious npm package versions angular-bmap@0.0.9 / ng-ui-library@1.0.987

`UC_3475_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*angular-bmap@0.0.9*" OR Processes.process="*ng-ui-library@1.0.987*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("angular-bmap@0.0.9", "ng-ui-library@1.0.987")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — Angular vs React: the security risk of indirect dependencies

`UC_3475_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Angular vs React: the security risk of indirect dependencies ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Angular vs React: the security risk of indirect dependencies
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
