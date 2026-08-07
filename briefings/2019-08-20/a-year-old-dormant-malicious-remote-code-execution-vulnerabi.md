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
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Webmin password_change.cgi unauthenticated command injection exploit attempt (CVE-2019-15107)

`UC_3505_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method=POST AND Web.url="*password_change.cgi*" by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| search NOT http_user_agent IN ("*Nessus*","*Qualys*","*nuclei*","*zgrab*","*masscan*")
| sort - lastTime
```

### Webmin RCE: miniserv/password_change.cgi spawning reverse shell (CVE-2019-15107)

`UC_3505_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*password_change.cgi*" OR Processes.parent_process_name="miniserv.pl" OR Processes.parent_process_name="perl") AND Processes.process_name IN ("sh","bash","dash","perl","python","python3","nc","ncat","netcat") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| where match(process, "(?i)(IO::Socket|Socket|fsockopen|/dev/tcp|sh -i|bash -i|perl -e|/bin/sh)")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has "password_change.cgi" or InitiatingProcessFileName =~ "miniserv.pl" or InitiatingProcessParentFileName =~ "miniserv.pl"
| where FileName in~ ("sh","bash","dash","perl","python","python3","nc","ncat","netcat")
| where ProcessCommandLine has_any ("IO::Socket","Socket","fsockopen","/dev/tcp","sh -i","bash -i","perl -e")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| sort by Timestamp desc
```

### Article-specific behavioural hunt — A year-old dormant malicious remote code execution vulnerability discovered in W

`UC_3505_0` · phase: **install** · confidence: **High**

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

Severity classified as **HIGH** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
