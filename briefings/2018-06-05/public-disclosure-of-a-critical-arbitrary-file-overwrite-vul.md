# [LOW] Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip

**Source:** Snyk
**Published:** 2018-06-05
**Article:** https://snyk.io/blog/zip-slip-vulnerability/

## Threat Profile

Snyk Blog Written by Danny Grander 
June 5, 2018
0 mins read The Snyk Security team is today announcing the public disclosure of a critical arbitrary file overwrite vulnerability called Zip Slip. It is a widespread vulnerability which typically results in remote command execution. The vulnerability affects thousands of projects, including ones from HP, Amazon, Apache, Pivotal and many others. It has been found in multiple ecosystems, including JavaScript, Ruby, .NET and Go, but is especially pre…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1574** — Hijack Execution Flow
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Zip Slip: archive-handler process writes shell script / web shell outside extraction dir

`UC_3612_0` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action=created) AND (Filesystem.process_name IN ("java.exe","javaw.exe","jar.exe","7z.exe","7za.exe","tar.exe","unzip.exe","WinRAR.exe","Rar.exe","UnRAR.exe","cpio.exe")) AND (Filesystem.file_name="*.sh" OR Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.jspx" OR Filesystem.file_name="*.war" OR Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.bat") by Filesystem.dest Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","jar.exe","7z.exe","7za.exe","7zG.exe","tar.exe","unzip.exe","WinRAR.exe","Rar.exe","UnRAR.exe","cpio.exe")
| where FileName endswith ".sh" or FileName endswith ".jsp" or FileName endswith ".jspx" or FileName endswith ".war" or FileName endswith ".aspx" or FileName endswith ".bat" or FileName endswith ".bash" or FileName endswith ".py"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### Zip Slip RCE: archive-extraction process spawns command interpreter

`UC_3612_1` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","javaw.exe","jar.exe","7z.exe","7za.exe","tar.exe","unzip.exe","WinRAR.exe","Rar.exe","UnRAR.exe","cpio.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wscript.exe","cscript.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","jar.exe","7z.exe","7za.exe","tar.exe","unzip.exe","WinRAR.exe","Rar.exe","UnRAR.exe","cpio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wscript.exe","cscript.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **LOW** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
