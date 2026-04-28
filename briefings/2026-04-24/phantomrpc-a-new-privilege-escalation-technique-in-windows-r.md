# [HIGH] PhantomRPC: A new privilege escalation technique in Windows RPC

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-24
**Article:** https://securelist.com/phantomrpc-rpc-vulnerability/119428/

## Threat Profile

Table of Contents
Intro 
MSRPC 
Impersonation in Windows 
Interaction between Group Policy service and TermService 
Coercing the Group Policy service 
RPC architecture flow 
Identifying RPC calls to unavailable servers 
Additional privilege escalation paths 
User interaction: From Edge to RDP 
Background services: From WDI to RDP 
Abusing the Local Service account: From ipconfig to DHCP 
Abusing Time 
Vulnerability disclosure 
Detection and defense 
Conclusion 
Authors
Haidar Kabibo 
Intro 
Wind…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1543.003** — Persistence (article-specific)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — PhantomRPC: A new privilege escalation technique in Windows RPC

`UC_41_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — PhantomRPC: A new privilege escalation technique in Windows RPC ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("gpupdate.exe","rpcrt4.dll","winsta.dll","w32tm.exe") OR Processes.process_path="*C:\Windows\System32\w32tm.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\System32\w32tm.exe*" OR Filesystem.file_name IN ("gpupdate.exe","rpcrt4.dll","winsta.dll","w32tm.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — PhantomRPC: A new privilege escalation technique in Windows RPC
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("gpupdate.exe", "rpcrt4.dll", "winsta.dll", "w32tm.exe") or FolderPath has_any ("C:\Windows\System32\w32tm.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\System32\w32tm.exe") or FileName in~ ("gpupdate.exe", "rpcrt4.dll", "winsta.dll", "w32tm.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
