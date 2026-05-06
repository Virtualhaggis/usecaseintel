# [CRIT] PhantomRPC: A new privilege escalation technique in Windows RPC

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
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
- **T1068** — Exploitation for Privilege Escalation
- **T1484.001** — Domain or Tenant Policy Modification: Group Policy Modification
- **T1134.002** — Access Token Manipulation: Create Process with Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PhantomRPC coercion: Network Service / Local Service context spawning gpupdate.exe /force or ipconfig

`UC_106_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_id) as process_id values(Processes.parent_process_name) as parent_process_name values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name="gpupdate.exe" AND Processes.process="*/force*") OR Processes.process_name="ipconfig.exe" (Processes.parent_user_id IN ("S-1-5-19","S-1-5-20") OR Processes.parent_user IN ("NT AUTHORITY\\NETWORK SERVICE","NT AUTHORITY\\LOCAL SERVICE") OR Processes.parent_process_name IN ("w3wp.exe","svchost.exe")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.parent_user | `drop_dm_object_name(Processes)` | where parent_user IN ("NT AUTHORITY\\NETWORK SERVICE","NT AUTHORITY\\LOCAL SERVICE") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "gpupdate.exe" and ProcessCommandLine has "/force")
   or FileName =~ "ipconfig.exe"
// Initiating process is running as Network Service or Local Service — the SeImpersonatePrivilege-holding accounts targeted by PhantomRPC
| where InitiatingProcessAccountName in~ ("network service", "local service", "iusr")
   or InitiatingProcessAccountSid in ("S-1-5-19", "S-1-5-20")
// Exclude legitimate SYSTEM-driven gpupdate (scheduled task)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, AccountSid,
          FileName, ProcessCommandLine,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentAccount = InitiatingProcessAccountName,
          ParentSid = InitiatingProcessAccountSid,
          ParentFolderPath = InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] PhantomRPC post-impersonation pivot: SYSTEM child process spawned by Network Service / Local Service parent

`UC_106_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_id) as process_id values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.user IN ("NT AUTHORITY\\SYSTEM","SYSTEM") Processes.parent_user IN ("NT AUTHORITY\\NETWORK SERVICE","NT AUTHORITY\\LOCAL SERVICE") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","net.exe","net1.exe","reg.exe","sc.exe","taskkill.exe","whoami.exe") by Processes.dest Processes.user Processes.parent_user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
// Child runs as SYSTEM
| where AccountSid == "S-1-5-18" or AccountName =~ "system"
// Parent was running as Network Service or Local Service — the privilege boundary that PhantomRPC crosses
| where InitiatingProcessAccountSid in ("S-1-5-19", "S-1-5-20")
   or InitiatingProcessAccountName in~ ("network service", "local service")
// Focus on hands-on-keyboard / discovery-flavoured children typical of post-LPE confirmation
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe",
                       "regsvr32.exe", "net.exe", "net1.exe", "reg.exe",
                       "sc.exe", "taskkill.exe", "whoami.exe", "wmic.exe",
                       "mshta.exe", "bitsadmin.exe", "certutil.exe")
// Filter expected svchost-hosted SYSTEM behaviour (legitimate service spawns SYSTEM child via service start, not as a Network/Local Service parent)
| where InitiatingProcessFileName !in~ ("services.exe", "wininit.exe", "smss.exe", "csrss.exe")
| project Timestamp, DeviceName, ChildAccount = AccountName, ChildSid = AccountSid,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentAccount = InitiatingProcessAccountName,
          ParentSid = InitiatingProcessAccountSid,
          ParentIntegrity = InitiatingProcessIntegrityLevel,
          ChildIntegrity = ProcessIntegrityLevel,
          ChildElevation = ProcessTokenElevation
| order by Timestamp desc
```

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
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — PhantomRPC: A new privilege escalation technique in Windows RPC

`UC_106_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
