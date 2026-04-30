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
- **T1134.001** — Token Impersonation/Theft
- **T1068** — Exploitation for Privilege Escalation
- **T1134.002** — Create Process with Token
- **T1059.003** — Windows Command Shell
- **T1559** — Inter-Process Communication
- **T1574** — Hijack Execution Flow

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PhantomRPC coercion: gpupdate.exe /force spawned by service-account process (IIS/SQL/etc.)

`UC_74_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name=gpupdate.exe Processes.process="*/force*" (Processes.parent_process_name IN (w3wp.exe,sqlservr.exe,httpd.exe,nginx.exe,tomcat*.exe,javaw.exe,java.exe,php-cgi.exe,node.exe,inetinfo.exe) OR Processes.parent_process_name=svchost.exe) by Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_name Processes.user | `drop_dm_object_name(Processes)` | where match(user,"(?i)NETWORK SERVICE|LOCAL SERVICE|IUSR|IIS APPPOOL")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where FileName =~ "gpupdate.exe" and ProcessCommandLine has "/force"
| where InitiatingProcessAccountName in~ ("network service","local service") 
   or InitiatingProcessFileName in~ ("w3wp.exe","sqlservr.exe","httpd.exe","nginx.exe","php-cgi.exe","node.exe","inetinfo.exe","tomcat9.exe","javaw.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName, ProcessIntegrityLevel
| sort by Timestamp desc
```

### [LLM] PhantomRPC token theft: SYSTEM-integrity shell spawned by Network/Local Service parent shortly after gpupdate

`UC_74_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN (cmd.exe,powershell.exe,pwsh.exe,conhost.exe) Processes.parent_process_name IN (w3wp.exe,sqlservr.exe,httpd.exe,nginx.exe,php-cgi.exe,node.exe,inetinfo.exe,svchost.exe,tomcat9.exe,javaw.exe) Processes.user IN ("NT AUTHORITY\\SYSTEM","SYSTEM") by Processes.dest Processes.parent_process_name Processes.parent_process_id Processes.process_name Processes.process Processes.user Processes.parent_process_path | `drop_dm_object_name(Processes)` | join type=inner dest parent_process_id [| tstats `summariesonly` values(Processes.user) as parent_user from datamodel=Endpoint.Processes where Processes.process_name IN (w3wp.exe,sqlservr.exe,httpd.exe,nginx.exe,php-cgi.exe,node.exe,inetinfo.exe,svchost.exe,tomcat9.exe,javaw.exe) by Processes.dest Processes.process_id as parent_process_id | `drop_dm_object_name(Processes)` | where match(parent_user,"(?i)NETWORK SERVICE|LOCAL SERVICE")]
```

**Defender KQL:**
```kql
let parents = DeviceProcessEvents
| where InitiatingProcessAccountName in~ ("network service","local service")
| where FileName in~ ("w3wp.exe","sqlservr.exe","httpd.exe","nginx.exe","php-cgi.exe","node.exe","inetinfo.exe","tomcat9.exe","javaw.exe","svchost.exe")
| project ParentTime=Timestamp, DeviceId, ParentPid=ProcessId, ParentName=FileName, ParentAccount=AccountName, ParentInitAccount=InitiatingProcessAccountName;
DeviceProcessEvents
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| where AccountName =~ "system" or ProcessIntegrityLevel =~ "System"
| join kind=inner parents on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.ParentPid
| where Timestamp between (ParentTime .. (ParentTime + 5m))
| project Timestamp, DeviceName, ParentName, ParentInitAccount, FileName, ProcessCommandLine, AccountName, ProcessIntegrityLevel, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### [LLM] PhantomRPC hunt: rogue process binding TermSrvApi RPC interface (UUID bde95fdf-eee0-45de-9e12-e5a61cd0d4fe)

`UC_74_4` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=etw_rpc (InterfaceUuid="bde95fdf-eee0-45de-9e12-e5a61cd0d4fe" OR Endpoint="TermSrvApi" OR Endpoint="ncalrpc:[TermSrvApi]") EventName IN ("RpcServerRegisterIf*","RpcServerUseProtseqEp*","AlpcCreatePort") | stats min(_time) as firstTime max(_time) as lastTime values(ProcessName) as ProcessName values(ProcessId) as ProcessId values(UserName) as UserName by host InterfaceUuid Endpoint | where NOT (match(ProcessName,"(?i)svchost\\.exe$") AND match(UserName,"(?i)NETWORK SERVICE"))
```

**Defender KQL:**
```kql
// Requires ETW-RPC forwarded into a custom table; example assumes 'RpcEvents_CL'
RpcEvents_CL
| where InterfaceUuid_s =~ "bde95fdf-eee0-45de-9e12-e5a61cd0d4fe" or Endpoint_s has "TermSrvApi"
| where EventName_s in~ ("RpcServerRegisterIf","RpcServerRegisterIf2","RpcServerRegisterIf3","RpcServerUseProtseqEp","AlpcCreatePort")
| where not(ProcessName_s has "svchost.exe" and InitiatingAccountName_s has "network service")
| project TimeGenerated, DeviceName_s, ProcessName_s, ProcessId_d, InitiatingAccountName_s, InterfaceUuid_s, Endpoint_s
| sort by TimeGenerated desc
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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — PhantomRPC: A new privilege escalation technique in Windows RPC

`UC_74_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
