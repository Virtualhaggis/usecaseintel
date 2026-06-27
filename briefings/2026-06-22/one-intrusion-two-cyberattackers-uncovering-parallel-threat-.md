# [CRIT] One intrusion, two cyberattackers: Uncovering parallel threat activity

**Source:** Microsoft Security Blog
**Published:** 2026-06-22
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/22/one-intrusion-two-cyberattackers-uncovering-parallel-threat-activity/

## Threat Profile

Content types News 
Products and services Microsoft Incident Response 
Microsoft Security Experts 
Topics Incident response 
Security management 
Security operations 
Threat trends 
What began as a routine ransomware investigation quickly revealed something far more complex. In this ninth cyberattack series report, DART details how a single intrusion uncovered parallel activity from two unrelated threat actors operating simultaneously—blending tactics, obscuring signals, and challenging traditio…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-49704`
- **CVE:** `CVE-2025-49706`
- **CVE:** `CVE-2025-53770`
- **CVE:** `CVE-2025-53771`
- **CVE:** `CVE-2025-6264`
- **IPv4 (defanged):** `65.38.121.226`
- **IPv4 (defanged):** `38.54.16.179`
- **IPv4 (defanged):** `91.236.230.76`
- **Domain (defanged):** `velo.qaubctgg.workers.dev`
- **Domain (defanged):** `royal-boat-bf05.qgtxtebl.workers.dev`
- **Domain (defanged):** `update.githubtestbak.workers.dev`
- **Domain (defanged):** `chat.hcqhajfv.workers.dev`
- **SHA256:** `649bdaa38e60ede6d140bd54ca5412f1091186a803d3905465219053393f6421`
- **SHA256:** `12f177290a299bae8a363f47775fb99f305bbdd56bbdfddb39595b43112f9fb7`
- **SHA256:** `a29125333ad72138d299cc9ef09718ddb417c3485f6b8fe05ba88a08bb0e5023`
- **SHA256:** `c74897b1e986e2876873abb3b5069bf1b103667f7f0e6b4581fbda3fd647a74a`
- **SHA256:** `c70fafe5f9a3e5a9ee7de584dd024cb552443659f06348398d3873aa88fd6682`
- **SHA256:** `040d7ee5b7bb0b978220be326804fa827f6284c8478a27af88c616fcacfeb423`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1083** — File and Directory Discovery
- **T1588.002** — Obtain Capabilities: Tool
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SharePoint LFI recon via win.ini / web.config requests (Storm-2603 ToolShell precursor)

`UC_79_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*win.ini*" OR Web.url="*web.config*") by Web.src, Web.dest, Web.http_method, Web.url, Web.http_user_agent, Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Velociraptor deployed with SYSTEM privileges (Storm-2603 LOTL tooling)

`UC_79_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=velociraptor.exe OR Processes.process="*velociraptor*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.process_integrity_level
| `drop_dm_object_name(Processes)`
| where process_integrity_level IN ("system","high") OR like(process,"%--config%") OR like(process,"%artifacts%")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "velociraptor.exe" or ProcessVersionInfoProductName has "Velociraptor" or ProcessVersionInfoFileDescription has "Velociraptor"
| where ProcessIntegrityLevel in ("System","High") or ProcessCommandLine has_any ("--config","artifacts collect","gui","frontend","client")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, ProcessIntegrityLevel, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Cloudflared tunnel established for covert C2 (Storm-2603)

`UC_79_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=cloudflared.exe OR Processes.process="*trycloudflare*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where like(process,"%tunnel%") OR like(process,"%--url%") OR like(process,"%--token%") OR like(process,"%trycloudflare%")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "cloudflared.exe" or ProcessVersionInfoProductName has "cloudflared" or ProcessCommandLine has "trycloudflare"
| where ProcessCommandLine has_any ("tunnel","--url","--token","run","trycloudflare")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Visual Studio Code remote tunnel abused as SSH/C2 channel (Storm-2603)

`UC_79_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=code.exe OR Processes.process_name=code-tunnel.exe OR Processes.process_name=code.cmd) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where like(process,"%tunnel%")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "code.exe" or FileName =~ "code-tunnel.exe" or ProcessVersionInfoProductName has "Visual Studio Code")
| where ProcessCommandLine has "tunnel"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### BYOVD vulnerable-driver load to disable endpoint protection (Storm-2603 NSecKrnl/ServiceMouse)

`UC_79_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=NSecKrnl.sys OR Filesystem.file_name=AToolsKrnl64.sys) by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("NSecKrnl.sys","AToolsKrnl64.sys")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Zoho Assist unsanctioned remote-support agent on server (Storm-2603)

`UC_79_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=ZohoURSService.exe OR Processes.process_name=ZA_Connect.exe OR Processes.process_name=ZA_Access.exe OR Processes.process_name=ZMAgent.exe OR Processes.process="*Zoho Assist*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessVersionInfoCompanyName has "Zoho" or FileName has_any ("ZohoURS","ZA_Connect","ZA_Access","ZMAgent") or ProcessCommandLine has "Zoho Assist"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoCompanyName, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-49704`, `CVE-2025-49706`, `CVE-2025-53770`, `CVE-2025-53771`, `CVE-2025-6264`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `65.38.121.226`, `38.54.16.179`, `91.236.230.76`, `velo.qaubctgg.workers.dev`, `royal-boat-bf05.qgtxtebl.workers.dev`, `update.githubtestbak.workers.dev`, `chat.hcqhajfv.workers.dev`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `649bdaa38e60ede6d140bd54ca5412f1091186a803d3905465219053393f6421`, `12f177290a299bae8a363f47775fb99f305bbdd56bbdfddb39595b43112f9fb7`, `a29125333ad72138d299cc9ef09718ddb417c3485f6b8fe05ba88a08bb0e5023`, `c74897b1e986e2876873abb3b5069bf1b103667f7f0e6b4581fbda3fd647a74a`, `c70fafe5f9a3e5a9ee7de584dd024cb552443659f06348398d3873aa88fd6682`, `040d7ee5b7bb0b978220be326804fa827f6284c8478a27af88c616fcacfeb423`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
