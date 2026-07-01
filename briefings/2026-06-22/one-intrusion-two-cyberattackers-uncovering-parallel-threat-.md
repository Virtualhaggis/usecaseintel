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
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1136.001** — Create Account: Local Account
- **T1136.002** — Create Account: Domain Account
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1068** — Exploitation for Privilege Escalation
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Storm-2603 SharePoint ToolShell exploitation: ToolPane.aspx/spinstall0.aspx + win.ini/web.config LFI probing

`UC_112_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url IN ("*/_layouts/15/ToolPane.aspx*","*spinstall0.aspx*","*win.ini*","*web.config*") OR Web.src IN ("38.54.16.179","91.236.230.76","65.38.121.226")) by Web.src, Web.dest, Web.http_method, Web.http_user_agent, Web.url, Web.status
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("38.54.16.179","91.236.230.76","65.38.121.226")
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SharePoint IIS worker (w3wp.exe) spawning command shell — ToolShell web-shell execution

`UC_112_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","msiexec.exe","cscript.exe","wscript.exe","net.exe","net1.exe","whoami.exe") by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","msiexec.exe","cscript.exe","wscript.exe","net.exe","net1.exe","whoami.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Velociraptor deployed via msiexec from workers.dev (Storm-2603 SecurityCheck.msi / CVE-2025-6264)

`UC_112_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="msiexec.exe" AND (Processes.process="*workers.dev*" OR Processes.process="*v3.msi*" OR Processes.process="*ssh.msi*" OR Processes.process="*SecurityCheck.msi*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("workers.dev","v3.msi","ssh.msi","SecurityCheck.msi"))
    or SHA256 in ("c70fafe5f9a3e5a9ee7de584dd024cb552443659f06348398d3873aa88fd6682","040d7ee5b7bb0b978220be326804fa827f6284c8478a27af88c616fcacfeb423")
    or InitiatingProcessSHA256 in ("c70fafe5f9a3e5a9ee7de584dd024cb552443659f06348398d3873aa88fd6682","040d7ee5b7bb0b978220be326804fa827f6284c8478a27af88c616fcacfeb423")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Multiple parallel remote-access/tunnel tools on one host (Cloudflare tunnel + VS Code tunnel + TightVNC + Zoho + OpenSSH)

`UC_112_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name="code.exe" AND Processes.process="*tunnel*") OR Processes.process_name="cloudflared.exe" OR Processes.process_name="tvnserver.exe" OR Processes.process="*--accept-server-license-terms*" OR Processes.process="*ssh.msi*" OR Processes.process="*ZohoAssist*" OR Processes.process="*ZA_Connect*" by Processes.dest, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| eval Tool=case(process_name="code.exe","VSCodeTunnel",process_name="cloudflared.exe","CloudflareTunnel",process_name="tvnserver.exe","TightVNC",like(process,"%ZohoAssist%") OR like(process,"%ZA_Connect%"),"ZohoAssist",like(process,"%ssh.msi%"),"OpenSSH",1==1,"Tunnel")
| stats dc(Tool) as ToolCount values(Tool) as Tools values(process) as Cmds by dest
| where ToolCount>=2
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| extend Tool = case(
    FileName =~ "code.exe" and ProcessCommandLine has "tunnel", "VSCodeTunnel",
    FileName =~ "cloudflared.exe" or ProcessCommandLine has "cloudflared", "CloudflareTunnel",
    FileName =~ "tvnserver.exe", "TightVNC",
    ProcessCommandLine has_any ("ZohoAssist","ZA_Connect") or FileName startswith "ZA_", "ZohoAssist",
    FileName =~ "sshd.exe" or ProcessCommandLine has "ssh.msi", "OpenSSH",
    "")
| where isnotempty(Tool)
| summarize Tools=make_set(Tool), ToolCount=dcount(Tool), Cmds=make_set(ProcessCommandLine, 8), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName
| where ToolCount >= 2   // 2+ distinct remote-access/tunnel families on one host = Storm-2603 multi-channel pattern
| order by LastSeen desc
```

### Storm-2603 rogue admin account creation (adminbak/adminbak2) and Domain Admins enumeration

`UC_112_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("net.exe","net1.exe") AND (Processes.process="*adminbak*" OR Processes.process="*localgroup administrators*" OR Processes.process="*domain admins*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "adminbak"
    or ProcessCommandLine contains "domain admins"
    or ProcessCommandLine contains "localgroup administrators"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Windows Defender disablement prior to tunnel install (Storm-2603 defense evasion)

`UC_112_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Set-MpPreference*" OR Processes.process="*DisableRealtimeMonitoring*" OR Processes.process="*DisableBehaviorMonitoring*")) OR (Processes.process_name IN ("sc.exe","net.exe") AND (Processes.process="*stop WinDefend*" OR Processes.process="*stop Sense*")) OR (Processes.process_name="reg.exe" AND Processes.process="*DisableAntiSpyware*")) by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Set-MpPreference","DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection"))
    or (FileName in~ ("sc.exe","net.exe") and ProcessCommandLine has_any ("stop WinDefend","stop Sense","config WinDefend"))
    or (FileName =~ "reg.exe" and ProcessCommandLine has "DisableAntiSpyware")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Storm-2603 concurrent C2 egress to workers.dev tunnels and attacker IPs

`UC_112_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("velo.qaubctgg.workers.dev","royal-boat-bf05.qgtxtebl.workers.dev","update.githubtestbak.workers.dev","chat.hcqhajfv.workers.dev") by DNS.src, DNS.query, DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("velo.qaubctgg.workers.dev","royal-boat-bf05.qgtxtebl.workers.dev","update.githubtestbak.workers.dev","chat.hcqhajfv.workers.dev")
    or RemoteIP in ("38.54.16.179","91.236.230.76","65.38.121.226")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
