# [CRIT] Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-06-09
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-for-june-2026-snort-rules-and-prominent-vulnerabilities/

## Threat Profile

Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities 
By 
Chetan Raghuprasad 
Tuesday, June 9, 2026 17:21
Patch Tuesday
Microsoft has released its monthly security update for June 2026, which includes 206 vulnerabilities affecting a range of products, including 32 that Microsoft marked as “critical”. 
Out of 32 "critical" entries, 28 are remote code execution (RCE) vulnerabilities in Microsoft Windows services and applications including Windows Active Directory, Wind…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42985`
- **CVE:** `CVE-2026-47291`
- **CVE:** `CVE-2026-44803`
- **CVE:** `CVE-2026-44812`
- **CVE:** `CVE-2026-42992`
- **CVE:** `CVE-2026-44799`
- **CVE:** `CVE-2026-44801`
- **CVE:** `CVE-2026-47289`
- **CVE:** `CVE-2026-48563`
- **CVE:** `CVE-2026-45607`
- **CVE:** `CVE-2026-45641`
- **CVE:** `CVE-2026-47652`
- **CVE:** `CVE-2026-45657`
- **CVE:** `CVE-2026-48574`
- **CVE:** `CVE-2026-42987`
- **CVE:** `CVE-2026-44815`
- **CVE:** `CVE-2026-45456`
- **CVE:** `CVE-2026-45458`
- **CVE:** `CVE-2026-47635`
- **CVE:** `CVE-2026-45461`
- **CVE:** `CVE-2026-45463`
- **CVE:** `CVE-2026-45472`
- **CVE:** `CVE-2026-45474`
- **CVE:** `CVE-2026-45476`
- **CVE:** `CVE-2026-44810`
- **CVE:** `CVE-2026-47644`
- **CVE:** `CVE-2026-26142`
- **CVE:** `CVE-2026-32193`
- **CVE:** `CVE-2026-45648`
- **CVE:** `CVE-2026-47288`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1543.003** — Persistence (article-specific)
- **T1505.003** — Server Software Component: Web Shell
- **T1203** — Exploitation for Client Execution
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1068** — Exploitation for Privilege Escalation
- **T1611** — Escape to Host
- **T1566.001** — Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### HTTP.sys CVE-2026-47291 post-exploit — w3wp.exe spawning script/LOLBin child after IIS crash

`UC_115_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","whoami.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where user="NT AUTHORITY\\SYSTEM" OR user="IIS APPPOOL*" | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-47291 http.sys integer-overflow post-exploit: w3wp.exe spawning shell/LOLBin children
let Lookback = 7d;
let SuspiciousChildren = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","nltest.exe"]);
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (SuspiciousChildren)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### RDC Client CVE-2026-42985 — mstsc.exe spawns child or connects to non-corporate RDP server

`UC_115_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.parent_process_name="mstsc.exe" Processes.process_name!="mstsc.exe" Processes.process_name!="conhost.exe" Processes.process_name!="WerFault.exe" by Processes.dest Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-42985 RDC client heap overflow — mstsc.exe spawning unexpected children OR connecting to non-corporate RDP server
let Lookback = 7d;
let CorpRdpRanges = dynamic(["10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","192.168."]);
let KnownChildren = dynamic(["conhost.exe","mstsc.exe","werfault.exe","rdpinit.exe","rdpclip.exe","tabtip.exe","splwow64.exe"]);
let ChildSpawn = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where FileName !in~ (KnownChildren)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256;
let ExternalRdp = DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where RemotePort == 3389 and ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | where not(RemoteIP startswith_cs CorpRdpRanges[0] or RemoteIP startswith_cs "192.168.")
    | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName;
union ChildSpawn, ExternalRdp
| order by Timestamp desc
```

### Win32K GRFX CVE-2026-44803/44812 — dwm.exe or csrss.exe spawning anomalous child or crashing

`UC_115_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("dwm.exe","csrss.exe") Processes.process_name!="conhost.exe" Processes.process_name!="WerFault.exe" Processes.process_name!="WerFaultSecure.exe" Processes.process_name!="fontdrvhost.exe" by Processes.dest Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | where user="NT AUTHORITY\\SYSTEM" OR user="NT AUTHORITY\\LOCAL SERVICE" | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-44803 / CVE-2026-44812 Win32K GRFX integer overflow — dwm.exe / csrss.exe anomalous child spawn
let Lookback = 7d;
let KnownChildren = dynamic(["conhost.exe","WerFault.exe","WerFaultSecure.exe","fontdrvhost.exe","winlogon.exe","smss.exe","csrss.exe"]);
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName in~ ("dwm.exe", "csrss.exe")
| where FileName !in~ (KnownChildren)
| where AccountName !endswith "$" or AccountName =~ "system"
| project Timestamp, DeviceName, AccountName, AccountSid,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### Hyper-V CVE-2026-45607/45641/47652 — vmwp.exe spawning anomalous child or crashing on host

`UC_115_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("vmwp.exe","vmms.exe","vmcompute.exe") Processes.process_name!="conhost.exe" Processes.process_name!="WerFault.exe" Processes.process_name!="vmwp.exe" by Processes.dest Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-45607 / 45641 / 47652 Hyper-V guest-to-host escape — vmwp.exe / vmms.exe anomalous child on host
let Lookback = 7d;
let KnownChildren = dynamic(["conhost.exe","WerFault.exe","WerFaultSecure.exe","vmwp.exe","vmcompute.exe","vmconnect.exe","vmms.exe"]);
let SuspiciousAnything = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName in~ ("vmwp.exe","vmms.exe","vmcompute.exe")
    | where FileName !in~ (KnownChildren)
    | project Timestamp, DeviceName, AccountName,
              ParentProcess = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              ChildImage = FolderPath,
              ChildCmd = ProcessCommandLine,
              ChildIntegrity = ProcessIntegrityLevel,
              SHA256;
let WorkerCrashes = DeviceEvents
    | where Timestamp > ago(Lookback)
    | where ActionType in ("ProcessCrash","WerFault")
    | where InitiatingProcessFileName in~ ("vmwp.exe","vmms.exe","vmcompute.exe")
            or FileName in~ ("vmwp.exe","vmms.exe","vmcompute.exe")
    | project Timestamp, DeviceName, ActionType, FileName, AdditionalFields;
union SuspiciousAnything, WorkerCrashes
| order by Timestamp desc
```

### Outlook Preview Pane CVE-2026-45456/45458/47635 — OUTLOOK.EXE → WINWORD.EXE → script/LOLBin chain

`UC_115_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.parent_process_name="winword.exe" (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wmic.exe","hh.exe","msiexec.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | join type=inner dest parent_process_name [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name="outlook.exe" Processes.process_name="winword.exe" by Processes.dest Processes.parent_process_name | `drop_dm_object_name(Processes)`] | sort - lastTime
```

**Defender KQL:**
```kql
// CVE-2026-45456 / 45458 / 47635 Office type-confusion via Outlook (classic) preview pane → Word rendering → exploit child
let Lookback = 7d;
let ScriptyChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wmic.exe","hh.exe","msiexec.exe","msbuild.exe"]);
let WordSpawnedByOutlook = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName =~ "OUTLOOK.EXE"
    | where FileName =~ "WINWORD.EXE"
    | project ParentSpawnTs = Timestamp, DeviceName, WordPid = ProcessId,
              OutlookCmd = InitiatingProcessCommandLine, WordCmd = ProcessCommandLine,
              AccountName;
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName =~ "WINWORD.EXE"
| where FileName in~ (ScriptyChildren)
| where AccountName !endswith "$"
| project ChildTs = Timestamp, DeviceName, AccountName, WordPid = InitiatingProcessId,
          WordCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| join kind=inner WordSpawnedByOutlook on DeviceName, WordPid
| where ChildTs between (ParentSpawnTs .. ParentSpawnTs + 5m)
| project ChildTs, DeviceName, AccountName, OutlookCmd, WordCmd, ChildImage, ChildCmd, SHA256
| order by ChildTs desc
```

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_115_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42985`, `CVE-2026-47291`, `CVE-2026-44803`, `CVE-2026-44812`, `CVE-2026-42992`, `CVE-2026-44799`, `CVE-2026-44801`, `CVE-2026-47289` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
