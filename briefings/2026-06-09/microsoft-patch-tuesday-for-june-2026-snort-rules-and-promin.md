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
- **T1203** — Exploitation for Client Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1566.002** — Phishing: Spearphishing Link
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1055** — Process Injection
- **T1505.003** — Server Software Component: Web Shell
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Hosts missing June 2026 Patch Tuesday critical RCE/EoP fixes

`UC_93_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812","CVE-2026-42992","CVE-2026-44799","CVE-2026-44801","CVE-2026-47289","CVE-2026-48563","CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-45657","CVE-2026-48574","CVE-2026-42987","CVE-2026-44815","CVE-2026-45456","CVE-2026-45458","CVE-2026-47635","CVE-2026-45461","CVE-2026-45463","CVE-2026-45472","CVE-2026-45474","CVE-2026-45476","CVE-2026-44810","CVE-2026-32193","CVE-2026-45648") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | eval HighPriority=if(cve IN ("CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812"),1,0) | stats values(cve) as MissingCVEs sum(HighPriority) as HighPriorityCount dc(cve) as TotalMissing by dest | sort - HighPriorityCount - TotalMissing
```

**Defender KQL:**
```kql
let HighPriority = dynamic(["CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812"]);
let AllCriticalCves = dynamic(["CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812","CVE-2026-42992","CVE-2026-44799","CVE-2026-44801","CVE-2026-47289","CVE-2026-48563","CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-45657","CVE-2026-48574","CVE-2026-42987","CVE-2026-44815","CVE-2026-45456","CVE-2026-45458","CVE-2026-47635","CVE-2026-45461","CVE-2026-45463","CVE-2026-45472","CVE-2026-45474","CVE-2026-45476","CVE-2026-44810","CVE-2026-32193","CVE-2026-45648"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (AllCriticalCves)
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSVersion) by DeviceId) on DeviceId
| summarize MissingCves = make_set(CveId),
            HighPriorityCount = countif(CveId in (HighPriority)),
            TotalMissing = dcount(CveId)
            by DeviceId, DeviceName, OSPlatform, OSVersion, IsInternetFacing
| order by IsInternetFacing desc, HighPriorityCount desc, TotalMissing desc
```

### Outlook preview-pane Type Confusion exploit chain (Outlook → Word → LOLBin)

`UC_93_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd values(Processes.parent_process) as wordCmd from datamodel=Endpoint.Processes where Processes.parent_process_name="winword.exe" AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","msbuild.exe","installutil.exe","curl.exe","wget.exe","msiexec.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name="outlook.exe" AND Processes.process_name="winword.exe" by Processes.dest | `drop_dm_object_name(Processes)` | fields dest]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "winword.exe"
| where InitiatingProcessParentFileName =~ "outlook.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","msbuild.exe","installutil.exe","curl.exe","wget.exe","msiexec.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          OutlookGrandparent = InitiatingProcessParentFileName,
          WordParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### mstsc.exe child process after outbound RDP to external server (RDC heap overflow)

`UC_93_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd values(Processes.process_path) as childPath from datamodel=Endpoint.Processes where Processes.parent_process_name="mstsc.exe" AND NOT Processes.process_name IN ("conhost.exe","WerFault.exe","WerFaultSecure.exe","rdpclip.exe","mstsc.exe","tabtip.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="mstsc.exe" AND All_Traffic.dest_port=3389 AND NOT (All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=172.16.0.0/12) by All_Traffic.src All_Traffic.dest_ip | rename All_Traffic.src as dest All_Traffic.dest_ip as RemoteIP | `drop_dm_object_name(All_Traffic)` | fields dest RemoteIP]
```

**Defender KQL:**
```kql
let RdpOutbound = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where RemotePort == 3389
    | where RemoteIPType == "Public"
    | project ConnTime = Timestamp, DeviceId, RemoteIP, RemoteUrl, ConnAccount = InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "mstsc.exe"
| where FileName !in~ ("conhost.exe","WerFault.exe","WerFaultSecure.exe","rdpclip.exe","tabtip.exe","mstsc.exe")
| join kind=inner RdpOutbound on DeviceId
| where Timestamp between (ConnTime .. ConnTime + 10m)
| extend DelaySec = datetime_diff('second', Timestamp, ConnTime)
| project ConnTime, ChildSpawnTime = Timestamp, DelaySec, DeviceName, AccountName,
          RemoteIP, RemoteUrl,
          ChildImage = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by ChildSpawnTime desc
```

### csrss.exe or dwm.exe spawning child process (Win32K-GRFX kernel exploit marker)

`UC_93_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="dwm.exe" OR Processes.parent_process_name="csrss.exe") AND NOT Processes.process_name IN ("conhost.exe","fontdrvhost.exe","WerFault.exe","WerFaultSecure.exe") by Processes.dest Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("dwm.exe","csrss.exe")
| where FileName !in~ ("WerFault.exe","WerFaultSecure.exe","conhost.exe","fontdrvhost.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### w3wp.exe spawning interpreter or LOLBin (http.sys exploitation / IIS RCE marker)

`UC_93_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd values(Processes.process_path) as childPath from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","cscript.exe","wscript.exe","whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process Processes.parent_process_path | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","cscript.exe","wscript.exe","whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","netstat.exe","tasklist.exe")
| project Timestamp, DeviceName, AccountName,
          AppPoolCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Hyper-V worker process (vmwp.exe / vmms.exe) spawning unexpected child (guest-to-host escape)

`UC_93_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd values(Processes.process_path) as childPath from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("vmwp.exe","vmms.exe","vmcompute.exe") AND NOT Processes.process_name IN ("conhost.exe","WerFault.exe","WerFaultSecure.exe","vmcompute.exe","vmwp.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("vmwp.exe","vmms.exe","vmcompute.exe")
| where FileName !in~ ("WerFault.exe","WerFaultSecure.exe","conhost.exe","vmcompute.exe","vmwp.exe")
| project Timestamp, DeviceName, AccountName,
          HyperVParent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_93_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
