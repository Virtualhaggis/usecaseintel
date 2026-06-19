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
- **T1210** — Exploitation of Remote Services
- **T1203** — Exploitation for Client Execution
- **T1566.002** — Spearphishing Link
- **T1204.002** — Malicious File
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1611** — Escape to Host
- **T1068** — Exploitation for Privilege Escalation
- **T1499.004** — Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### June 2026 Patch Tuesday — exposure inventory for critical RCE CVEs

`UC_168_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812","CVE-2026-42992","CVE-2026-44799","CVE-2026-44801","CVE-2026-47289","CVE-2026-48563","CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-45657","CVE-2026-48574","CVE-2026-42987","CVE-2026-44815","CVE-2026-45456","CVE-2026-45458","CVE-2026-47635","CVE-2026-45461","CVE-2026-45463","CVE-2026-45472","CVE-2026-45474","CVE-2026-44810","CVE-2026-32193","CVE-2026-45648","CVE-2026-47644","CVE-2026-45476","CVE-2026-26142") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature
| `drop_dm_object_name(Vulnerabilities)`
| stats values(cve) as missing_cves dc(cve) as missing_cve_count min(firstSeen) as firstSeen max(lastSeen) as lastSeen by dest
| where missing_cve_count > 0
| sort - missing_cve_count
```

**Defender KQL:**
```kql
let JuneCriticalCVEs = dynamic(["CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812","CVE-2026-42992","CVE-2026-44799","CVE-2026-44801","CVE-2026-47289","CVE-2026-48563","CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-45657","CVE-2026-48574","CVE-2026-42987","CVE-2026-44815","CVE-2026-45456","CVE-2026-45458","CVE-2026-47635","CVE-2026-45461","CVE-2026-45463","CVE-2026-45472","CVE-2026-45474","CVE-2026-44810","CVE-2026-32193","CVE-2026-45648","CVE-2026-47644","CVE-2026-45476","CVE-2026-26142"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in (JuneCriticalCVEs)
| where VulnerabilitySeverityLevel in ("Critical","High")
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, IsExploitAvailable, CvssScore) on CveId
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            MissingCVEs = make_set(CveId), AffectedProducts = make_set(SoftwareName),
            RecommendedKBs = make_set(RecommendedSecurityUpdateId),
            ExploitAvailableCVEs = make_set_if(CveId, IsExploitAvailable == true)
            by DeviceId, DeviceName, OSPlatform, OSVersion
| extend MissingCount = array_length(MissingCVEs)
| order by array_length(ExploitAvailableCVEs) desc, MissingCount desc
```

### Remote Desktop Client (mstsc.exe) spawning anomalous child after outbound RDP — malicious-server RCE

`UC_168_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="mstsc.exe"
    AND NOT Processes.process_name IN ("mstsc.exe","conhost.exe","WerFault.exe","wermgr.exe","splwow64.exe","rdpclip.exe","rdpinit.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| where NOT match(user, "\\$$")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "mstsc.exe"
| where FileName !in~ ("conhost.exe","WerFault.exe","wermgr.exe","splwow64.exe","rdpclip.exe","rdpinit.exe","mstsc.exe")
| where AccountName !endswith "$"
| extend SuspChild = FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msbuild.exe","installutil.exe","whoami.exe","net.exe","net1.exe")
| extend SuspPath = FolderPath has_any (@"\Users\Public\",@"\AppData\Local\Temp\",@"\AppData\Roaming\",@"\ProgramData\",@"\Windows\Temp\")
| where SuspChild or SuspPath
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath, ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### Outlook/Word spawning script interpreter or LOLBin — preview-pane type-confusion RCE (CVE-2026-45456/45458/47635)

`UC_168_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("OUTLOOK.EXE","outlook.exe","WINWORD.EXE","winword.exe")
    AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msbuild.exe","installutil.exe","msiexec.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| where NOT match(user, "\\$$")
| sort - lastTime
```

**Defender KQL:**
```kql
let SuspChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msbuild.exe","installutil.exe","msiexec.exe","hh.exe"]);
let OfficeParents = dynamic(["outlook.exe","winword.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (OfficeParents)
| where FileName in~ (SuspChildren)
   or FolderPath has_any (@"\Users\Public\",@"\AppData\Local\Temp\",@"\AppData\Roaming\Microsoft\Templates\",@"\AppData\Roaming\Microsoft\Word\STARTUP\",@"\AppData\Roaming\Microsoft\Outlook\",@"\ProgramData\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### IIS w3wp.exe spawning shell or recon LOLBin — potential HTTP.sys integer-overflow (CVE-2026-47291) post-exploit

`UC_168_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="w3wp.exe"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","whoami.exe","net.exe","net1.exe","nltest.exe","systeminfo.exe","tasklist.exe","ipconfig.exe","arp.exe","wmic.exe","hostname.exe","quser.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
let ReconShells = dynamic(["cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","whoami.exe","net.exe","net1.exe","nltest.exe","systeminfo.exe","tasklist.exe","ipconfig.exe","arp.exe","wmic.exe","hostname.exe","quser.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (ReconShells)
| project Timestamp, DeviceName, AccountName,
          AppPool = InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountSid,
          ChildImage = FolderPath, ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### Hyper-V worker process (vmwp.exe) anomalous child or unexpected hardware-resource access — guest-to-host escape (CVE-2026-45607/45641/47652)

`UC_168_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("vmwp.exe","vmms.exe","vmcompute.exe","vmsp.exe")
    AND NOT Processes.process_name IN ("vmwp.exe","vmms.exe","vmcompute.exe","vmsp.exe","WerFault.exe","conhost.exe","wermgr.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
let HypervProcs = dynamic(["vmwp.exe","vmms.exe","vmcompute.exe","vmsp.exe"]);
let AllowedChildren = dynamic(["vmwp.exe","vmms.exe","vmcompute.exe","vmsp.exe","WerFault.exe","conhost.exe","wermgr.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (HypervProcs)
| where FileName !in~ (AllowedChildren)
| extend SuspChild = FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","whoami.exe","net.exe","net1.exe","nltest.exe","reg.exe","sc.exe","schtasks.exe","wmic.exe")
| extend SuspPath = FolderPath has_any (@"\Users\Public\",@"\AppData\",@"\ProgramData\",@"\Windows\Temp\",@"\Windows\Tasks\")
| where SuspChild or SuspPath
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountSid,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath, ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### Windows Kernel BugCheck following inbound network burst — possible CVE-2026-45657 TCP/IP UAF exploitation

`UC_168_7` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as crash_count min(_time) as crash_time max(_time) as last_crash_time from datamodel=Endpoint.Filesystem where source="WinEventLog:System" (EventCode=1001 OR EventCode=41 OR EventCode=6008) by host
| join type=inner host
  [| tstats `summariesonly` count as inbound_count dc(All_Traffic.src_ip) as distinct_src from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (80,135,139,445,3389,5985) AND All_Traffic.direction="inbound" earliest=-1h by All_Traffic.dest as host
    | rename All_Traffic.dest as host]
| where inbound_count > 1000 OR distinct_src > 50
| sort - crash_time
```

**Defender KQL:**
```kql
let CrashWindow = 2h;
let Crashes = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("UnexpectedShutdown","OsBugCheck","KernelCrash")
    | project CrashTime = Timestamp, DeviceId, DeviceName, CrashDetails = AdditionalFields;
Crashes
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == "InboundConnectionAccepted" or ActionType == "ConnectionAccepted"
    | where RemoteIPType == "Public"
    | summarize InboundCount = count(), UniqueSrcIPs = dcount(RemoteIP), SampleRemotes = make_set(RemoteIP, 10), TargetPorts = make_set(LocalPort, 10)
              by DeviceId, NetWindowEnd = bin(Timestamp, CrashWindow)
    | where InboundCount > 500 or UniqueSrcIPs > 25
) on DeviceId
| where CrashTime between (NetWindowEnd - CrashWindow .. NetWindowEnd + CrashWindow)
| project CrashTime, DeviceName, InboundCount, UniqueSrcIPs, SampleRemotes, TargetPorts, CrashDetails
| order by CrashTime desc
```

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_168_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
