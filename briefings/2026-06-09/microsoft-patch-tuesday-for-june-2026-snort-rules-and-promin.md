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
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1068** — Exploitation for Privilege Escalation
- **T1611** — Escape to Host
- **T1566.001** — Phishing: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Pre-auth HTTP.sys integer overflow probe (CVE-2026-47291)

`UC_103_2` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("w3wp.exe","svchost.exe") Processes.action="terminated" by host Processes.process_name Processes.parent_process_name _time span=10m | `drop_dm_object_name(Processes)` | join type=left host [| tstats summariesonly=t count as inboundHttpHits dc(Web.src) as distinctSources from datamodel=Web where Web.dest_port IN (80,443,8080) by Web.dest _time span=10m | rename Web.dest as host | where inboundHttpHits > 50] | where isnotnull(inboundHttpHits) | sort - lastTime
```

**Defender KQL:**
```kql
// Hunt: w3wp.exe / svchost.exe (http-hosting) crashes correlated with recent inbound HTTP — possible CVE-2026-47291 probing
let WindowMinutes = 10m;
let Crashes = DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where InitiatingProcessFileName =~ "services.exe"
    | where FileName in~ ("w3wp.exe","svchost.exe")
    | where ActionType == "ProcessCreated"
    | summarize StartCount = count() by DeviceId, DeviceName, FileName, bin(Timestamp, WindowMinutes)
    | where StartCount >= 3;  // 3+ restarts of the same http-hosting process in 10m is unusual
let InboundHttp = DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where ActionType == "InboundConnectionAccepted"
    | where LocalPort in (80, 443, 8080, 8443)
    | where RemoteIPType == "Public"
    | summarize InboundHits = count(), DistinctSrcIPs = dcount(RemoteIP) by DeviceId, bin(Timestamp, WindowMinutes);
Crashes
| join kind=inner InboundHttp on DeviceId, $left.Timestamp == $right.Timestamp
| project Timestamp, DeviceName, FileName, StartCount, InboundHits, DistinctSrcIPs
| order by Timestamp desc
```

### Malicious RDP server post-connect child process (CVE-2026-42985)

`UC_103_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd from datamodel=Endpoint.Processes where Processes.parent_process_name="mstsc.exe" Processes.process_name!="mstsc.exe" by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(process_name, "^(conhost|werfault|RuntimeBroker|rdpclip|tabtip)\.exe$")
```

**Defender KQL:**
```kql
// Hunt: mstsc.exe spawning a non-trivial child after recent outbound RDP — CVE-2026-42985 / -42992 / -44799 client-side RCE
let RdpEgress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where RemotePort == 3389 and RemoteIPType == "Public"
    | project ConnectTime = Timestamp, DeviceId, DeviceName, AccountName = InitiatingProcessAccountName, RemoteIP, RemoteUrl;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "mstsc.exe"
| where FileName !in~ ("conhost.exe","werfault.exe","runtimebroker.exe","rdpclip.exe","tabtip.exe","mstsc.exe")
| where AccountName !endswith "$"
| join kind=inner RdpEgress on DeviceId
| where Timestamp between (ConnectTime .. ConnectTime + 5m)
| project Timestamp, ConnectTime, DelaySec = datetime_diff('second', Timestamp, ConnectTime), DeviceName, AccountName, ChildFile = FileName, ChildCmd = ProcessCommandLine, RemoteIP
| order by Timestamp desc
```

### Win32K GRFX SYSTEM elevation chain (CVE-2026-44803/44812)

`UC_103_4` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("dwm.exe","csrss.exe","winlogon.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe") by host Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
// Hunt: shell / scripting child of dwm.exe / csrss.exe / winlogon.exe — anomalous, possible Win32K-GRFX LPE chain (CVE-2026-44803/44812)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("dwm.exe","csrss.exe","winlogon.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","net.exe","net1.exe","whoami.exe")
| where ProcessIntegrityLevel in~ ("System","High")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### Hyper-V worker process anomaly — guest-to-host escape (CVE-2026-45607/45641/47652)

`UC_103_5` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as childCmd from datamodel=Endpoint.Processes where Processes.parent_process_name="vmwp.exe" Processes.process_name!="vmwp.exe" by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(process_name, "^(conhost|werfault|vmcompute)\.exe$")
```

**Defender KQL:**
```kql
// Hunt: vmwp.exe (Hyper-V VM worker) spawning unexpected children OR crashing repeatedly — possible guest-to-host escape via CVE-2026-45607 / -45641 / -47652
let UnusualChildren = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "vmwp.exe"
    | where FileName !in~ ("conhost.exe","werfault.exe","vmcompute.exe","vmwp.exe")
    | project Timestamp, DeviceName, Kind = "UnusualChild",
              Parent = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              Child = FileName,
              ChildCmd = ProcessCommandLine,
              SHA256;
let CrashBursts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "werfault.exe"
    | where ProcessCommandLine has "vmwp.exe"
    | summarize Crashes = count() by DeviceId, DeviceName, bin(Timestamp, 30m)
    | where Crashes >= 2
    | extend Kind = "CrashBurst", Child = "werfault.exe", ChildCmd = strcat(Crashes, " vmwp.exe crashes/30m");
union isfuzzy=true UnusualChildren, CrashBursts
| order by Timestamp desc
```

### Outlook preview pane → Word type-confusion code exec (CVE-2026-45456/45458/47635)

`UC_103_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("outlook.exe","winword.exe")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(process_name, "^(splwow64|winword|excel|powerpnt|onenote|msoadfsb|werfault|conhost|RuntimeBroker|MicrosoftEdgeUpdate|olk|searchprotocolhost)\.exe$") | where NOT (parent_process_name="winword.exe" AND process_name="outlook.exe")
```

**Defender KQL:**
```kql
// Alert: OUTLOOK.EXE / WINWORD.EXE spawning a non-Office child — CVE-2026-45456 / -45458 / -47635 / -45461 / -45463 / -45472 / -45474 preview-pane RCE
let OfficeAllowList = dynamic(["splwow64.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe","msoadfsb.exe","werfault.exe","conhost.exe","runtimebroker.exe","microsoftedgeupdate.exe","olk.exe","searchprotocolhost.exe","officeclicktorun.exe","msoia.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe")
| where tolower(FileName) !in (OfficeAllowList)
| where not (InitiatingProcessFileName =~ "winword.exe" and FileName =~ "outlook.exe")
| where AccountName !endswith "$"
| extend SuspiciousChildScore =
      iff(FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","msbuild.exe","installutil.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe"), 5,
      iff(FolderPath has_any (@"\AppData\", @"\Temp\", @"\Public\", @"\ProgramData\"), 3, 1))
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildFolderPath = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, SuspiciousChildScore
| order by SuspiciousChildScore desc, Timestamp desc
```

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_103_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
