# [HIGH] Gogs patches critical zero-day enabling remote code execution

**Source:** BleepingComputer
**Published:** 2026-06-08
**Article:** https://www.bleepingcomputer.com/news/security/gogs-patches-critical-zero-day-enabling-remote-code-execution/

## Threat Profile

Gogs patches critical zero-day enabling remote code execution 
By Sergiu Gatlan 
June 8, 2026
12:18 PM
0 
Gogs has patched a critical security zero-day flaw that can allow attackers to compromise Internet-facing instances and access any repositories (including private ones).
This  argument injection vulnerability has yet to be assigned a CVE ID, can only be exploited by authenticated attackers without admin privileges, and affects all Gogs releases up to and including 0.14.2 and 0.15.0+dev.
They…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-39933`
- **CVE:** `CVE-2024-39932`
- **CVE:** `CVE-2026-26194`
- **CVE:** `CVE-2024-39930`
- **CVE:** `CVE-2025-8110`
- **CVE:** `CVE-2024-55947`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1203** — Exploitation for Client Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1592.002** — Gather Victim Host Information: Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gogs Merge() argument injection — git rebase invoked with --exec= flag

`UC_33_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmdline values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("gogs","gogs.exe")) (Processes.process_name IN ("git","git.exe")) Processes.process="*rebase*" Processes.process="*--exec=*" by host Processes.user Processes.parent_process_name Processes.process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Gogs Merge() argument injection — GHSA-qf6p-p7ww-cwr9 / fixed in PR #8301
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("gogs","gogs.exe")
      or InitiatingProcessParentFileName in~ ("gogs","gogs.exe")
| where FileName in~ ("git","git.exe")
| where ProcessCommandLine has "rebase"
| where ProcessCommandLine has "--exec="
     or ProcessCommandLine matches regex @"(?i)\s--exec(=|\s)"
| project Timestamp, DeviceName, AccountName, AccountDomain,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine,
          FolderPath, SHA256, ReportId
| order by Timestamp desc
```

### [LLM] Gogs daemon ancestry spawns shell / downloader (post-arg-injection RCE)

`UC_33_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("gogs","gogs.exe","git","git.exe")) Processes.process_name IN ("sh","bash","dash","zsh","ash","ksh","cmd.exe","powershell.exe","pwsh","pwsh.exe","curl","curl.exe","wget","wget.exe","python","python3","perl","ruby","php","nc","ncat","socat","certutil.exe","bitsadmin.exe","mshta.exe") (Processes.process="*curl *" OR Processes.process="*wget *" OR Processes.process="*/dev/tcp/*" OR Processes.process="*bash -i*" OR Processes.process="*-c *" OR Processes.process="*base64 -d*" OR Processes.process="*chmod +x*" OR Processes.process="*/tmp/*" OR Processes.process="*/dev/shm/*" OR Processes.process="*powershell -e*" OR Processes.process="*IEX*" OR Processes.process="*DownloadString*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Post-arg-injection shell / downloader spawned by Gogs ancestry
let GogsAncestor = dynamic(["gogs","gogs.exe"]);
let SuspiciousChildren = dynamic([
  "sh","bash","dash","zsh","ash","ksh",
  "cmd.exe","powershell.exe","pwsh","pwsh.exe",
  "curl","curl.exe","wget","wget.exe",
  "python","python3","perl","ruby","php",
  "nc","ncat","ncat.exe","socat",
  "certutil.exe","bitsadmin.exe","mshta.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (GogsAncestor)
      or InitiatingProcessParentFileName in~ (GogsAncestor)
| where FileName in~ (SuspiciousChildren)
// Discriminate from legit server-side git hooks (pre-receive / post-receive / post-update)
| where ProcessCommandLine matches regex @"(?i)(curl\s|wget\s|/dev/tcp/|bash\s+-i|nc\s+-[^\s]*[el]|chmod\s+\+x|/tmp/|/dev/shm/|certutil\s+-(urlcache|decode)|powershell\s+-(e|nop|w hidden)|IEX\s|DownloadString|base64\s+-d)"
| where not(InitiatingProcessCommandLine has_any ("hooks/pre-receive","hooks/post-receive","hooks/update","hooks/post-update"))
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, SHA256, ReportId
| order by Timestamp desc
```

### [LLM] Internet-facing Gogs instances on pre-0.14.3 (CVE-pending Merge() injection)

`UC_33_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count latest(Processes.process_path) as process_path values(Processes.user) as gogs_user from datamodel=Endpoint.Processes where Processes.process_name IN ("gogs","gogs.exe") by host Processes.process_name
| `drop_dm_object_name(Processes)`
| lookup asset_inventory host OUTPUT gogs_version, internet_facing
| eval major=tonumber(mvindex(split(gogs_version,"."),0))
| eval minor=tonumber(mvindex(split(gogs_version,"."),1))
| eval patch=tonumber(mvindex(split(replace(gogs_version,"\+.*$",""),"."),2))
| where major==0 AND (minor<14 OR (minor==14 AND patch<=2) OR (minor==15 AND like(gogs_version, "%+dev%")))
| sort - internet_facing host
| table host process_path gogs_user gogs_version internet_facing
```

**Defender KQL:**
```kql
// Internet-facing Gogs instances on vulnerable versions (≤ 0.14.2, 0.15.0+dev)
let GogsAssets = DeviceTvmSoftwareInventory
  | where SoftwareName =~ "gogs" or (SoftwareVendor =~ "gogs" and SoftwareName has "gogs")
  | extend VerNoMeta = tostring(split(SoftwareVersion, "+")[0])
  | extend Parts = split(VerNoMeta, ".")
  | extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
  | extend IsDevBuild = SoftwareVersion has "+dev"
  | where Major == 0
        and ((Minor < 14)
          or (Minor == 14 and Patch <= 2)
          or (Minor == 15 and IsDevBuild));
GogsAssets
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform, OSVersion) by DeviceId
  ) on DeviceId
| project DeviceName, OSPlatform, OSVersion, PublicIP, IsInternetFacing,
          SoftwareVendor, SoftwareName, SoftwareVersion
| order by IsInternetFacing desc, DeviceName asc
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
  - CVE(s): `CVE-2024-39933`, `CVE-2024-39932`, `CVE-2026-26194`, `CVE-2024-39930`, `CVE-2025-8110`, `CVE-2024-55947`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
