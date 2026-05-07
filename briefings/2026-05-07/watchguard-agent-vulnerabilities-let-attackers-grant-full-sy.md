# [HIGH] WatchGuard Agent Vulnerabilities Let Attackers Grant Full SYSTEM Privileges on Windows

**Source:** Cyber Security News
**Published:** 2026-05-07
**Article:** https://cybersecuritynews.com/watchguard-agent-vulnerabilities-windows/

## Threat Profile

Home Cyber Security News 
WatchGuard Agent Vulnerabilities Let Attackers Grant Full SYSTEM Privileges on Windows 
By Abinaya 
May 7, 2026 
WatchGuard has released urgent security updates to address multiple high-severity vulnerabilities affecting the WatchGuard Agent on Windows.
The most critical of these flaws allows authenticated local attackers to escalate their privileges to the highest system level, granting them complete control over the compromised machine.
Additional vulnerabilities disc…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-6787`
- **CVE:** `CVE-2026-6788`
- **CVE:** `CVE-2026-41288`
- **CVE:** `CVE-2026-41286`
- **CVE:** `CVE-2026-41287`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1068** — Exploitation for Privileged Escalation
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable WatchGuard Agent for Windows ≤ 1.25.02.0000 (WGSA-2026-00013)

`UC_20_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-6787","CVE-2026-6788","CVE-2026-41288","CVE-2026-41286","CVE-2026-41287") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cvss
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstSeen) ctime(lastSeen)
| sort - cvss
```

**Defender KQL:**
```kql
let WatchGuardCVEs = dynamic(["CVE-2026-6787","CVE-2026-6788","CVE-2026-41288","CVE-2026-41286","CVE-2026-41287"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (WatchGuardCVEs)
   or (SoftwareVendor has_any ("watchguard","panda") and SoftwareName has_any ("agent","aether") and SoftwareVersion startswith "1.25.02")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp,*) by DeviceId) on DeviceId
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing
| order by VulnerabilitySeverityLevel asc, DeviceName asc
```

### [LLM] WatchGuard Agent service spawning shells / LOLBins (post-EOP via CVE-2026-6787/6788/41288)

`UC_20_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("AgentSvc.exe","Agent Service.exe","WGAgent.exe") OR Processes.parent_process_path="*\\Panda Security\\Panda Aether Agent\\*" OR Processes.parent_process_path="*\\WatchGuard\\*Agent*\\*") (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","net.exe","net1.exe","whoami.exe","reg.exe","sc.exe","schtasks.exe","bitsadmin.exe","certutil.exe")) NOT (Processes.user IN ("*$","*SYSTEM") AND Processes.process_name="msiexec.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_integrity_level
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let AgentBinaries = dynamic(["agentsvc.exe","agent service.exe","wgagent.exe"]);
let AgentPaths = dynamic([@"\Panda Security\Panda Aether Agent\", @"\WatchGuard\Agent\", @"\WatchGuard\Endpoint Agent\"]);
let SuspiciousChildren = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","net.exe","net1.exe","whoami.exe","reg.exe","sc.exe","schtasks.exe","bitsadmin.exe","certutil.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (AgentBinaries)
    or InitiatingProcessFolderPath has_any (AgentPaths)
| where FileName in~ (SuspiciousChildren)
| where InitiatingProcessIntegrityLevel in ("System","High")
| where not(FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("/i","/x","REINSTALL"))
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ParentIntegrity = InitiatingProcessIntegrityLevel,
          ChildImage  = FolderPath,
          ChildName   = FileName,
          ChildCmd    = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Article-specific behavioural hunt — WatchGuard Agent Vulnerabilities Let Attackers Grant Full SYSTEM Privileges on W

`UC_20_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — WatchGuard Agent Vulnerabilities Let Attackers Grant Full SYSTEM Privileges on W ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — WatchGuard Agent Vulnerabilities Let Attackers Grant Full SYSTEM Privileges on W
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-6787`, `CVE-2026-6788`, `CVE-2026-41288`, `CVE-2026-41286`, `CVE-2026-41287`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
