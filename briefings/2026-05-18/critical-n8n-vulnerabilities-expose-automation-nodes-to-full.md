# [CRIT] Critical n8n Vulnerabilities Expose Automation Nodes to Full RCE

**Source:** Cyber Security News
**Published:** 2026-05-18
**Article:** https://cybersecuritynews.com/n8n-rce-vulnerabilities/

## Threat Profile

Home Cyber Security News 
Critical n8n Vulnerabilities Expose Automation Nodes to Full RCE 
By Abinaya 
May 18, 2026 
A fresh set of critical vulnerabilities in the popular workflow automation platform n8n is raising serious security concerns, as researchers warn that attackers could chain multiple flaws to achieve full remote code execution (RCE) on affected systems.
The vulnerabilities, disclosed via GitHub Security Advisories and tracked as CVE-2026-44789, CVE-2026-44790, and CVE-2026-44791, …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44789`
- **CVE:** `CVE-2026-44790`
- **CVE:** `CVE-2026-44791`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] n8n Git node argument injection via crafted Git CLI flags (CVE-2026-44790)

`UC_19_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=git OR Processes.process_name=git.exe) AND (Processes.parent_process_name=node OR Processes.parent_process_name=node.exe OR Processes.parent_process="*n8n*") AND (Processes.process="*--upload-pack=*" OR Processes.process="*--receive-pack=*" OR Processes.process="*-c core.sshCommand*" OR Processes.process="*-c http.extraHeader*" OR Processes.process="*--config-env=*" OR Processes.process="*--exec-path=*" OR Processes.process="*-c protocol.allow*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git", "git.exe")
| where InitiatingProcessFileName in~ ("node", "node.exe") 
    or InitiatingProcessCommandLine has "n8n" 
    or InitiatingProcessFolderPath has "n8n"
| where ProcessCommandLine has_any ("--upload-pack=", "--receive-pack=", "-c core.sshCommand", "-c http.extraHeader", "--config-env=", "--exec-path=", "-c protocol.allow", "-c uploadpack.")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPid = InitiatingProcessId, SHA256
| order by Timestamp desc
```

### [LLM] n8n Node.js worker spawning reverse-shell pattern child (post-exploit RCE indicator)

`UC_19_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=node OR Processes.parent_process_name=node.exe OR Processes.parent_process="*n8n*") AND (Processes.process_name=bash OR Processes.process_name=sh OR Processes.process_name=dash OR Processes.process_name=zsh OR Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe) AND (Processes.process="*/dev/tcp/*" OR Processes.process="*/dev/udp/*" OR Processes.process="*bash -i*" OR Processes.process="*sh -i *" OR Processes.process="*mkfifo*" OR Processes.process="*socat*tcp*" OR Processes.process="*ncat -e*" OR Processes.process="*nc -e *" OR Processes.process="*IEX(New-Object*" OR Processes.process="*-nop -w hidden*" OR Processes.process="*DownloadString*" OR Processes.process="*exec 5<>*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node", "node.exe")
    or InitiatingProcessCommandLine has "n8n"
    or InitiatingProcessFolderPath has "n8n"
| where FileName in~ ("bash","sh","dash","zsh","ksh","cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "/dev/tcp/", "/dev/udp/", "bash -i", "sh -i ",
    "mkfifo", "socat tcp", "ncat -e", "nc -e ",
    "exec 5<>", "0<&", "IEX(New-Object",
    "-nop -w hidden", "DownloadString", "Invoke-WebRequest http",
    "FromBase64String"
  )
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPid = InitiatingProcessId
| order by Timestamp desc
```

### [LLM] n8n version vulnerable to CVE-2026-44789/44790/44791 present on managed devices

`UC_19_6` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-44789","CVE-2026-44790","CVE-2026-44791") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort 0 - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-44789", "CVE-2026-44790", "CVE-2026-44791")
| join kind=leftouter DeviceInfo on DeviceId
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName,
          SoftwareVersion, CveId, VulnerabilitySeverityLevel,
          RecommendedSecurityUpdate, IsInternetFacing
| order by IsInternetFacing desc, VulnerabilitySeverityLevel desc
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-44789`, `CVE-2026-44790`, `CVE-2026-44791`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
