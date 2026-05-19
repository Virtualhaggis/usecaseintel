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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.001** — PowerShell
- **T1059.006** — Python
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable n8n version exposed to CVE-2026-44789/44790/44791 RCE chain

`UC_12_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-44789","CVE-2026-44790","CVE-2026-44791") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-44789","CVE-2026-44790","CVE-2026-44791")
   or (SoftwareName =~ "n8n" and SoftwareVendor in~ ("n8n","n8n.io"))
| extend MajorMinorPatch = SoftwareVersion
| where (SoftwareVersion startswith "1." and SoftwareVersion !startswith "1.123.4" and SoftwareVersion !startswith "1.124" and SoftwareVersion !startswith "1.125")
     or (SoftwareVersion startswith "2.20." and SoftwareVersion !in~ ("2.20.7","2.20.8","2.20.9"))
     or (SoftwareVersion startswith "2.21.")
     or (SoftwareVersion startswith "2.22.0")
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```

### [LLM] n8n Git node argument injection — git invoked by node with dangerous CLI flags

`UC_12_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","n8n","n8n.exe") OR Processes.parent_process IN ("*n8n*","*/n8n/*")) Processes.process_name IN ("git","git.exe") (Processes.process="*--upload-pack=*" OR Processes.process="*--receive-pack=*" OR Processes.process="*--exec=*" OR Processes.process="*--config-env=*" OR Processes.process="*-c core.sshCommand=*" OR Processes.process="*-c protocol.ext.allow*" OR Processes.process="*-c http.extraHeader*" OR Processes.process="*--output=*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git","git.exe")
| where InitiatingProcessFileName in~ ("node","node.exe","n8n","n8n.exe")
   or InitiatingProcessFolderPath has_any (@"/n8n/", @"\n8n\", "/.n8n/")
   or InitiatingProcessCommandLine has "n8n"
| where ProcessCommandLine has_any ("--upload-pack=", "--receive-pack=", "--exec=", "--config-env=", "--output=")
   or ProcessCommandLine matches regex @"(?i)\s-c\s+core\.sshcommand="
   or ProcessCommandLine matches regex @"(?i)\s-c\s+protocol\.(ext|file)\."
   or ProcessCommandLine matches regex @"(?i)\s-c\s+http\.extraheader="
   or ProcessCommandLine matches regex @"(?i)\s-c\s+credential\.helper="
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### [LLM] n8n node.js runtime spawns shell or scripting interpreter — post-RCE execution

`UC_12_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe") OR Processes.parent_process IN ("*/n8n*","*\\n8n*")) Processes.parent_process IN ("*n8n*") Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe","python","python3","python.exe","perl","ruby","nc","ncat","curl","wget") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe")
| where InitiatingProcessCommandLine has "n8n"
   or InitiatingProcessFolderPath has_any (@"/n8n/", @"\n8n\", "/.n8n/", "/usr/local/lib/node_modules/n8n")
| where FileName in~ ("sh","bash","dash","zsh","ksh","cmd.exe","powershell.exe","pwsh","pwsh.exe","python","python3","python.exe","perl","ruby","nc","ncat","socat","curl","wget","busybox")
| where AccountName !endswith "$"
// suppress legitimate n8n child-process node usage (the Execute Command and Code nodes wrap shell execs deliberately — review InitiatingProcessCommandLine for those node IDs first)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessId, SHA256
| order by Timestamp desc
```

### [LLM] n8n process reads sensitive credential or secret files — CVE-2026-44790 arbitrary file read

`UC_12_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node","node.exe","git","git.exe") AND Filesystem.parent_process IN ("*n8n*","*node*")) (Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/etc/passwd" OR Filesystem.file_path="*/.env" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.git-credentials" OR Filesystem.file_path="*/database.sqlite") by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let sensitive_paths = dynamic([
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/authorized_keys",
    "/.aws/credentials", "/.aws/config",
    "/.kube/config",
    "/.docker/config.json",
    "/.git-credentials", "/.netrc",
    "/.env", "/.n8n/database.sqlite", "/.n8n/config"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
   or (ActionType == "FileAccessed")
| where InitiatingProcessFileName in~ ("node","node.exe","git","git.exe")
| where InitiatingProcessCommandLine has "n8n"
   or InitiatingProcessFolderPath has_any (@"/n8n/", @"\n8n\", "/.n8n/", "/usr/local/lib/node_modules/n8n")
| where FolderPath has_any (sensitive_paths)
   or FileName in~ (".env","id_rsa","id_ed25519","credentials","config.json",".git-credentials",".netrc","shadow","passwd")
// suppress n8n's own data directory file activity
| where not (FolderPath has "/.n8n/" and InitiatingProcessCommandLine has "n8n" and FileName !in~ (".env","database.sqlite"))
| project Timestamp, DeviceName, FileName, FolderPath, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessId
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

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
