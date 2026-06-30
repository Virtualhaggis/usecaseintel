# [HIGH] CISA Warns Critical Lantronix EDS5000 Flaw Is Being Actively Exploited

**Source:** The Hacker News
**Published:** 2026-06-24
**Article:** https://thehackernews.com/2026/06/cisa-warns-critical-lantronix-eds5000.html

## Threat Profile

CISA Warns Critical Lantronix EDS5000 Flaw Is Being Actively Exploited 
 Ravie Lakshmanan  Jun 24, 2026 Vulnerability / Network Security 
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) on Tuesday warned of active exploitation of a critical security flaw impacting Lantronix EDS5000 Series devices, urging Federal Civilian Executive Branch (FCEB) agencies to apply the fixes by June 26, 2026.
The vulnerability in question is CVE-2025-67038 (CVSS score: 9.8), a code injection flaw…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-67038`
- **CVE:** `CVE-2026-34908`
- **CVE:** `CVE-2026-34909`
- **CVE:** `CVE-2026-34910`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UniFi OS unauthenticated RCE chain exploit attempt via nginx URI-normalization bypass (CVE-2026-34908/9/10)

`UC_73_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/auth/validate-sso/*" AND (Web.url="*..%2f*" OR Web.url="*..%2e*" OR Web.url="*%2e%2e*" OR Web.url="*latest_package*")) by Web.src, Web.dest, Web.dest_port, Web.http_method, Web.url, Web.http_user_agent, Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

### UniFi OS Server post-exploit reverse shell from ucs-update / unifi service account (CVE-2026-34910)

`UC_73_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_name IN ("sh","bash","dash","nc","ncat","netcat","python","python3","perl","cmd.exe","powershell.exe") AND (Endpoint.Processes.user IN ("ucs-update","unifi") OR Endpoint.Processes.parent_process_name IN ("unifi","ucs-update","unifi-core")) AND (Endpoint.Processes.process="*/dev/tcp/*" OR Endpoint.Processes.process="*mkfifo*" OR Endpoint.Processes.process="*bash -i*" OR Endpoint.Processes.process="*socket.socket*" OR Endpoint.Processes.process="*nc -e*" OR Endpoint.Processes.process="*-e /bin*" OR Endpoint.Processes.process="*Net.Sockets*")) by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process_name, Endpoint.Processes.process_name, Endpoint.Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName has_any ("ucs-update","unifi") or InitiatingProcessFolderPath has_any ("unifi-core","UniFi OS Server","/usr/lib/unifi")
| where FileName in~ ("sh","bash","dash","nc","ncat","netcat","python","python3","perl","cmd.exe","powershell.exe")
| where ProcessCommandLine has_any ("/dev/tcp/","mkfifo","bash -i","sh -i","socket.socket","nc -e","ncat -e","-e /bin","Net.Sockets","Invoke-")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

### KEV exposure hunt: UniFi OS and Lantronix EDS5000 actively-exploited CVEs present in fleet

`UC_73_6` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2026-34908","CVE-2026-34909","CVE-2026-34910","CVE-2025-67038")) by Vulnerabilities.dest, Vulnerabilities.cve, Vulnerabilities.severity, Vulnerabilities.signature, Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | sort - cve
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-34908","CVE-2026-34909","CVE-2026-34910","CVE-2025-67038")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId) on DeviceId
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, PublicIP
| order by IsInternetFacing desc, CveId asc
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
  - CVE(s): `CVE-2025-67038`, `CVE-2026-34908`, `CVE-2026-34909`, `CVE-2026-34910`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
