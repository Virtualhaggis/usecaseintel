# [CRIT] Researcher Details WhatsApp-to-Host Attack Chain Using Three OpenClaw Flaws

**Source:** The Hacker News
**Published:** 2026-07-10
**Article:** https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html

## Threat Profile

Researcher Details WhatsApp-to-Host Attack Chain Using Three OpenClaw Flaws 
 Ravie Lakshmanan  Jul 10, 2026 AI Security / Vulnerability 
Details have emerged about three now-patched security flaws in the OpenClaw personal artificial intelligence (AI) assistant that, if successfully exploited, could enable credential theft, privilege escalation, and arbitrary code execution on the host.
A brief description of the high-severity vulnerabilities is as follows -
GHSA-hjr6-g723-hmfm (CVSS score: 8.…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `GHSA-hjr6-g723-hmfm`
- **CVE:** `GHSA-9969-8g9h-rxwm`
- **CVE:** `GHSA-575v-8hfq-m3mc`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059** — Command and Scripting Interpreter
- **T1203** — Exploitation for Client Execution
- **T1610** — Deploy Container
- **T1611** — Escape to Host
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Git ext:: external transport helper command execution (OpenClaw WhatsApp-to-host RCE)

`UC_14_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*ext::*" (Processes.process_name=git OR Processes.process="*git *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "ext::"
| where FileName =~ "git" or ProcessCommandLine has "git"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Container bind-mount of parent /home or /var (OpenClaw denylist parent-directory bypass)

`UC_14_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("docker","podman","nerdctl","runc","mount")) AND (Processes.process="*-v /home:*" OR Processes.process="*-v /var:*" OR Processes.process="*--volume /home:*" OR Processes.process="*--volume /var:*" OR Processes.process="*source=/home,*" OR Processes.process="*source=/var,*" OR Processes.process="*--bind /home *" OR Processes.process="*--bind /var *") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("docker","podman","nerdctl","runc","mount")
| where ProcessCommandLine has_any ("-v /home:","-v /var:","--volume /home:","--volume /var:","source=/home,","source=/var,","--bind /home ","--bind /var ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Docker socket access by non-Docker process (OpenClaw /var mount host escape)

`UC_14_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*docker.sock*" AND NOT Processes.process_name IN ("docker","dockerd","containerd","podman","dockerd-current") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "docker.sock"
| where FileName !in~ ("docker","dockerd","containerd","podman")
| where ProcessCommandLine has_any ("--unix-socket","unix://","/containers/","/exec","socat","curl")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Single process reading multiple users' SSH/AWS/GPG secrets under /home (OpenClaw mount harvest)

`UC_14_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_secret_files values(Filesystem.file_name) as file_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/home/*/.ssh/*" OR Filesystem.file_path="/home/*/.aws/credentials" OR Filesystem.file_path="/home/*/.gnupg/*") by Filesystem.dest Filesystem.user
| `drop_dm_object_name(Filesystem)`
| where distinct_secret_files >= 3
| convert ctime(firstTime) ctime(lastTime)
| sort - distinct_secret_files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/home/"
| where FolderPath has_any ("/.ssh/", "/.aws/", "/.gnupg/")
| where FileName in~ ("id_rsa","id_ed25519","id_ecdsa","id_dsa","credentials") or FolderPath has "/.gnupg/"
| extend HomeUser = extract(@"/home/([^/]+)/", 1, FolderPath)
| summarize DistinctHomeUsers = dcount(HomeUser), Users = make_set(HomeUser, 20), Files = make_set(FolderPath, 50), FileCount = count() by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, bin(Timestamp, 10m)
| where DistinctHomeUsers >= 2
| order by DistinctHomeUsers desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `GHSA-hjr6-g723-hmfm`, `GHSA-9969-8g9h-rxwm`, `GHSA-575v-8hfq-m3mc`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
