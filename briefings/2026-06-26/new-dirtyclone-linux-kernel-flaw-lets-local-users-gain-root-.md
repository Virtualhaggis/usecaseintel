# [HIGH] New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets

**Source:** The Hacker News
**Published:** 2026-06-26
**Article:** https://thehackernews.com/2026/06/new-dirtyclone-linux-kernel-flaw-lets.html

## Threat Profile

New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets 
 Swati Khandelwal  Jun 26, 2026 Linux / Vulnerability 
DirtyClone is a new Linux kernel privilege escalation in the DirtyFrag family. JFrog Security Research published a working exploit walkthrough for the flaw on June 25, the first public demonstration for this variant.
Tracked as  CVE-2026-43503  (CVSS 8.8), it lets a local user corrupt file-backed memory through a cloned network packet and gain root. The patch l…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-43503`
- **CVE:** `CVE-2026-31431`
- **CVE:** `CVE-2026-43284`
- **CVE:** `CVE-2026-43500`
- **CVE:** `CVE-2026-46300`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1611** — Escape to Host
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unprivileged user+network namespace creation (DirtyClone CAP_NET_ADMIN path)

`UC_16_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=unshare Processes.process="*--user*" Processes.user!=root by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where like(process,"%--net%") OR like(process,"%-n %") OR like(process,"%--map-root%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "unshare"
| where ProcessCommandLine has_any ("--user","-U","--map-root-user")
| where ProcessCommandLine has_any ("--net","-n")
| where AccountName != "root" and isnotempty(AccountName)
| where InitiatingProcessFileName !in~ ("podman","buildah","conmon","runc","crun","bwrap","chrome","chrome_sandbox","flatpak")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Loopback IPsec/XFRM tunnel configured by local process (DirtyClone write primitive)

`UC_16_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN (ip,setkey) by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where (like(process,"%xfrm%") OR process_name="setkey") AND (like(process,"%127.0.0.1%") OR like(process,"%::1%")) AND (like(process,"%state add%") OR like(process,"%policy add%") OR like(process,"% add %")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ip","setkey")
| where (ProcessCommandLine has "xfrm" or FileName =~ "setkey")
| where ProcessCommandLine has_any ("state add","policy add"," add ")
| where ProcessCommandLine has_any ("127.0.0.1","::1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Namespace creation followed by loopback IPsec setup (DirtyClone exploit chain)

`UC_16_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name=unshare OR Processes.process_name=ip OR Processes.process_name=setkey) by Processes.dest Processes.user Processes.process Processes.process_name _time span=10m | `drop_dm_object_name(Processes)` | eval stage=case(process_name="unshare" AND like(process,"%--user%") AND (like(process,"%--net%") OR like(process,"%-n %")),"userns", (like(process,"%xfrm%") OR process_name="setkey") AND (like(process,"%127.0.0.1%") OR like(process,"%::1%")),"ipsec_loopback", true(),"other") | where stage!="other" | stats dc(stage) as stages values(stage) as stages_seen values(process) as cmds min(_time) as firstTime max(_time) as lastTime by dest user | where stages>=2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let win = 10m;
let ns = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "unshare"
    | where ProcessCommandLine has_any ("--user","-U") and ProcessCommandLine has_any ("--net","-n")
    | project NsTime = Timestamp, DeviceId, DeviceName, NsUser = AccountName, NsCmd = ProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ip","setkey")
| where ProcessCommandLine has "xfrm" and ProcessCommandLine has_any ("127.0.0.1","::1")
| project IpTime = Timestamp, DeviceId, DeviceName, IpUser = AccountName, IpCmd = ProcessCommandLine
| join kind=inner ns on DeviceId
| where IpTime between (NsTime .. NsTime + win)
| project DeviceName, NsUser, IpUser, NsTime, IpTime, DelaySec = datetime_diff('second', IpTime, NsTime), NsCmd, IpCmd
| order by IpTime desc
```

### Hosts exposed to DirtyFrag-class kernel LPE (CVE-2026-43503 and siblings)

`UC_16_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-43503","CVE-2026-43284","CVE-2026-43500","CVE-2026-46300","CVE-2026-31431")
| summarize Cves = make_set(CveId), arg_max(Timestamp, *) by DeviceId, DeviceName
| project DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion, Cves, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
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

### Article-specific behavioural hunt — New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets

`UC_16_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/su*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New DirtyClone Linux Kernel Flaw Lets Local Users Gain Root via Cloned Packets
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/su"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-43503`, `CVE-2026-31431`, `CVE-2026-43284`, `CVE-2026-43500`, `CVE-2026-46300`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
