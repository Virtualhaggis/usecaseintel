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
- **CVE:** `CVE-2026-11645`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

`UC_4_2` · phase: **install** · confidence: **High**

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
  - CVE(s): `CVE-2026-43503`, `CVE-2026-31431`, `CVE-2026-43284`, `CVE-2026-43500`, `CVE-2026-46300`, `CVE-2026-11645`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
