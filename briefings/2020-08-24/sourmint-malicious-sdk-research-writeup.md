# [HIGH] SourMint malicious SDK research writeup

**Source:** Snyk
**Published:** 2020-08-24
**Article:** https://snyk.io/blog/sour-mint-malicious-sdk/

## Threat Profile

Snyk Blog In this article
Written by Kirill Efimov 
August 24, 2020
0 mins read Overview 
Excessive data collection on iOS [August 2020] 
Remote Code Execution (RCE) on iOS [October 2020] 
Download tracking in Android [October 2020] 
Timeline 
Overview The Mintegral SDK is a popular mobile app advertising SDK available for both the iOS and Android platforms. It is used by thousands of mobile apps with over a billion downloads per month. The SDK is used by application developers to monetize their…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `9329a7706dd43d6ed64d022ad0e7b13b`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1567** — Exfiltration Over Web Service
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SourMint/Mintegral SDK covert click-data exfiltration to n.systemlog.me

`UC_3304_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*n.systemlog.me*" OR Web.dest="n.systemlog.me" OR Web.url="*systemlog.me/log*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "systemlog.me"
| where RemoteUrl has "n.systemlog.me" or RemoteUrl has "systemlog.me/log"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Devices=make_set(DeviceName,50) by RemoteUrl, InitiatingProcessFileName, RemoteIP
| order by LastSeen desc
```

### Mintegral SourMint SDK config/analytics beacon to rayjump.com

`UC_3304_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query="*setting.rayjump.com*" OR DNS.query="*analytics.rayjump.com*" OR DNS.query="*rayjump.com*") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "rayjump.com"
| extend Endpoint = case(RemoteUrl has "setting.rayjump.com", "settings-control", RemoteUrl has "analytics.rayjump.com", "analytics", "other-rayjump")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), URLs=make_set(RemoteUrl,20) by DeviceName, InitiatingProcessFileName, Endpoint
| order by LastSeen desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — SourMint malicious SDK research writeup

`UC_3304_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SourMint malicious SDK research writeup ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/MobileSubstrate/MobileSubstrate.dylib*" OR Filesystem.file_path="*/usr/sbin/sshd*" OR Filesystem.file_path="*/etc/apt*" OR Filesystem.file_path="*/usr/bin/ssh*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SourMint malicious SDK research writeup
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/sbin/sshd", "/etc/apt", "/usr/bin/ssh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9329a7706dd43d6ed64d022ad0e7b13b`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
