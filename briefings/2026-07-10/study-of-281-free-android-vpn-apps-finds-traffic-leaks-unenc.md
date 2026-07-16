# [CRIT] Study of 281 Free Android VPN Apps Finds Traffic Leaks, Unencrypted Data, and Tracking

**Source:** The Hacker News
**Published:** 2026-07-10
**Article:** https://thehackernews.com/2026/07/study-of-281-free-android-vpn-apps.html

## Threat Profile

Study of 281 Free Android VPN Apps Finds Traffic Leaks, Unencrypted Data, and Tracking 
 Swati Khandelwal  Jul 10, 2026 Mobile Security / Privacy 
Researchers ran 281 of the most popular free VPN apps on the Google Play Store through a new testing system and found that many fail at the basics people install a VPN for, i.e., keeping their traffic private and secure.
The apps flagged with at least one problem have been installed more than 2.4 billion times.
The problems are basic, not sophistica…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2016-6329`
- **CVE:** `CVE-2016-2183`

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
- **T1557** — Adversary-in-the-Middle
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1020** — Automated Exfiltration
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1600.001** — Weaken Encryption: Reduce Key Space
- **T1040** — Network Sniffing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Android VPN app fetches OpenVPN config over cleartext HTTP (tunnel-hijack exposure)

`UC_107_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=80 (All_Traffic.url="*.ovpn" OR All_Traffic.url="*.conf" OR All_Traffic.url="*openvpn*config*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.url All_Traffic.app | rename All_Traffic.* as * | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 80
| where RemoteUrl endswith ".ovpn" or RemoteUrl endswith ".conf" or (RemoteUrl has "openvpn" and RemoteUrl has "config")
| join kind=inner (DeviceInfo | where OSPlatform =~ "Android" | distinct DeviceId, DeviceName, OSPlatform) on DeviceId
| project Timestamp, DeviceName, OSPlatform, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### DNS leak: Android endpoint queries public resolvers while VPN tunnel expected

`UC_107_7` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=53 (All_Traffic.dest="8.8.8.8" OR All_Traffic.dest="8.8.4.4" OR All_Traffic.dest="1.1.1.1" OR All_Traffic.dest="1.0.0.1" OR All_Traffic.dest="9.9.9.9" OR All_Traffic.dest="208.67.222.222" OR All_Traffic.dest="208.67.220.220") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | rename All_Traffic.* as * | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 53
| where RemoteIP in ("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112","208.67.222.222","208.67.220.220")
| join kind=inner (DeviceInfo | where OSPlatform =~ "Android" | distinct DeviceId, DeviceName, OSPlatform) on DeviceId
| summarize QueryCount=count(), Resolvers=make_set(RemoteIP), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName
| order by QueryCount desc
```

### Android VPN/privacy app beaconing to advertising & analytics networks

`UC_107_8` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*graph.facebook.com*" OR All_Traffic.url="*google-analytics.com*" OR All_Traffic.url="*app-measurement.com*" OR All_Traffic.url="*api.appsflyer.com*" OR All_Traffic.url="*app.adjust.com*" OR All_Traffic.url="*api.mixpanel.com*" OR All_Traffic.url="*flurry.com*") by All_Traffic.src All_Traffic.dest All_Traffic.url All_Traffic.app | rename All_Traffic.* as * | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
let TrackerHosts = dynamic(["graph.facebook.com","google-analytics.com","app-measurement.com","api.appsflyer.com","app.adjust.com","api.mixpanel.com","flurry.com","in.appcenter.ms"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (TrackerHosts)
| join kind=inner (DeviceInfo | where OSPlatform =~ "Android" | distinct DeviceId, DeviceName, OSPlatform) on DeviceId
| summarize Trackers=make_set(RemoteUrl), Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName
| order by Hits desc
```

### Endpoint carrying VPN library vulnerable to SWEET32 weak-cipher CVEs (Blowfish / 3DES)

`UC_107_9` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2016-6329","CVE-2016-2183")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), CVEs=make_set(CveId) by DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform
| order by LastSeen desc
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
  - CVE(s): `CVE-2016-6329`, `CVE-2016-2183`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
