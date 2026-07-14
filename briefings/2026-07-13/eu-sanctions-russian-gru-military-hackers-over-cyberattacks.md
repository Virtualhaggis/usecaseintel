# [HIGH] EU sanctions Russian GRU military hackers over cyberattacks

**Source:** BleepingComputer
**Published:** 2026-07-13
**Article:** https://www.bleepingcomputer.com/news/security/eu-and-uk-hit-russia-with-first-joint-cyber-sanctions-package/

## Threat Profile

EU sanctions Russian GRU military hackers over cyberattacks 
By Sergiu Gatlan 
July 13, 2026
07:19 AM
0 
The European Union and the United Kingdom jointly sanctioned dozens of Russian individuals and entities and accused Russia of coordinating a network of hacking groups responsible for attacks across Europe.
Today, the Council of the European Union announced sanctions on nine individuals and four entities, including Russian military intelligence (GRU) officers and cybercriminals, while the UK s…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1027** — Obfuscated Files or Information
- **T1485** — Data Destruction
- **T1561.002** — Disk Structure Wipe
- **T1489** — Service Stop
- **T1090** — Proxy
- **T1572** — Protocol Tunneling
- **T1558.003** — Kerberoasting
- **T1558** — Steal or Forge Kerberos Tickets
- **T1550.003** — Pass the Ticket

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sandworm DynoWiper wiper binary execution (KillFiles.NMO campaign hashes)

`UC_41_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6","86596a5c5b05a8bfbd14876de7404702f7d0d61b","69ede7e341fd26fa0577692b601d80cb44778d93") OR Processes.process_name IN ("schtask.exe","schtask2.exe")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA1 in~ ("4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6","86596a5c5b05a8bfbd14876de7404702f7d0d61b","69ede7e341fd26fa0577692b601d80cb44778d93")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Sandworm Rsocx SOCKS5 tunnel C2 to 31.172.71.5

`UC_41_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="31.172.71.5" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "31.172.71.5" or InitiatingProcessSHA1 =~ "9ec4c38394ea2048ca81d48b1bd66de48d8bd4e8"
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessSHA1, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Sandworm post-exploitation Rubeus Kerberos toolkit (campaign hash)

`UC_41_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash="410c8a57fe6e09edbfebaba7d5d3e4797ca80a19" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA1 =~ "410c8a57fe6e09edbfebaba7d5d3e4797ca80a19"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
