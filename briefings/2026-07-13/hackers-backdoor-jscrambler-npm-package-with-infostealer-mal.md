# [HIGH] Hackers backdoor Jscrambler npm package with infostealer malware

**Source:** BleepingComputer
**Published:** 2026-07-13
**Article:** https://www.bleepingcomputer.com/news/security/hackers-backdoor-jscrambler-npm-package-with-infostealer-malware/

## Threat Profile

Hackers backdoor Jscrambler npm package with infostealer malware 
By Bill Toulas 
July 13, 2026
03:44 PM
0 
The Jscrambler client-side web security company disclosed that a threat actor published a malicious version of its npm package that has been downloaded almost 1,500 times.
The malicious Jscrambler package spanned releases 8.14, 8.16, 8.17, and 8.20 and included information-stealing malware that executed during the ‘preinstall’ hook.
“Today, we identified the unauthorized publication of a m…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.27.122.124`
- **IPv4 (defanged):** `57.128.246.79`
- **Domain (defanged):** `temp.sh`
- **SHA256:** `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`
- **SHA256:** `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`
- **SHA256:** `bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0`
- **SHA256:** `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
- **SHA256:** `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
- **SHA256:** `c8fd47d36bdf7c825378593ab82ef8c24d1dc52e26b507812393e24e1d5201fd`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript
- **T1036.005** — Match Legitimate Name or Location
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1204.003** — Malicious Image

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Jscrambler npm preinstall hook (setup.js) drops & executes native binary from temp dir

`UC_24_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=node.exe (Processes.process_path="*\\Temp\\*" OR Processes.process_path="*/tmp/*" OR Processes.process_path="*/var/folders/*") (Processes.parent_process="*setup.js*" OR Processes.parent_process="*intro.js*" OR Processes.parent_process="*preinstall*" OR Processes.parent_process="*jscrambler*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has_any ("setup.js","intro.js","preinstall","jscrambler")
| where FolderPath contains @"\Temp\" or FolderPath contains "/tmp/" or FolderPath contains "/var/folders/"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Jscrambler infostealer C2 egress to 37.27.122.124 / 57.128.246.79 / temp.sh

`UC_24_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="37.27.122.124" OR All_Traffic.dest_ip="57.128.246.79") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("37.27.122.124","57.128.246.79") or RemoteUrl has "temp.sh"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Jscrambler IronWorm infostealer known-bad SHA256 present on endpoint

`UC_24_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash="a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60" OR Processes.process_hash="a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86" OR Processes.process_hash="bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0" OR Processes.process_hash="fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd" OR Processes.process_hash="b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903" OR Processes.process_hash="c8fd47d36bdf7c825378593ab82ef8c24d1dc52e26b507812393e24e1d5201fd") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let hashes = dynamic(["a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60","a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86","bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0","fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd","b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903","c8fd47d36bdf7c825378593ab82ef8c24d1dc52e26b507812393e24e1d5201fd"]);
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 in (hashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.27.122.124`, `57.128.246.79`, `temp.sh`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`, `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`, `bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0`, `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`, `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`, `c8fd47d36bdf7c825378593ab82ef8c24d1dc52e26b507812393e24e1d5201fd`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
