# [HIGH] node-ipc npm Package with 822K Weekly Downloads Compromised in Supply Chain Attack

**Source:** Cyber Security News
**Published:** 2026-05-14
**Article:** https://cybersecuritynews.com/node-ipc-npm-package-compromised/

## Threat Profile

Home Cyber Attack News 
node-ipc npm Package with 822K Weekly Downloads Compromised in Supply Chain Attack 
By Guru Baran 
May 14, 2026 
A widely used JavaScript inter-process communication library has been weaponized again. Socket and Stepsecurity have confirmed that three newly published versions of node-ipc, a package with over 822,000 weekly downloads, contain obfuscated stealer and backdoor payloads, marking the second major supply chain compromise of this package since 2022.
The affected v…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.16.75.69`
- **Domain (defanged):** `atlantis-software.net`
- **Domain (defanged):** `sh.azurestaticprovider.net`
- **Domain (defanged):** `bt.node.js`
- **SHA256:** `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`
- **SHA256:** `449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e`
- **SHA256:** `c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea`
- **SHA256:** `78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1567** — Exfiltration Over Web Service
- **T1571** — Non-Standard Port
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node-ipc stealer DNS TXT exfiltration to bt.node.js zone (xh/xd/xf prefixes)

`UC_18_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen dc(Resolution.query) as uniqueQueries values(Resolution.src) as src from datamodel=Network_Resolution.DNS where Resolution.query="*.bt.node.js" OR Resolution.query="xh.*.bt.node.js" OR Resolution.query="xd.*.bt.node.js" OR Resolution.query="xf.*.bt.node.js" OR Resolution.record_type="TXT" Resolution.query="*bt.node.js" by Resolution.src Resolution.query_type span=5m | `drop_dm_object_name(Resolution)` | where count > 50 OR uniqueQueries > 25
```

**Defender KQL:**
```kql
// Defender: catch the DNS TXT burst to bt.node.js (29k queries per 500KiB archive)
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
| where Q endswith ".bt.node.js" or Q == "bt.node.js"
   or Q startswith "xh." or Q startswith "xd." or Q startswith "xf."
   and Q contains "bt.node.js"
| summarize QueryCount = count(),
            DistinctSubdomains = dcount(Q),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleQueries = make_set(Q, 25)
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where QueryCount >= 50 or DistinctSubdomains >= 25   // single archive => ~29,400 queries; 50 is a soft floor
| order by QueryCount desc
```

### [LLM] node-ipc bootstrap C2 contact: sh.azurestaticprovider.net / 37.16.75.69

`UC_18_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.src) as src values(All_Traffic.dest_port) as ports values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="37.16.75.69" OR All_Traffic.dest_ip="37.16.75.69" OR All_Traffic.dest="sh.azurestaticprovider.net" OR All_Traffic.dest_host="sh.azurestaticprovider.net" OR All_Traffic.url="*azurestaticprovider.net*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | append [ | tstats `summariesonly` count from datamodel=Network_Resolution.DNS where Resolution.query="sh.azurestaticprovider.net" OR Resolution.query="*.azurestaticprovider.net" by Resolution.src Resolution.query | `drop_dm_object_name(Resolution)` ]
```

**Defender KQL:**
```kql
// Defender: any device contacting the node-ipc bootstrap C2
let bad_ips = dynamic(["37.16.75.69"]);
let bad_domains = dynamic(["sh.azurestaticprovider.net", "azurestaticprovider.net"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteIP in (bad_ips)
       or RemoteUrl has_any (bad_domains)
    | project Timestamp, DeviceName, DeviceId, ActionType,
              RemoteIP, RemotePort, RemoteUrl, Protocol,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessAccountName ),
  ( DeviceEvents
    | where Timestamp > ago(14d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q endswith "azurestaticprovider.net"
    | project Timestamp, DeviceName, DeviceId, ActionType,
              RemoteIP = tostring(parse_json(AdditionalFields).IPAddresses),
              RemotePort = int(null), RemoteUrl = Q, Protocol = "dns",
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] node-ipc stager archive drop: <tmp>/nt-<pid>/<machineHex>.tar.gz or known-bad node-ipc.cjs SHA256

`UC_18_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Processes.parent_process_name) as parent values(Processes.process) as process values(Filesystem.file_path) as file_path from datamodel=Endpoint where (Filesystem.file_path="*/nt-*/*.tar.gz" OR Filesystem.file_path="*\\nt-*\\*.tar.gz" OR Filesystem.file_hash="96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144" OR Filesystem.file_hash="449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e" OR Filesystem.file_hash="c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea" OR Filesystem.file_hash="78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981" OR Processes.process="*__ntw=1*") by host Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
// Defender: stager tarball drop + known-bad hashes + __ntw=1 fork marker
let bad_hashes = dynamic([
    "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144",  // node-ipc.cjs payload
    "449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e",  // 9.1.6 tgz
    "c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea",  // 9.2.3 tgz
    "78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981"   // 12.0.1 tgz
]);
union isfuzzy=true
  ( DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType == "FileCreated"
    | where SHA256 in (bad_hashes)
       or (FolderPath matches regex @"(?i)[\\/]nt-\d+[\\/]" and FileName endswith ".tar.gz")
       or FileName matches regex @"(?i)^[0-9a-f]{8,}\.tar\.gz$" and FolderPath has "nt-"
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessAccountName ),
  ( DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has "__ntw=1"
       or InitiatingProcessCommandLine has "__ntw=1"
    | where InitiatingProcessFileName has_any ("node", "node.exe", "npm", "yarn", "pnpm")
         or FileName has_any ("node", "node.exe")
    | project Timestamp, DeviceName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, AccountName, SHA256 = "",
              FolderPath, ActionType = "ProcessCreated" )
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.16.75.69`, `atlantis-software.net`, `sh.azurestaticprovider.net`, `bt.node.js`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`, `449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e`, `c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea`, `78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
