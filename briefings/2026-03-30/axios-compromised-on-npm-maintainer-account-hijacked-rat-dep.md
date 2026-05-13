# [HIGH] axios compromised on npm: maintainer account hijacked, RAT deployed

**Source:** Aikido
**Published:** 2026-03-30
**Article:** https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat

## Threat Profile

Blog Vulnerabilities & Threats axios compromised on npm: maintainer account hijacked, RAT deployed axios compromised on npm: maintainer account hijacked, RAT deployed Written by Madeline Lawrence Published on: Mar 30, 2026 Key takeaways The npm account of the lead axios maintainer was hijacked. Two malicious versions were published: axios@1.14.1 and axios@0.30.4 . npm has since removed both.
Anyone who installed either version before the takedown should assume their system is compromised. The ma…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.206.73`
- **Domain (defanged):** `sfrclak.com`
- **SHA256:** `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`
- **SHA256:** `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`
- **SHA256:** `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`
- **SHA1:** `2553649f2322049666871cea80a5d0d6adc700ca`
- **SHA1:** `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
- **SHA1:** `07d889e2dadce6f3910dcbc253317d28ca61c766`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1218** — System Binary Proxy Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] axios npm RAT C2 beacon to sfrclak.com / 142.11.206.73:8000

`UC_298_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="142.11.206.73" OR All_Traffic.url="*sfrclak.com*" by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.url
| `drop_dm_object_name(All_Traffic)`
| append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="sfrclak.com" OR DNS.query="*.sfrclak.com" OR DNS.answer="142.11.206.73" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` ]
| eval indicator=coalesce(dest, query)
| stats min(firstTime) as firstTime max(lastTime) as lastTime sum(count) as count values(src) as src values(user) as user values(app) as app values(url) as url values(query) as dns_query values(answer) as dns_answer by indicator
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badIp = "142.11.206.73";
let badDomain = "sfrclak.com";
let badUrl = "sfrclak.com:8000/6202033";
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteIP == badIp or RemoteUrl has badDomain or RemoteUrl has badUrl
 | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, ReportId),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "DnsQueryResponse"
 | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
 | where QueryName has badDomain
 | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, QueryName, ReportId)
| order by Timestamp desc
```

### [LLM] axios RAT artifact dropped: com.apple.act.mond / wt.exe / ld.py with known SHA256

`UC_298_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a","617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101","fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf")) OR (Filesystem.file_path="*/Library/Caches/com.apple.act.mond") OR (Filesystem.file_path="*\\ProgramData\\wt.exe") OR (Filesystem.file_path="/tmp/ld.py") OR (Filesystem.file_path="*\\Temp\\6202033.vbs") OR (Filesystem.file_path="*\\Temp\\6202033.ps1") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badHashes = dynamic([
  "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
  "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
  "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where SHA256 in (badHashes)
  or (FileName =~ "com.apple.act.mond" and FolderPath has @"/Library/Caches/")
  or (FileName =~ "wt.exe" and FolderPath startswith @"C:\ProgramData")
  or (FileName =~ "ld.py" and FolderPath =~ "/tmp/")
  or (FileName in~ ("6202033.vbs","6202033.ps1") and FolderPath has @"\Temp\")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] PowerShell copy masqueraded as Windows Terminal in %PROGRAMDATA% running 6202033.ps1

`UC_298_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path="*\\ProgramData\\wt.exe" OR Processes.parent_process_path="*\\ProgramData\\wt.exe") OR (Processes.process_name IN ("wscript.exe","cscript.exe") AND (Processes.process="*6202033.vbs*" OR Processes.process="*\\Temp\\6202033*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe","wt.exe") AND Processes.process="*6202033.ps1*") OR (Processes.parent_process_name IN ("node.exe","npm.cmd","npm.exe","npx.cmd") AND Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe","cmd.exe") AND (Processes.process="*6202033*" OR Processes.process="*plain-crypto-js*" OR Processes.process="*sfrclak*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.parent_process Processes.process_name Processes.process_path Processes.process Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath startswith @"C:\ProgramData" and FileName =~ "wt.exe")
   or (InitiatingProcessFolderPath startswith @"C:\ProgramData" and InitiatingProcessFileName =~ "wt.exe")
   or (FileName in~ ("wscript.exe","cscript.exe") and ProcessCommandLine has "6202033")
   or (FileName in~ ("powershell.exe","pwsh.exe","wt.exe") and ProcessCommandLine has "6202033.ps1")
   or (InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","npx.cmd") and FileName in~ ("wscript.exe","cscript.exe","powershell.exe","cmd.exe") and (ProcessCommandLine has_any ("6202033","plain-crypto-js","sfrclak") or InitiatingProcessCommandLine has_any ("plain-crypto-js","setup.js")))
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentPath = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildFile = FileName,
          ChildPath = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256
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

### Article-specific behavioural hunt — axios compromised on npm: maintainer account hijacked, RAT deployed

`UC_298_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — axios compromised on npm: maintainer account hijacked, RAT deployed ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.js","wt.exe","6202033.vbs","6202033.ps1","safe-chain.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/Library/Caches/com.apple.act.mond*" OR Filesystem.file_path="*/tmp/ld.py*" OR Filesystem.file_name IN ("setup.js","wt.exe","6202033.vbs","6202033.ps1","safe-chain.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — axios compromised on npm: maintainer account hijacked, RAT deployed
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.js", "wt.exe", "6202033.vbs", "6202033.ps1", "safe-chain.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null", "/Library/Caches/com.apple.act.mond", "/tmp/ld.py") or FileName in~ ("setup.js", "wt.exe", "6202033.vbs", "6202033.ps1", "safe-chain.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.206.73`, `sfrclak.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`, `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`, `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`, `2553649f2322049666871cea80a5d0d6adc700ca`, `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`, `07d889e2dadce6f3910dcbc253317d28ca61c766`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
