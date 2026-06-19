# [HIGH] 145 Mastra npm Packages Compromised via Hijacked Contributor Account

**Source:** The Hacker News, Aikido
**Published:** 2026-06-17
**Article:** https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html

## Threat Profile

Blog Vulnerabilities & Threats Over 140 popular Mastra npm Packages Hit by Supply Chain Attack Over 140 popular Mastra npm Packages Hit by Supply Chain Attack Written by Ilyas Makari Published on: Jun 17, 2026 On June 17th we detected a large-scale supply chain attack targeting the entire @mastra npm scope, a popular open-source AI agent framework. An attacker republished 141 packages in a burst between 01:15 and 02:00 UTC, silently injecting a malicious dependency into every one of them. The af…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `https://23.254.164.92:8000/update/49890878`
- **Domain (defanged):** `https://23.254.164.123:443/49890878`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1041** — Exfiltration Over C2 Channel
- **T1564.003** — Hidden Window
- **T1199** — Trusted Relationship
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### easy-day-js postinstall hook running node setup.cjs --no-warnings

`UC_85_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name=node.exe OR Processes.process_name=node) Processes.process="*setup.cjs*" Processes.process="*--no-warnings*" by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | where parent IN ("npm.exe","npm-cli.js","node.exe","npx.exe","yarn.exe","pnpm.exe","cmd.exe","bash","sh") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine has "setup.cjs" and ProcessCommandLine has "--no-warnings"
| where InitiatingProcessFileName in~ ("npm.exe","npm","npm-cli.js","npx.exe","npx","node.exe","yarn.exe","pnpm.exe","cmd.exe","bash","sh")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Outbound HTTPS to Mastra supply-chain C2 23.254.164.92:8000 and 23.254.164.123:443

`UC_85_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("23.254.164.92","23.254.164.123")) (All_Traffic.dest_port IN (8000,443)) by All_Traffic.src All_Traffic.user All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badIPs = dynamic(["23.254.164.92","23.254.164.123"]);
let badDomains = dynamic(["hwsrv-1327786.hostwindsdns.com","hwsrv-1327785.hostwindsdns.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (badIPs)
   or RemoteUrl has_any (badDomains)
   or RemoteUrl has "/update/49890878"
| extend Stage = case(RemoteIP == "23.254.164.92" or RemoteUrl has "hwsrv-1327786", "Stage1-Download",
                     RemoteIP == "23.254.164.123" or RemoteUrl has "hwsrv-1327785", "Stage2-Exfil", "Unknown")
| project Timestamp, DeviceName, Stage, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Node spawning detached script from %TEMP% with 24-hex filename and host:port argv (stage-2)

`UC_85_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name=node.exe OR Processes.process_name=node) by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)(?:[\\\/]Temp[\\\/]|AppData[\\\/]Local[\\\/]Temp[\\\/]|\/tmp\/)[a-f0-9]{24}\.js\s+\S+:\d{2,5}" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine matches regex @"(?i)(?:\\Temp\\|AppData\\Local\\Temp\\|/tmp/)[a-f0-9]{24}\.js\s+\S+:\d{2,5}"
| extend Stage2Target = extract(@"([a-zA-Z0-9\.\-]+:\d{2,5})\s*$", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Stage2Target, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### npm install referencing compromised @mastra packages or easy-day-js dependency

`UC_85_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe","node.exe")) by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | search cmdline="*easy-day-js*" OR cmdline="*@mastra/core*" OR cmdline="*@mastra/deployer*" OR cmdline="*@mastra/server*" OR cmdline="*@mastra/memory*" OR cmdline="*@mastra/schema-compat*" OR cmdline="*@mastra/mcp*" OR cmdline="*@mastra/pg*" OR cmdline="*@mastra/libsql*" OR cmdline="*@mastra/evals*" OR cmdline="*@mastra/datadog*" OR cmdline="*@mastra/rag*" OR cmdline="*@mastra/deployer-vercel*" OR cmdline="*@mastra/redis*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let compromised = dynamic(["easy-day-js","@mastra/schema-compat","@mastra/core","@mastra/memory","@mastra/server","@mastra/deployer","@mastra/pg","@mastra/mcp","@mastra/libsql","@mastra/evals","@mastra/datadog","@mastra/rag","@mastra/deployer-vercel","@mastra/redis"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe","node.exe") or InitiatingProcessFileName in~ ("npm.exe","npm","npx.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has_any (compromised) or InitiatingProcessCommandLine has_any (compromised)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Mastra dropper beacon file .pkg_history/.pkg_logs created by node in temp directory

`UC_85_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN (".pkg_history",".pkg_logs")) Filesystem.action=created by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | search path="*\\Temp\\*" OR path="*/tmp/*" OR path="*AppData\\Local\\Temp*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName in~ (".pkg_history",".pkg_logs")
| where FolderPath has_any (@"\Temp\", "/tmp/", @"AppData\Local\Temp")
| where InitiatingProcessFileName in~ ("node.exe","node")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### node.exe reading developer credential files shortly after npm install (Mastra stage-2)

`UC_85_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.process_name=node.exe (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.config\\gh\\hosts.yml*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*\\.ssh\\id_rsa*" OR Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*Runner.Worker*secret*" OR Filesystem.file_path="*_temp\\_runner_file_commands*") by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredentialReads = DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where (FolderPath has @"\.aws\" and FileName == "credentials")
    or (FolderPath has "/.aws/" and FileName == "credentials")
    or (FolderPath has @"\.config\gh\" and FileName == "hosts.yml")
    or (FolderPath has "/.config/gh/" and FileName == "hosts.yml")
    or (FolderPath has @"\.ssh\" and FileName matches regex @"^id_(rsa|ed25519|ecdsa)$")
    or (FolderPath has "Runner.Worker" and FolderPath has "_temp")
    or FileName =~ ".npmrc";
let RecentNpmInstall = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "npm" and ProcessCommandLine has "install"
| project NpmTime = Timestamp, DeviceId, NpmUser = AccountName;
CredentialReads
| join kind=inner RecentNpmInstall on DeviceId
| where Timestamp between (NpmTime .. NpmTime + 10m)
| project Timestamp, DeviceName, NpmTime, DelaySec = datetime_diff('second', Timestamp, NpmTime), InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.254.164.92`, `23.254.164.123`, `https://23.254.164.92:8000/update/49890878`, `https://23.254.164.123:443/49890878`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
