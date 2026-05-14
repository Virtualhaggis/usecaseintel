# [HIGH] npm backdoor lets hackers hijack gambling outcomes

**Source:** Aikido
**Published:** 2026-02-16
**Article:** https://www.aikido.dev/blog/npm-backdoor-lets-hackers-hijack-gambling-outcomes

## Threat Profile

Blog Vulnerabilities & Threats npm backdoor lets hackers hijack gambling outcomes npm backdoor lets hackers hijack gambling outcomes Written by Ilyas Makari Published on: Feb 16, 2026 Our malware detection pipelines recently lit up on a small cluster of packages on npm that looked... familiar.
Packages like json-bigint-extend , jsonfx , and jsonfb were mimicking the popular json-bigint library: same functionality, an identical README file, and even an author name uncomfortably close to the origi…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `payment.y1pay.vip`
- **Domain (defanged):** `payment.snip-site.cc`
- **Domain (defanged):** `gameland.21game.live`
- **Domain (defanged):** `gameland.myapptest.top`
- **Domain (defanged):** `gameland.nbzysp1.com`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Egress to sidoraress json-bigint-extend gambling backdoor C2 infrastructure

`UC_400_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods from datamodel=Web.Web where (Web.url="*payment.y1pay.vip*" OR Web.url="*payment.snip-site.cc*" OR Web.url="*gameland.21game.live*" OR Web.url="*gameland.myapptest.top*" OR Web.url="*gameland.nbzysp1.com*" OR Web.dest IN ("payment.y1pay.vip","payment.snip-site.cc","gameland.21game.live","gameland.myapptest.top","gameland.nbzysp1.com")) by Web.src Web.dest Web.user Web.http_user_agent
| `drop_dm_object_name(Web)`
| append [
  | tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("payment.y1pay.vip","payment.snip-site.cc","gameland.21game.live","gameland.myapptest.top","gameland.nbzysp1.com") OR DNS.query="*.y1pay.vip" OR DNS.query="*.snip-site.cc" OR DNS.query="*.21game.live" OR DNS.query="*.myapptest.top" OR DNS.query="*.nbzysp1.com" by DNS.src DNS.query DNS.answer DNS.record_type
  | `drop_dm_object_name(DNS)`
]
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _c2_hosts = dynamic(["payment.y1pay.vip","payment.snip-site.cc","gameland.21game.live","gameland.myapptest.top","gameland.nbzysp1.com"]);
let _c2_paths = dynamic(["/v1/risk/get-risk-code","/v1/risk/log"]);
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > ago(30d)
   | where RemoteUrl has_any (_c2_hosts) or RemoteUrl has_any (_c2_paths)
   | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             InitiatingProcessFolderPath, InitiatingProcessAccountName, InitiatingProcessSHA256),
  (DeviceEvents
   | where Timestamp > ago(30d)
   | where ActionType == "DnsQueryResponse"
   | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
   | where QueryName has_any (_c2_hosts) or QueryName endswith ".y1pay.vip" or QueryName endswith ".snip-site.cc" or QueryName endswith ".21game.live" or QueryName endswith ".myapptest.top" or QueryName endswith ".nbzysp1.com"
   | project Timestamp, DeviceName, ActionType, QueryName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
| order by Timestamp desc
```

### [LLM] Installation of sidoraress malicious npm packages (json-bigint-extend/jsonfb/jsonfx)

`UC_400_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm","node","yarn","pnpm","npx") OR Processes.parent_process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm","node","yarn","pnpm","npx")) (Processes.process="*json-bigint-extend*" OR Processes.process="*jsonfb*" OR Processes.process="*jsonfx*") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _pkg_managers = dynamic(["npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm","node","yarn","pnpm","npx"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (_pkg_managers) or InitiatingProcessFileName in~ (_pkg_managers)
| where (ProcessCommandLine has_any ("jsonfb","jsonfx") or ProcessCommandLine contains "json-bigint-extend")
     or (InitiatingProcessCommandLine has_any ("jsonfb","jsonfx") or InitiatingProcessCommandLine contains "json-bigint-extend")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] Inbound HTTP request bearing sidoraress backdoor x-operation operator tokens

`UC_400_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.http_user_agent) as uas from datamodel=Web.Web where (Web.url="*cfh2DNITa84qpYQ0tdCz*" OR Web.url="*m3QiEkg8Y1r9LFTI5e4f*" OR Web.url="*Y3SrZjVqWOvKsBdpTCh7*" OR Web.url="*SJQf31UJkZ1f88q9m361*" OR Web.http_user_agent="*cfh2DNITa84qpYQ0tdCz*" OR Web.http_user_agent="*m3QiEkg8Y1r9LFTI5e4f*" OR Web.http_user_agent="*Y3SrZjVqWOvKsBdpTCh7*" OR Web.http_user_agent="*SJQf31UJkZ1f88q9m361*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| append [
  search (sourcetype=nginx* OR sourcetype=apache* OR sourcetype=iis* OR sourcetype=*waf* OR sourcetype=*cef* OR tag=web)
    ("cfh2DNITa84qpYQ0tdCz" OR "m3QiEkg8Y1r9LFTI5e4f" OR "Y3SrZjVqWOvKsBdpTCh7" OR "SJQf31UJkZ1f88q9m361")
  | stats count min(_time) as firstTime max(_time) as lastTime by host src sourcetype uri http_method
]
| convert ctime(firstTime) ctime(lastTime)
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

### Article-specific behavioural hunt — npm backdoor lets hackers hijack gambling outcomes

`UC_400_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — npm backdoor lets hackers hijack gambling outcomes ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("express.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("express.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — npm backdoor lets hackers hijack gambling outcomes
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("express.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("express.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `payment.y1pay.vip`, `payment.snip-site.cc`, `gameland.21game.live`, `gameland.myapptest.top`, `gameland.nbzysp1.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
