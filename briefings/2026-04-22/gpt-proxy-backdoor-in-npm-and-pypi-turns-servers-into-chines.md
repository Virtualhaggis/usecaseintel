# [HIGH] GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays

**Source:** Aikido
**Published:** 2026-04-22
**Article:** https://www.aikido.dev/blog/gpt-proxy-backdoor-npm-pypi-chinese-llm-relay

## Threat Profile

Blog Vulnerabilities & Threats GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays Written by Ilyas Makari Published on: Apr 22, 2026 We recently observed two malicious packages across npm ( kube-health-tools ) and PyPI ( kube-node-health ) that appear designed to target Kubernetes environments. Both packages are innocuous on the surface, using names that reference Kubernetes to appear legitimate. But u…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sync.geeker.indevs.in`
- **SHA256:** `b3405b8456f4e82f192cdff6fdd5b290a58fafda01fbc08174105b922bd7b3cf`
- **SHA256:** `5d58ce3119c37f2bd552f4d883a4f4896dfcb8fb04875f844f999497e4ca846d`
- **SHA256:** `fb3ae78d09c119ec335c3b99a95c97d9bb6f92fd2c7c9b0d3e875347e2f25bb2`
- **SHA256:** `3a3d8f8636fa1db21871005a49ecd7fa59688fa763622fa737ce6b899558b300`
- **MD5:** `e5c2b988f369d9e51f30985eb8c1c5ae`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1572** — Protocol Tunneling
- **T1036.004** — Masquerading: Masquerade Task or Service
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1070.004** — Indicator Removal: File Deletion
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GPT-Proxy backdoor C2 / Stage-2 download (sync.geeker.indevs.in, gibunxi4201/kube-node-diag)

`UC_251_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as resolver from datamodel=Network_Resolution.DNS where (DNS.query="sync.geeker.indevs.in" OR DNS.query="*.geeker.indevs.in") by DNS.query | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user from datamodel=Web.Web where (Web.url="*github.com/gibunxi4201/kube-node-diag*" OR Web.url="*kube-diag-linux-amd64-packed*" OR Web.url="*kube-diag-full-linux-amd64-packed*" OR Web.dest="sync.geeker.indevs.in") by Web.url, Web.dest | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender for Endpoint on Linux
let c2_host = "sync.geeker.indevs.in";
let stage2_path = "gibunxi4201/kube-node-diag";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has c2_host
    or RemoteUrl has stage2_path
    or RemoteUrl has "kube-diag-linux-amd64-packed"
    or RemoteUrl has "kube-diag-full-linux-amd64-packed"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] Stage-2 implant masquerading as node-health-check daemon (/tmp/.kh, /tmp/.ns)

`UC_251_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where ( Processes.process_path IN ("*/tmp/.kh*","*/tmp/.ns*") OR Processes.process_name IN ("kube-diag-linux-amd64-packed","kube-diag-full-linux-amd64-packed") OR (Processes.process="*node-health-check*" AND Processes.process="*--mode=daemon*") OR Processes.process_hash IN ("b3405b8456f4e82f192cdff6fdd5b290a58fafda01fbc08174105b922bd7b3cf","5d58ce3119c37f2bd552f4d883a4f4896dfcb8fb04875f844f999497e4ca846d","fb3ae78d09c119ec335c3b99a95c97d9bb6f92fd2c7c9b0d3e875347e2f25bb2","3a3d8f8636fa1db21871005a49ecd7fa59688fa763622fa737ce6b899558b300") ) by Processes.dest, Processes.user, Processes.process_name, Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let known_hashes = dynamic(["b3405b8456f4e82f192cdff6fdd5b290a58fafda01fbc08174105b922bd7b3cf","5d58ce3119c37f2bd552f4d883a4f4896dfcb8fb04875f844f999497e4ca846d","fb3ae78d09c119ec335c3b99a95c97d9bb6f92fd2c7c9b0d3e875347e2f25bb2","3a3d8f8636fa1db21871005a49ecd7fa59688fa763622fa737ce6b899558b300"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/tmp/.kh"
    or FolderPath startswith "/tmp/.ns"
    or InitiatingProcessFolderPath startswith "/tmp/.kh"
    or InitiatingProcessFolderPath startswith "/tmp/.ns"
    or FileName in ("kube-diag-linux-amd64-packed","kube-diag-full-linux-amd64-packed")
    or (ProcessCommandLine has "node-health-check" and ProcessCommandLine has "--mode=daemon")
    or SHA256 in (known_hashes)
    or InitiatingProcessSHA256 in (known_hashes)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] npm/PyPI dropper self-cleanup: find rm -rf of kube-health-tools in node_modules

`UC_251_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="find" AND (Processes.process="*kube-health-tools*" OR Processes.process="*kube-node-health*") AND Processes.process="*/node_modules/*" AND Processes.process="*rm -rf*" by Processes.dest, Processes.user, Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "find"
| where ProcessCommandLine has_any ("kube-health-tools","kube-node-health")
| where ProcessCommandLine has "node_modules"
| where ProcessCommandLine has "rm -rf" or ProcessCommandLine has "-exec rm"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
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

### Article-specific behavioural hunt — GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays

`UC_251_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.kh*" OR Filesystem.file_path="*/tmp/.ns*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — GPT-Proxy Backdoor in npm and PyPI turns Servers into Chinese LLM Relays
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.kh", "/tmp/.ns", "/dev/null") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sync.geeker.indevs.in`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b3405b8456f4e82f192cdff6fdd5b290a58fafda01fbc08174105b922bd7b3cf`, `5d58ce3119c37f2bd552f4d883a4f4896dfcb8fb04875f844f999497e4ca846d`, `fb3ae78d09c119ec335c3b99a95c97d9bb6f92fd2c7c9b0d3e875347e2f25bb2`, `3a3d8f8636fa1db21871005a49ecd7fa59688fa763622fa737ce6b899558b300`, `e5c2b988f369d9e51f30985eb8c1c5ae`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
