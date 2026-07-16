# [HIGH] AsyncAPI npm packages infected with credential-stealing malware

**Source:** BleepingComputer
**Published:** 2026-07-15
**Article:** https://www.bleepingcomputer.com/news/security/-asyncapi-npm-packages-infected-with-credential-stealing-malware/

## Threat Profile

​ ​AsyncAPI npm packages infected with credential-stealing malware 
By Bill Toulas 
July 15, 2026
11:37 AM
0 
Five malicious versions of AsyncAPI packages were published to the Node Package Manager (npm) in a supply-chain attack that delivered a remote access trojan with info-stealing capabilities.
The threat actor exploited a misconfigured GitHub Actions workflow and pushed trojanized packages in the @asyncapi namespace that had a cummulative weekly download count of more than 2.25 million.
Mul…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `85.137.53.71`
- **Domain (defanged):** `relay.damus.io`
- **Domain (defanged):** `relay.nostr.com`
- **Domain (defanged):** `ethereum-rpc.publicnode.com`
- **Domain (defanged):** `router.bittorrent.com`
- **Domain (defanged):** `dht.transmissionbt.com`
- **SHA256:** `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1`
- **SHA256:** `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab`
- **SHA256:** `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4`
- **SHA256:** `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b`
- **SHA256:** `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript
- **T1036.005** — Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1564.003** — Hidden Window
- **T1102** — Web Service
- **T1571** — Non-Standard Port
- **T1102.002** — Bidirectional Communication

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious @asyncapi package versions installed via npm/node (AsyncAPI supply-chain)

`UC_10_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","node.exe","npm","node","yarn.exe","pnpm.exe","npx.exe")) (Processes.process="*@asyncapi/generator@3.3.1*" OR Processes.process="*@asyncapi/generator-helpers@1.1.1*" OR Processes.process="*@asyncapi/generator-components@0.7.1*" OR Processes.process="*@asyncapi/specs@6.11.2*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","npm.exe","npx.exe","yarn.exe","pnpm.exe","cmd.exe","powershell.exe","bash.exe","sh","node")
| where ProcessCommandLine has_any ("@asyncapi/generator@3.3.1","@asyncapi/generator-helpers@1.1.1","@asyncapi/generator-components@0.7.1","@asyncapi/specs@6.11.2","@asyncapi/specs@6.11.2-alpha.1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Miasma sync.js payload dropped to masqueraded NodeJS app-data folder

`UC_10_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="sync.js" (Endpoint.Filesystem.file_path="*\\NodeJS\\sync.js" OR Endpoint.Filesystem.file_path="*/NodeJS/sync.js" OR Endpoint.Filesystem.file_path="*/.config/node/sync.js") by Endpoint.Filesystem.dest Endpoint.Filesystem.user Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name Endpoint.Filesystem.process_name | `drop_dm_object_name(Endpoint.Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "sync.js"
| where FolderPath has @"\NodeJS\" or FolderPath has "/NodeJS/" or FolderPath endswith "/.config/node/sync.js"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Node.js executing the hidden Miasma sync.js loader

`UC_10_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("node.exe","node")) (Processes.process="*\\NodeJS\\sync.js*" OR Processes.process="*/NodeJS/sync.js*" OR Processes.process="*/.config/node/sync.js*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine has_any (@"NodeJS\sync.js","NodeJS/sync.js","node/sync.js")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Miasma multi-channel C2 egress (85.137.53.71, Nostr, BitTorrent DHT, Ethereum RPC)

`UC_10_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="85.137.53.71" AND All_Traffic.dest_port IN (8080,8081,8091)) OR All_Traffic.dest IN ("relay.damus.io","relay.nostr.com","ethereum-rpc.publicnode.com","router.bittorrent.com","dht.transmissionbt.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteIP == "85.137.53.71" and RemotePort in (8080,8081,8091))
     or (RemoteUrl has_any ("relay.damus.io","relay.nostr.com","ethereum-rpc.publicnode.com","router.bittorrent.com","dht.transmissionbt.com") and InitiatingProcessFileName in~ ("node.exe","node"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### Node.js retrieving Miasma second stage from IPFS (ipfs.io + campaign CIDs)

`UC_10_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="ipfs.io" AND All_Traffic.process_name IN ("node.exe","node")) OR All_Traffic.url="*QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9*" OR All_Traffic.url="*Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf*" by All_Traffic.src All_Traffic.dest All_Traffic.url All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9","Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf")
     or (RemoteUrl has "ipfs.io" and InitiatingProcessFileName in~ ("node.exe","node"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
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
  - IP / domain IOC(s): `85.137.53.71`, `relay.damus.io`, `relay.nostr.com`, `ethereum-rpc.publicnode.com`, `router.bittorrent.com`, `dht.transmissionbt.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1`, `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab`, `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4`, `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b`, `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
