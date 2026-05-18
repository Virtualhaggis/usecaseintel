# [CRIT] bittensor-wallet 4.0.2 Compromised on PyPI - Backdoor Exfiltrates Private Keys

**Source:** StepSecurity
**Published:** 2026-03-26
**Article:** https://www.stepsecurity.io/blog/bittensor-wallet-4-0-2-compromised-on-pypi---backdoor-exfiltrates-private-keys

## Threat Profile

Back to Blog Threat Intel bittensor-wallet 4.0.2 Compromised on PyPI - Backdoor Exfiltrates Private Keys On March 17, 2026, bittensor-wallet 4.0.2 was identified as a compromised PyPI package. The malicious release had been live on PyPI for approximately 48 hours before being yanked. This post is a ground-up technical breakdown based on a direct diff of the source tarballs for versions 4.0.1 and 4.0.2 — covering exactly what changed, how the backdoor works, and what defenders should do. We also …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `finney.opentensor-metrics.com`
- **Domain (defanged):** `finney.subtensor-telemetry.com`
- **Domain (defanged):** `finney.metagraph-stats.com`
- **Domain (defanged):** `opentensor-cdn.com`
- **Domain (defanged):** `tuwyqibtvy.opentensor-cdn.com`
- **Domain (defanged):** `yccansiwfr.opentensor-cdn.com`
- **Domain (defanged):** `tbqcbkpbhy.opentensor-cdn.com`
- **Domain (defanged):** `t.opentensor-cdn.com`
- **SHA256:** `6a416b72ff24804abc12484a3b41413a8580acedd8a5f8c84224fcf0732c2f8e`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **T1567** — Exfiltration Over Web Service
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] bittensor-wallet 4.0.2 backdoor C2 domain contact (opentensor-* lookalikes)

`UC_326_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query="*opentensor-metrics.com" OR DNS.query="*subtensor-telemetry.com" OR DNS.query="*metagraph-stats.com" OR DNS.query="*opentensor-cdn.com") by DNS.src DNS.dest DNS.query host | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count from datamodel=Network_Traffic where (All_Traffic.dest="*opentensor-metrics.com" OR All_Traffic.dest="*subtensor-telemetry.com" OR All_Traffic.dest="*metagraph-stats.com" OR All_Traffic.dest="*opentensor-cdn.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["opentensor-metrics.com","subtensor-telemetry.com","metagraph-stats.com","opentensor-cdn.com"]);
union isfuzzy=true
(DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where isnotempty(RemoteUrl) and RemoteUrl has_any (_c2_domains)
  | project Timestamp, DeviceName, EvtSource="NetConn", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Indicator=RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType == "DnsQueryResponse"
  | extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
  | where isnotempty(QueryName) and QueryName has_any (_c2_domains)
  | project Timestamp, DeviceName, EvtSource="DNS", InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Indicator=QueryName, RemoteIP="", RemotePort=int(0))
| order by Timestamp desc
```

### [LLM] DNS tunneling exfiltration pattern to *.t.opentensor-cdn.com (hex chunk/index/total/session)

`UC_326_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution where DNS.query="*.t.opentensor-cdn.com" by DNS.src DNS.query host _time | `drop_dm_object_name(DNS)` | rex field=query "^(?<hex_chunk>[0-9a-f]{40,})\.(?<idx>\d+)\.(?<total>\d+)\.(?<session>\d+)\.t\.opentensor-cdn\.com$" | where isnotnull(hex_chunk) | stats count as chunk_count min(_time) as firstTime max(_time) as lastTime dc(session) as session_count values(session) as sessions values(total) as expected_total values(query) as sample_queries by src host | where chunk_count >= 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
| where QueryName endswith ".t.opentensor-cdn.com"
| where QueryName matches regex @"^[0-9a-f]{40,}\.[0-9]+\.[0-9]+\.[0-9]+\.t\.opentensor-cdn\.com$"
| extend SessionId = extract(@"\.([0-9]+)\.t\.opentensor-cdn\.com$", 1, QueryName)
| extend ChunkTotal = extract(@"\.([0-9]+)\.[0-9]+\.t\.opentensor-cdn\.com$", 1, QueryName)
| summarize ChunkCount = count(),
            Sessions = make_set(SessionId, 10),
            ExpectedTotal = make_set(ChunkTotal, 5),
            SampleQueries = make_set(QueryName, 5),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| where ChunkCount >= 3
| order by LastSeen desc
```

### [LLM] Compromised bittensor-wallet 4.0.2 source-tarball SHA256 on disk

`UC_326_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="6a416b72ff24804abc12484a3b41413a8580acedd8a5f8c84224fcf0732c2f8e" OR Filesystem.file_hash="edc2588d5e272835285e4171dd3daf862149f617015bf52e43d433d8e5c297c5") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.user host | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_hash="6a416b72ff24804abc12484a3b41413a8580acedd8a5f8c84224fcf0732c2f8e" OR Processes.process_hash="edc2588d5e272835285e4171dd3daf862149f617015bf52e43d433d8e5c297c5") by Processes.dest Processes.process Processes.process_hash Processes.user | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
let _bad_hashes = dynamic([
  "6a416b72ff24804abc12484a3b41413a8580acedd8a5f8c84224fcf0732c2f8e",
  "edc2588d5e272835285e4171dd3daf862149f617015bf52e43d433d8e5c297c5"]);
union isfuzzy=true
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (_bad_hashes)
  | project Timestamp, DeviceName, Source="FileEvent", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (_bad_hashes) or InitiatingProcessSHA256 in (_bad_hashes)
  | project Timestamp, DeviceName, Source="ProcessEvent", ActionType="ProcessCreated", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName)
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Article-specific behavioural hunt — bittensor-wallet 4.0.2 Compromised on PyPI - Backdoor Exfiltrates Private Keys

`UC_326_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — bittensor-wallet 4.0.2 Compromised on PyPI - Backdoor Exfiltrates Private Keys ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("setup.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — bittensor-wallet 4.0.2 Compromised on PyPI - Backdoor Exfiltrates Private Keys
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("setup.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `finney.opentensor-metrics.com`, `finney.subtensor-telemetry.com`, `finney.metagraph-stats.com`, `opentensor-cdn.com`, `tuwyqibtvy.opentensor-cdn.com`, `yccansiwfr.opentensor-cdn.com`, `tbqcbkpbhy.opentensor-cdn.com`, `t.opentensor-cdn.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6a416b72ff24804abc12484a3b41413a8580acedd8a5f8c84224fcf0732c2f8e`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
