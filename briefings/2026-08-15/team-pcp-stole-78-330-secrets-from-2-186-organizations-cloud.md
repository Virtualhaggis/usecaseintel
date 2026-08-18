# [CRIT] Team PCP Stole 78,330 Secrets From 2,186 Organizations. CloudSEK Just Published the List.

**Source:** StepSecurity
**Published:** 2026-08-15
**Article:** https://www.stepsecurity.io/blog/teampcp-supply-chain-attack-cicd-secrets-cloudsek-disclosure

## Threat Profile

Back to Blog Threat Intel Team PCP Stole 78,330 Secrets From 2,186 Organizations. CloudSEK Just Published the List. CloudSEK has published the victim list from Team PCP's supply chain campaign: 78,330 secrets exfiltrated from the CI/CD pipelines of 2,186 organizations over five days in March 2026. StepSecurity's research team has tracked this threat actor across the Trivy, telnyx, and LiteLLM compromises. Here is how the campaign works, why CI/CD pipelines are the target, and the layered control…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **IPv4 (defanged):** `83.142.209.203`
- **SHA256:** `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9`
- **SHA256:** `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TeamPCP CI/CD credential-stealer C2 egress to 83.142.209.203 / checkmarx.zone

`UC_35_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.203" OR All_Traffic.dest="83.142.209.11") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.user
| `drop_dm_object_name("All_Traffic")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("83.142.209.203","83.142.209.11")
    or RemoteUrl has_any ("checkmarx.zone","models.litellm.cloud")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### TeamPCP Cloud Stealer reading CI runner process memory via /proc/<pid>/mem

`UC_35_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*/proc/*" AND Processes.process="*mem*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| where match(process,"/proc/\d+/mem") OR like(process,"%Runner.Worker%") OR like(process,"%TeamPCP%") OR like(process,"%entrypoint.sh%")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "/proc/" and ProcessCommandLine has "mem"
| where ProcessCommandLine matches regex @"/proc/[0-9]+/mem"
     or ProcessCommandLine has_any ("Runner.Worker","TeamPCP","entrypoint.sh")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Install of TeamPCP-backdoored PyPI packages (litellm 1.82.7/1.82.8, telnyx 4.87.1/4.87.2)

`UC_35_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*litellm==1.82.7*","*litellm==1.82.8*","*litellm-1.82.7*","*litellm-1.82.8*","*telnyx==4.87.1*","*telnyx==4.87.2*","*telnyx-4.87.1*","*telnyx-4.87.2*") by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("litellm==1.82.7","litellm==1.82.8","litellm-1.82.7","litellm-1.82.8","telnyx==4.87.1","telnyx==4.87.2","telnyx-4.87.1","telnyx-4.87.2")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Stolen credentials reused from TeamPCP C2 IP in AWS CloudTrail

`UC_35_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype="aws:cloudtrail" (sourceIPAddress="83.142.209.203" OR sourceIPAddress="83.142.209.11")
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as eventNames values(errorCode) as errors by userIdentity.arn, userIdentity.accessKeyId, sourceIPAddress, awsRegion
| convert ctime(firstTime) ctime(lastTime)
```

### Execution/write of known TeamPCP stealer binary by SHA256

`UC_35_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash="7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9" OR Processes.process_hash="cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3" by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_hash
| `drop_dm_object_name("Processes")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceProcessEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, AccountName, ActionKind="ProcessExec", FileName, FolderPath, SHA256, InitiatingProcessSHA256 ),
( DeviceFileEvents | where Timestamp > ago(30d) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ActionKind="FileWrite", FileName, FolderPath, SHA256, InitiatingProcessSHA256 )
| where SHA256 in ("7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9","cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3")
    or InitiatingProcessSHA256 in ("7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9","cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3")
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
  - IP / domain IOC(s): `83.142.209.203`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9`, `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
