# [CRIT] Behind the Scenes: How StepSecurity Detected and Helped Remediate the Largest npm Supply Chain Attack

**Source:** StepSecurity
**Published:** 2026-04-09
**Article:** https://www.stepsecurity.io/blog/behind-the-scenes-how-stepsecurity-detected-and-helped-remediate-the-largest-npm-supply-chain-attack

## Threat Profile

Back to Blog Product 10 Layers Deep: How StepSecurity Stops TeamPCP's Trivy Supply Chain Attack on GitHub Actions TeamPCP weaponized 76 Trivy version tags overnight. The KICS attack followed the same playbook days later. One security control is not enough. Here is how the StepSecurity platform's ten independent security layers work together to prevent credential exfiltration, detect compromised actions at runtime, and respond to incidents across your entire organization before attackers can succ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **IPv4 (defanged):** `45.148.10.212`
- **Domain (defanged):** `scan.aquasecurtiy.org`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- **Domain (defanged):** `plug-tab-protective-relay.trycloudflare.com`
- **SHA256:** `887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073`
- **SHA256:** `f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d`
- **SHA256:** `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0`
- **SHA256:** `bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7`
- **SHA256:** `e64e152afe2c722d750f10259626f357cdea40420c5eedab37969fbf13abbecf`
- **SHA256:** `ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c`
- **SHA256:** `d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c`
- **SHA256:** `e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1111343`
- **SHA256:** `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538`
- **SHA256:** `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1583.001** — Acquire Infrastructure: Domains (typosquat)
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TeamPCP Trivy/KICS C2 callback to scan.aquasecurtiy.org / 45.148.10.212

`UC_433_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="45.148.10.212" OR All_Traffic.dest_host="scan.aquasecurtiy.org" OR All_Traffic.dest_host="*.aquasecurtiy.org" OR All_Traffic.url="*scan.aquasecurtiy.org*") by All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.action | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution.DNS where DNS.query="*aquasecurtiy.org" by DNS.dest DNS.query | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badIPs = dynamic(["45.148.10.212"]);
let badHosts = dynamic(["scan.aquasecurtiy.org"]);
union isfuzzy=true
( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (badIPs)
        or RemoteUrl has_any (badHosts)
    | project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName ),
( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q endswith "aquasecurtiy.org"
    | project Timestamp, DeviceName, DeviceId, ActionType, Query=Q, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName )
| order by Timestamp desc
```

### Read of /proc/<pid>/mem targeting GitHub Runner.Worker (TeamPCP credential dump)

`UC_433_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="/proc/*/mem" by Filesystem.dest Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "^(gdb|strace|ltrace|crash|perf|makedumpfile|criu|systemd-coredump)$") | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="python*" OR Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="node") AND Processes.process="*/proc/*/mem*" by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender for Endpoint on Linux — read of /proc/<pid>/mem
let legit_debuggers = dynamic(["gdb","strace","ltrace","crash","perf","makedumpfile","criu","systemd-coredump"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName !startswith "WIN"
| where (FolderPath matches regex @"^/proc/[0-9]+$" and FileName =~ "mem")
     or (FolderPath matches regex @"^/proc/[0-9]+/mem$")
     or (FileName =~ "mem" and FolderPath has "/proc/")
| where InitiatingProcessFileName !in~ (legit_debuggers)
| project Timestamp, DeviceName, DeviceId, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("Runner.Worker","/proc/","trivy-action","aquasecurity","kics")
    | project DeviceId, CtxTime=Timestamp, CtxCmd=ProcessCommandLine, CtxFile=FileName
  ) on DeviceId
| order by Timestamp desc
```

### TeamPCP sysmon.py systemd-user persistence on developer host

`UC_433_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user values(Filesystem.action) as action from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.config/systemd/user/sysmon.py" OR Filesystem.file_name="sysmon.py") AND (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=write) by Filesystem.dest Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/.config/systemd/user/*.service" Filesystem.file_path="*sysmon*" by Filesystem.dest Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Creation of sysmon.py under ~/.config/systemd/user/ (TeamPCP persistence)
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"/.config/systemd/user"
| where FileName =~ "sysmon.py"
   or (FileName endswith ".service" and FileName has "sysmon")
| project Timestamp, DeviceName, DeviceId, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("trivy","aquasecurity","setup-trivy")
    | summarize TrivyExecCount=count(), LastTrivyExec=max(Timestamp) by DeviceId
  ) on DeviceId
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
  - IP / domain IOC(s): `45.148.10.212`, `scan.aquasecurtiy.org`, `models.litellm.cloud`, `checkmarx.zone`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`, `plug-tab-protective-relay.trycloudflare.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073`, `f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d`, `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0`, `bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7`, `e64e152afe2c722d750f10259626f357cdea40420c5eedab37969fbf13abbecf`, `ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c`, `d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c`, `e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1111343` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
