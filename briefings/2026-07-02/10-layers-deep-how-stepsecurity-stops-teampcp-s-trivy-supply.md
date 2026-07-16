# [CRIT] 10 Layers Deep: How StepSecurity Stops TeamPCP's Trivy Supply Chain Attack on GitHub Actions

**Source:** StepSecurity
**Published:** 2026-07-02
**Article:** https://www.stepsecurity.io/blog/10-layers-deep-how-stepsecurity-stops-teampcps-trivy-supply-chain-attack-on-github-actions

## Threat Profile

Back to Blog Product 10 Layers Deep: How StepSecurity Stops TeamPCP's Trivy Supply Chain Attack on GitHub Actions TeamPCP weaponized 76 Trivy version tags overnight. The KICS attack followed the same playbook days later. One security control is not enough. Here is how the StepSecurity platform's ten independent security layers work together to prevent credential exfiltration, detect compromised actions at runtime, and respond to incidents across your entire organization before attackers can succ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **IPv4 (defanged):** `45.148.10.212`
- **IPv4 (defanged):** `83.142.209.203`
- **IPv4 (defanged):** `94.154.172.43`
- **Domain (defanged):** `scan.aquasecurtiy.org`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `audit.checkmarx.cx`
- **Domain (defanged):** `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1071.004** — Application Layer Protocol: DNS
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TeamPCP Trivy/KICS supply-chain credential exfil to scan.aquasecurtiy.org & 45.148.10.212

`UC_164_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("45.148.10.212","83.142.209.203","94.154.172.43") OR All_Traffic.dest IN ("scan.aquasecurtiy.org","checkmarx.zone","audit.checkmarx.cx","models.litellm.cloud")) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, All_Traffic.bytes_out
| `drop_dm_object_name("All_Traffic")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("45.148.10.212","83.142.209.203","94.154.172.43")
   or RemoteUrl has_any ("scan.aquasecurtiy.org","checkmarx.zone","audit.checkmarx.cx","models.litellm.cloud")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Credential harvest via /proc/<pid>/mem read of GitHub Actions Runner.Worker

`UC_164_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process has "Runner.Worker" OR Processes.process has "Runner.Worker") AND Processes.process="*/proc/*" AND Processes.process="*mem*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has "Runner.Worker" or InitiatingProcessCommandLine has "Runner.Worker" or ProcessCommandLine has "Runner.Worker"
| where FileName in~ ("python","python3","node","sh","bash","perl","ruby")
| where ProcessCommandLine has "/proc/" and ProcessCommandLine has "mem"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### DNS resolution of TeamPCP typosquat exfil domain scan.aquasecurtiy.org

`UC_164_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("scan.aquasecurtiy.org","checkmarx.zone","audit.checkmarx.cx","models.litellm.cloud","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io") by DNS.src, DNS.query, DNS.answer
| `drop_dm_object_name("DNS")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any ("scan.aquasecurtiy.org","checkmarx.zone","audit.checkmarx.cx","models.litellm.cloud","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### GitHub Actions runner spawns network tool / interpreter under compromised trivy-action or KICS

`UC_164_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process has "Runner.Worker" OR Processes.parent_process="*trivy*" OR Processes.parent_process="*kics*") AND Processes.process_name IN ("curl","wget","python","python3","node","nc","ncat") by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has "Runner.Worker" or InitiatingProcessCommandLine has_any ("trivy","trivy-action","kics")
| where FileName in~ ("curl","wget","python","python3","node","nc","ncat")
| where ProcessCommandLine has_any ("http://","https://","-d ","--data","POST","/proc/","scan.aquasecurtiy")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
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
  - IP / domain IOC(s): `45.148.10.212`, `83.142.209.203`, `94.154.172.43`, `scan.aquasecurtiy.org`, `checkmarx.zone`, `models.litellm.cloud`, `audit.checkmarx.cx`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
