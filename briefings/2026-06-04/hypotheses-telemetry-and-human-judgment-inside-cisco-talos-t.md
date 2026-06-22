# [HIGH] Hypotheses, telemetry, and human judgment: Inside Cisco Talos Threat Hunting

**Source:** Cisco Talos
**Published:** 2026-06-04
**Article:** https://blog.talosintelligence.com/hypotheses-telemetry-and-human-judgment-inside-cisco-talos-threat-hunting/

## Threat Profile

Hypotheses, telemetry, and human judgment: Inside Cisco Talos Threat Hunting 
By 
Cisco Talos 
Thursday, June 4, 2026 08:05
Headlines
By Ron Scott-Adams 
Most security tools operate on a simple principle: If a known-bad pattern appears, fire an alert. This works well enough for many threats, but it fails against adversaries who closely study detection thresholds and deliberately stay under them. 
Cisco Talos Threat Hunting  operates on a different principle. Instead of waiting until we’re sure w…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `144.31.221.82`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### KongTuke TDS C2 callout to 144.31.221.82:6060 with /capcha URL path

`UC_210_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.url) as urls values(All_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="144.31.221.82" AND All_Traffic.dest_port=6060) OR (All_Traffic.url="*/capcha9856*" OR All_Traffic.url="*/capcha*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.user host
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "144.31.221.82"
   or (RemotePort == 6060 and RemoteUrl has "/capcha")
   or RemoteUrl has "/capcha9856"
| project Timestamp, DeviceName, DeviceId, AccountName=InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, Protocol,
          ParentImage=InitiatingProcessParentFileName, ReportId
| order by Timestamp desc
```

### PowerShell Invoke-WebRequest dropping script.ps1 to user AppData (KongTuke stage-2)

`UC_210_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*Invoke-WebRequest*" OR Processes.process="*iwr *" OR Processes.process="*Net.WebClient*") Processes.process="*script.ps1*" (Processes.process="*AppData*" OR Processes.process="*ApplicationData*" OR Processes.process="*\\Roaming\\*" OR Processes.process="*\\Local\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr ", "Net.WebClient", "DownloadFile", "DownloadString")
| where ProcessCommandLine has "script.ps1"
| where ProcessCommandLine has_any ("AppData", "ApplicationData", "\\Roaming\\", "\\Local\\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          ParentImage=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          SHA256, ReportId
| order by Timestamp desc
```

### Same host calling KongTuke C2 from both powershell.exe and curl.exe within short window

`UC_210_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Processes.process_name) as distinct_procs values(Processes.process_name) as procs values(Processes.process) as cmdlines min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","curl.exe") (Processes.process="*144.31.221.82*" OR Processes.process="*capcha*") by Processes.dest Processes.user host
| `drop_dm_object_name(Processes)`
| where distinct_procs >= 2
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "144.31.221.82" or (RemotePort == 6060 and RemoteUrl has "/capcha")
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "curl.exe")
| summarize ProcessSet = make_set(InitiatingProcessFileName),
            FirstConnection = min(Timestamp),
            LastConnection = max(Timestamp),
            ConnectionCount = count(),
            CmdLines = make_set(InitiatingProcessCommandLine, 8)
          by DeviceId, DeviceName, RemoteIP, AccountName=InitiatingProcessAccountName
| where array_length(ProcessSet) >= 2
| where (ProcessSet has "curl.exe") and (ProcessSet has_any ("powershell.exe","pwsh.exe"))
| order by FirstConnection desc
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

### Article-specific behavioural hunt — Hypotheses, telemetry, and human judgment: Inside Cisco Talos Threat Hunting

`UC_210_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hypotheses, telemetry, and human judgment: Inside Cisco Talos Threat Hunting ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("script.ps1","curl.exe") OR Processes.process="*-EncodedCommand*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("script.ps1","curl.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hypotheses, telemetry, and human judgment: Inside Cisco Talos Threat Hunting
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("script.ps1", "curl.exe") or ProcessCommandLine has_any ("-EncodedCommand"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("script.ps1", "curl.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `144.31.221.82`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
