# [CRIT] Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-07-30
**Article:** https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/

## Threat Profile

Threat Research Center 
Threat Research 
Vulnerabilities 
Vulnerabilities 
Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks 
10 min read 
Related Products Advanced Threat Prevention Advanced WildFire Cloud-Delivered Security Services Cortex Cortex XDR Cortex Xpanse Cortex XSIAM Next-Generation Firewall Unit 42 AI Security Assessment Unit 42 Frontier AI Defense Unit 42 Incident Response 
By: Andy Piazza 
Published: July 30, 2026 
Categories: Threat Research 
Vulnerabi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`
- **CVE:** `CVE-2026-21858`
- **CVE:** `CVE-2025-68613`
- **CVE:** `CVE-2026-3055`
- **CVE:** `CVE-2026-39987`
- **CVE:** `CVE-2026-34486`
- **CVE:** `CVE-2026-33824`
- **Domain (defanged):** `code.newcli.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1106** — Native API
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1070** — Indicator Removal
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1046** — Network Service Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Egress to AI-tool anonymizing proxy code.newcli[.]com (knaithe/KnYuan campaign)

`UC_106_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*code.newcli.com*" OR Web.dest="code.newcli.com" by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.app | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "newcli.com" or RemoteUrl has_any ("code.newcli.com/ultra","code.newcli.com/codex")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Direct egress to Chinese-market LLM APIs (DeepSeek/Qwen) from the estate

`UC_106_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.dest IN ("api.deepseek.com","dashscope.aliyuncs.com") OR Web.url IN ("*api.deepseek.com*","*dashscope.aliyuncs.com*") by Web.src, Web.dest, Web.url, Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("api.deepseek.com","dashscope.aliyuncs.com")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Procs=make_set(InitiatingProcessFileName,10) by DeviceName, InitiatingProcessAccountName, RemoteUrl
| order by FirstSeen desc
```

### Langflow CVE-2026-33017 unauthenticated RCE exploitation (build_public_tmp)

`UC_106_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method="POST" AND Web.url="*/api/v1/validate/code*" by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.status | `drop_dm_object_name(Web)` | where count > 0 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "/api/v1/validate/code"
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Hermes Agent autonomous attack framework execution (fofoapi.py / FofaMap MCP)

`UC_106_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*fofoapi.py*","*fofa-cyberspace-search*","*FofaMap-Platinum*","*hermes*agent*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("fofoapi.py","fofa-cyberspace-search","FofaMap-Platinum","web-terminal-exploitation","godmode")
   or ProcessCommandLine matches regex @"(?i)hermes[-_ ]?agent"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### AI coding-tool anti-attribution / permission-bypass config artifacts

`UC_106_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*dangerously-skip-permissions*","*CLAUDE_CODE_ATTRIBUTION_HEADER*","*CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC*","*disable_response_storage*","*approvalMode*yolo*") by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("dangerously-skip-permissions","CLAUDE_CODE_ATTRIBUTION_HEADER","CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC","disable_response_storage")
   or ProcessCommandLine matches regex @"(?i)approvalMode\s*[:=]\s*.?yolo"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Autonomous mass-scan burst: langflow_poc.py multi-threaded FOFA target sweep

`UC_106_11` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*langflow_poc.py*","*langflow_targets.txt*") OR (Processes.process="*--scan-file*" AND Processes.process="*--threads*") by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ScannerHosts = DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "langflow_poc.py" or ProcessCommandLine has "langflow_targets.txt" or (ProcessCommandLine has "--scan-file" and ProcessCommandLine has "--threads")
| distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceId in (ScannerHosts)
| where RemoteIPType == "Public" and RemotePort in (7860, 80, 443)
| summarize DistinctTargets=dcount(RemoteIP), Conns=count(), Window=max(Timestamp)-min(Timestamp) by DeviceId, DeviceName, bin(Timestamp, 5m)
| where DistinctTargets >= 10   // 10 = actor's --threads 10 concurrency against many FOFA targets in a tight window
| order by DistinctTargets desc
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

### Article-specific behavioural hunt — Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks

`UC_106_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fofoapi.py","langflow_poc.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/worker*" OR Filesystem.file_name IN ("fofoapi.py","langflow_poc.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fofoapi.py", "langflow_poc.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/worker") or FileName in~ ("fofoapi.py", "langflow_poc.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `code.newcli.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`, `CVE-2026-21858`, `CVE-2025-68613`, `CVE-2026-3055`, `CVE-2026-39987`, `CVE-2026-34486`, `CVE-2026-33824`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
