# [CRIT] TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain Attack

**Source:** The Hacker News, Cyber Security News
**Published:** 2026-05-11
**Article:** https://thehackernews.com/2026/05/teampcp-compromises-checkmarx-jenkins.html

## Threat Profile

Home Cyber Security News 
TeamPCP Compromised Checkmarx Jenkins AST Plugin Following KICS Supply Chain Attack 
By Tushar Subhra Dutta 
May 12, 2026 




A supply chain attack that started with a relatively obscure open-source scanner has now reached one of the most widely used application security tools in the industry. In May 2026, a malicious version of the Checkmarx Jenkins AST plugin was quietly published to the Jenkins Marketplace, exposing development pipelines to credential theft and …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-41940`
- **SHA256:** `01ff1e56fd59a8fa525d97e670f7f297a1a204331b89b2cd4e36a9abc6419203`
- **SHA256:** `f50a96d26a5b0beb29de4127e82b2bf350c21511e5a43d286e43f798dc6cd53f`
- **SHA256:** `3ddb8967919a801b3c383e58cddceab21138134c6a26560d99e2672e86f36f2a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1610** — Deploy Container

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TeamPCP C2 egress to checkmarx.cx / checkmarx.zone infrastructure

`UC_17_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="checkmarx.cx" OR DNS.query="*.checkmarx.cx" OR DNS.query="checkmarx.zone" OR DNS.query="*.checkmarx.zone") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("91.195.240.123","94.154.172.43","94.154.172.183") OR All_Traffic.dest IN ("checkmarx.cx","audit.checkmarx.cx","updates.checkmarx.cx","checkmarx.zone") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TeampcpIPs = dynamic(["91.195.240.123","94.154.172.43","94.154.172.183"]);
let TeampcpDomains = dynamic(["checkmarx.cx","audit.checkmarx.cx","updates.checkmarx.cx","checkmarx.zone"]);
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > datetime(2026-03-19)
   | where RemoteIP in (TeampcpIPs)
      or RemoteUrl in~ (TeampcpDomains)
      or RemoteUrl endswith ".checkmarx.cx"
      or RemoteUrl endswith ".checkmarx.zone"
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, ActionType, Source="DeviceNetworkEvents"),
  (DeviceEvents
   | where Timestamp > datetime(2026-03-19)
   | where ActionType == "DnsQueryResponse"
   | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
   | where QueryName endswith "checkmarx.cx" or QueryName endswith "checkmarx.zone"
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP="", RemotePort=int(null), RemoteUrl=QueryName, ActionType, Source="DeviceEvents.DnsQueryResponse")
| order by Timestamp desc
```

### [LLM] Malicious Checkmarx Jenkins AST plugin 2026.5.09 artifact (hash + filename)

`UC_17_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("01ff1e56fd59a8fa525d97e670f7f297a1a204331b89b2cd4e36a9abc6419203","f50a96d26a5b0beb29de4127e82b2bf350c21511e5a43d286e43f798dc6cd53f","3ddb8967919a801b3c383e58cddceab21138134c6a26560d99e2672e86f36f2a") OR Filesystem.file_name IN ("checkmarx-ast-scanner-2026.5.09.hpi","checkmarx-ast-scanner-2026.5.09.jar","checkmarx-ast-scanner-2026.5.09.pom") by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("01ff1e56fd59a8fa525d97e670f7f297a1a204331b89b2cd4e36a9abc6419203","f50a96d26a5b0beb29de4127e82b2bf350c21511e5a43d286e43f798dc6cd53f","3ddb8967919a801b3c383e58cddceab21138134c6a26560d99e2672e86f36f2a") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousHashes = dynamic([
    "01ff1e56fd59a8fa525d97e670f7f297a1a204331b89b2cd4e36a9abc6419203",
    "f50a96d26a5b0beb29de4127e82b2bf350c21511e5a43d286e43f798dc6cd53f",
    "3ddb8967919a801b3c383e58cddceab21138134c6a26560d99e2672e86f36f2a"]);
let MaliciousNames = dynamic([
    "checkmarx-ast-scanner-2026.5.09.hpi",
    "checkmarx-ast-scanner-2026.5.09.jar",
    "checkmarx-ast-scanner-2026.5.09.pom"]);
union isfuzzy=true
  (DeviceFileEvents
   | where Timestamp > datetime(2026-05-09)
   | where SHA256 in (MaliciousHashes) or FileName in~ (MaliciousNames) or FileName has "checkmarx-ast-scanner-2026.5.09"
   | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="DeviceFileEvents"),
  (DeviceProcessEvents
   | where Timestamp > datetime(2026-05-09)
   | where SHA256 in (MaliciousHashes) or FileName in~ (MaliciousNames) or InitiatingProcessSHA256 in (MaliciousHashes)
   | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName, Source="DeviceProcessEvents"),
  (DeviceImageLoadEvents
   | where Timestamp > datetime(2026-05-09)
   | where SHA256 in (MaliciousHashes) or FileName has "checkmarx-ast-scanner-2026.5.09"
   | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="DeviceImageLoadEvents")
| order by Timestamp desc
```

### [LLM] TeamPCP CI/CD artifact references — tpcp.tar.gz, tpcp-docs, malicious Docker/VSIX tags

`UC_17_9` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent_process_name values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process IN ("*tpcp.tar.gz*","*tpcp-docs*","*checkmarx/kics:v2.1.20-debian*","*checkmarx/kics:latest*","*checkmarx/ast-github-action:2.3.35*","*ast-results-2.53.0.vsix*","*cx-dev-assist-1.7.0.vsix*","*checkmarx-ast-scanner-2026.5.09*","*checkmarx.ast-results*","*checkmarx.cx-dev-assist*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("tpcp.tar.gz","ast-results-2.53.0.vsix","cx-dev-assist-1.7.0.vsix","checkmarx-ast-scanner-2026.5.09.hpi","checkmarx-ast-scanner-2026.5.09.jar","checkmarx-ast-scanner-2026.5.09.pom") by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Artifacts = dynamic([
    "tpcp.tar.gz",
    "tpcp-docs",
    "checkmarx/kics:v2.1.20-debian",
    "checkmarx/kics:latest",
    "checkmarx/ast-github-action:2.3.35",
    "ast-results-2.53.0.vsix",
    "cx-dev-assist-1.7.0.vsix",
    "checkmarx-ast-scanner-2026.5.09",
    "checkmarx.ast-results:2.63",
    "checkmarx.ast-results:2.66",
    "checkmarx.cx-dev-assist:1.17",
    "checkmarx.cx-dev-assist:1.19"]);
union isfuzzy=true
  (DeviceProcessEvents
   | where Timestamp > datetime(2026-03-19)
   | where ProcessCommandLine has_any (Artifacts) or InitiatingProcessCommandLine has_any (Artifacts) or FileName has_any (Artifacts)
   | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceProcessEvents"),
  (DeviceFileEvents
   | where Timestamp > datetime(2026-03-19)
   | where FileName has_any ("tpcp.tar.gz","ast-results-2.53.0.vsix","cx-dev-assist-1.7.0.vsix","checkmarx-ast-scanner-2026.5.09") or FolderPath has "tpcp-docs"
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceFileEvents")
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain A

`UC_17_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain A ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("checkmarx-ast-scanner-2026.5.09.jar"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("checkmarx-ast-scanner-2026.5.09.jar"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain A
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("checkmarx-ast-scanner-2026.5.09.jar"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("checkmarx-ast-scanner-2026.5.09.jar"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-41940`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `01ff1e56fd59a8fa525d97e670f7f297a1a204331b89b2cd4e36a9abc6419203`, `f50a96d26a5b0beb29de4127e82b2bf350c21511e5a43d286e43f798dc6cd53f`, `3ddb8967919a801b3c383e58cddceab21138134c6a26560d99e2672e86f36f2a`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
