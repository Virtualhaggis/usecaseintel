# [CRIT] UAT-4356's Targeting of Cisco Firepower Devices

**Source:** Cisco Talos
**Published:** 2026-04-23
**Article:** https://blog.talosintelligence.com/uat-4356-firestarter/

## Threat Profile

UAT-4356's Targeting of Cisco Firepower Devices 
By 
Cisco Talos 
Thursday, April 23, 2026 11:10
Threat Advisory
Threats
APT
Cisco Talos is aware of UAT-4356 's continued active targeting of Cisco Firepower devices’ Firepower eXtensible Operating System (FXOS). UAT-4356 exploited n-day vulnerabilities ( CVE-2025-20333 and CVE-2025-20362 ) to gain unauthorized access to vulnerable devices, where the threat actor deployed their custom-built backdoor dubbed “FIRESTARTER.” FIRESTARTER considerably o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2025-20362`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1543** — Create or Modify System Process
- **T1554** — Compromise Host Software Binary
- **T1014** — Rootkit
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1133** — External Remote Services
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] FIRESTARTER on-disk artifacts on Cisco ASA/FTD (lina_cs, svc_samcore.log, CSP_MOUNTLIST)

`UC_72_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.action) as action from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/bin/lina_cs","/opt/cisco/platform/logs/var/log/svc_samcore.log") OR Filesystem.file_name IN ("lina_cs","svc_samcore.log","CSP_MOUNTLIST.tmp","CSP_MOUNT_LIST")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.process="*lina_cs*" OR Processes.process="*show kernel process*lina_cs*" OR Processes.process="*pidof lina_cs*" OR Processes.process="*CSP_MOUNT_LIST*" OR Processes.process="*svc_samcore.log*") by Processes.dest Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let names = dynamic(["lina_cs","svc_samcore.log","CSP_MOUNTLIST.tmp","CSP_MOUNT_LIST"]);
let paths = dynamic(["/usr/bin/lina_cs","/opt/cisco/platform/logs/var/log/svc_samcore.log"]);
DeviceFileEvents
| where Timestamp > ago(90d)
| where FileName in~ (names) or FolderPath in~ (paths) or FolderPath has_any (paths)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| union (
    DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where ProcessCommandLine has_any ("lina_cs","svc_samcore.log","CSP_MOUNT_LIST","CSP_MOUNTLIST.tmp","pidof lina_cs","show kernel process")
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
)
```

### [LLM] Snort SIDs 65340/46897/62949 firing against Cisco ASA/FTD WebVPN (UAT-4356 exploit chain)

`UC_72_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(IDS_Attacks.signature) as signature values(IDS_Attacks.signature_id) as sid values(IDS_Attacks.src) as src values(IDS_Attacks.dest) as dest from datamodel=Network_IDS_Attacks where IDS_Attacks.signature_id IN ("65340","46897","62949") OR IDS_Attacks.signature IN ("*CVE-2025-20333*","*CVE-2025-20362*","*FIRESTARTER*","*ArcaneDoor*") by IDS_Attacks.dest IDS_Attacks.src IDS_Attacks.signature_id | `drop_dm_object_name(IDS_Attacks)` | join type=inner dest [| tstats `summariesonly` count as outbound_flows values(All_Traffic.dest) as outbound_dest values(All_Traffic.dest_port) as outbound_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category="asa_ftd" OR All_Traffic.src_category="firepower" by All_Traffic.src | rename All_Traffic.src as dest | `drop_dm_object_name(All_Traffic)`] | where outbound_flows > 0 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Pivots on Defender XDR alert ingestion of upstream Snort/Firepower events tagged with Cisco's published SIDs/CVEs
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any ("CVE-2025-20333","CVE-2025-20362","FIRESTARTER","ArcaneDoor","UAT-4356","UAT4356","Storm-1849")
   or Title has_any ("sid:65340","sid:46897","sid:62949","1:65340","1:46897","1:62949")
| join kind=inner (AlertEvidence | project AlertId, DeviceId, DeviceName, RemoteIP=tostring(parse_json(AdditionalFields).RemoteIP), LocalIP=tostring(parse_json(AdditionalFields).LocalIP)) on AlertId
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemotePort in (443, 8443) and ActionType == "ConnectionSuccess"
    | summarize OutboundFlows=count(), OutboundDsts=make_set(RemoteIP, 25) by DeviceId
) on DeviceId
| where isnotempty(OutboundFlows)
| project Timestamp, Title, DeviceName, LocalIP, RemoteIP, OutboundFlows, OutboundDsts
```

### Article-specific behavioural hunt — UAT-4356's Targeting of Cisco Firepower Devices

`UC_72_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/cisco/platform/logs/var/log/svc_samcore.log*" OR Filesystem.file_path="*/usr/bin/lina_cs*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/cisco/platform/logs/var/log/svc_samcore.log", "/usr/bin/lina_cs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-20333`, `CVE-2025-20362`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
