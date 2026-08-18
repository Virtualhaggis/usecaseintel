# [CRIT] Microsoft Patches 398 Flaws Including a Windows Driver Zero-Day Under Active Attack

**Source:** The Hacker News, Cisco Talos
**Published:** 2026-08-11
**Article:** https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including.html

## Threat Profile

Microsoft Patch Tuesday for August 2026 — Snort rules and prominent vulnerabilities 
By 
Cisco Talos 
Tuesday, August 11, 2026 18:21
Patch Tuesday
Microsoft has released its monthly security update for August 2026, which includes 421 vulnerabilities affecting a range of products, including 62 that Microsoft marked as "critical." 
Microsoft notes that 1 of the vulnerabilities disclosed this month have been exploited in the wild 
CVE-2026-68820  is an elevation of privilege vulnerability affecting…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-68820`
- **CVE:** `CVE-2026-62893`
- **CVE:** `CVE-2026-65665`
- **CVE:** `CVE-2026-62823`
- **CVE:** `CVE-2026-62830`
- **CVE:** `CVE-2026-50516`
- **CVE:** `CVE-2026-68794`
- **CVE:** `CVE-2026-68816`
- **CVE:** `CVE-2026-68804`
- **CVE:** `CVE-2026-62911`
- **CVE:** `CVE-2026-63515`
- **CVE:** `CVE-2026-65657`
- **CVE:** `CVE-2026-63532`
- **CVE:** `CVE-2026-64898`
- **CVE:** `CVE-2026-64903`
- **CVE:** `CVE-2026-64909`
- **CVE:** `CVE-2026-64910`
- **CVE:** `CVE-2026-64911`
- **CVE:** `CVE-2026-70130`
- **CVE:** `CVE-2026-63513`
- **CVE:** `CVE-2026-63519`
- **CVE:** `CVE-2026-65664`
- **CVE:** `CVE-2026-63526`
- **CVE:** `CVE-2026-66807`
- **CVE:** `CVE-2026-63518`
- **CVE:** `CVE-2026-63525`
- **CVE:** `CVE-2026-64907`
- **CVE:** `CVE-2026-62827`
- **CVE:** `CVE-2026-64921`
- **CVE:** `CVE-2026-62824`
- **CVE:** `CVE-2026-62818`
- **CVE:** `CVE-2026-62817`
- **CVE:** `CVE-2026-62820`
- **CVE:** `CVE-2026-62878`
- **CVE:** `CVE-2026-66802`
- **CVE:** `CVE-2026-71331`
- **CVE:** `CVE-2026-62890`
- **CVE:** `CVE-2026-62822`
- **CVE:** `CVE-2026-66799`
- **CVE:** `CVE-2026-62816`
- **CVE:** `CVE-2026-62819`
- **CVE:** `CVE-2026-62889`
- **CVE:** `CVE-2026-65789`
- **CVE:** `CVE-2026-65791`
- **CVE:** `CVE-2026-49163`
- **CVE:** `CVE-2026-50481`
- **CVE:** `CVE-2026-68823`
- **CVE:** `CVE-2026-62869`
- **CVE:** `CVE-2026-56161`
- **CVE:** `CVE-2026-63522`
- **CVE:** `CVE-2026-56162`
- **CVE:** `CVE-2026-62836`
- **CVE:** `CVE-2026-50515`
- **CVE:** `CVE-2026-62873`
- **CVE:** `CVE-2026-59115`
- **CVE:** `CVE-2026-70332`
- **CVE:** `CVE-2026-63508`
- **CVE:** `CVE-2026-59118`
- **CVE:** `CVE-2026-65668`
- **CVE:** `CVE-2026-62815`
- **CVE:** `CVE-2026-62896`
- **CVE:** `CVE-2026-62918`
- **CVE:** `CVE-2026-65667`
- **CVE:** `CVE-2026-58650`
- **CVE:** `CVE-2026-63520`
- **CVE:** `CVE-2026-59124`
- **CVE:** `CVE-2026-59133`
- **CVE:** `CVE-2026-59132`
- **CVE:** `CVE-2026-61348`
- **CVE:** `CVE-2026-61925`
- **CVE:** `CVE-2026-61930`
- **CVE:** `CVE-2026-62688`
- **CVE:** `CVE-2026-62696`
- **CVE:** `CVE-2026-62713`
- **CVE:** `CVE-2026-62712`
- **CVE:** `CVE-2026-62735`
- **CVE:** `CVE-2026-62737`
- **CVE:** `CVE-2026-62783`
- **CVE:** `CVE-2026-62766`
- **CVE:** `CVE-2026-65788`
- **CVE:** `CVE-2026-69278`
- **CVE:** `CVE-2026-70307`
- **CVE:** `CVE-2026-70335`
- **CVE:** `CVE-2026-66804`
- **CVE:** `CVE-2026-70355`
- **CVE:** `CVE-2026-61358`
- **CVE:** `CVE-2026-61929`
- **CVE:** `CVE-2026-62698`
- **CVE:** `CVE-2026-62721`
- **CVE:** `CVE-2026-62741`
- **CVE:** `CVE-2026-62788`
- **CVE:** `CVE-2026-62832`
- **CVE:** `CVE-2026-62888`
- **CVE:** `CVE-2026-65775`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Article-specific behavioural hunt — Microsoft Patches 398 Flaws Including a Windows Driver Zero-Day Under Active Att

`UC_78_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patches 398 Flaws Including a Windows Driver Zero-Day Under Active Att ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys","atbroker.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys","atbroker.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patches 398 Flaws Including a Windows Driver Zero-Day Under Active Att
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys", "atbroker.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys", "atbroker.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-68820`, `CVE-2026-62893`, `CVE-2026-65665`, `CVE-2026-62823`, `CVE-2026-62830`, `CVE-2026-50516`, `CVE-2026-68794`, `CVE-2026-68816` _(+86 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
