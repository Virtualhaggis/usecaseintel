# [HIGH] Microsoft Releases Cumulative Update for Windows 11, Version 25H2 and 24H2

**Source:** Cyber Security News
**Published:** 2026-05-13
**Article:** https://cybersecuritynews.com/microsoft-releases-cumulative-update-for-windows-11/

## Threat Profile

Home Cyber Security News 
Microsoft Releases Cumulative Update for Windows 11, Version 25H2 and 24H2 
By Tushar Subhra Dutta 
May 13, 2026 
Microsoft pushed out a significant cumulative update for Windows 11 on May 12, 2026, covering both version 25H2 and version 24H2. The update, identified as KB5089549, brings OS Builds 26200.8457 and 26100.8457 to users running these versions. 
It bundles the latest security fixes alongside quality improvements carried over from April’s optional preview relea…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1592.002** — Gather Victim Host Information: Software
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Windows 11 24H2/25H2 devices missing May 2026 cumulative update KB5089549

`UC_15_2` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Updates where Updates.dest_category="windows" by Updates.dest Updates.vendor_product Updates.signature Updates.signature_id Updates.status Updates.os | `drop_dm_object_name(Updates)` | search vendor_product="Microsoft Windows*" os IN ("Windows 11*","Windows*24H2*","Windows*25H2*") | eval is_may2026_lcu=if(signature_id IN ("KB5089549","5089549") OR signature LIKE "%KB5089549%",1,0), is_may2026_ssu=if(signature_id IN ("KB5092762","5092762") OR signature LIKE "%KB5092762%",1,0) | stats max(is_may2026_lcu) AS has_lcu max(is_may2026_ssu) AS has_ssu values(os) AS os values(signature) AS recent_kbs by dest | where has_lcu=0 OR has_ssu=0 | eval missing=case(has_lcu=0 AND has_ssu=0,"KB5089549+KB5092762",has_lcu=0,"KB5089549 (LCU)",has_ssu=0,"KB5092762 (SSU)") | table dest os missing recent_kbs
```

**Defender KQL:**
```kql
// Win 11 24H2 = OS Build 26100.x, patched build is 26100.8457
// Win 11 25H2 = OS Build 26200.x, patched build is 26200.8457
// SSU KB5092762 brings servicing stack to 26100.8456
let target_lcu = "KB5089549";
let target_ssu = "KB5092762";
let inv = DeviceTvmSoftwareInventory
    | where OSPlatform == "Windows11"
    | where SoftwareName has "windows_11" or SoftwareVendor =~ "microsoft"
    | summarize arg_max(Timestamp, *) by DeviceId;
DeviceInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, *) by DeviceId
| where OSPlatform == "Windows11"
| extend BuildParts = split(OSBuild, ".")
| extend MajorBuild = toint(BuildParts[0]), Revision = toint(BuildParts[1])
| where MajorBuild in (26100, 26200)          // 24H2 / 25H2 families
| extend Branch = case(MajorBuild == 26100, "24H2", MajorBuild == 26200, "25H2", "unknown")
| extend MissingMay2026LCU = (Revision < 8457)
| where MissingMay2026LCU == true
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilities
    | where OSPlatform == "Windows11"
    | where RecommendedSecurityUpdateId has_any (target_lcu, target_ssu, "5089549", "5092762")
    | summarize CveIds = make_set(CveId), Severities = make_set(VulnerabilitySeverityLevel) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, Branch, OSBuild, Revision,
          ExpectedMinRevision = 8457, MissingLCU = target_lcu, MissingSSU = target_ssu,
          IsInternetFacing, MachineGroup, LoggedOnUsers, CveIds, Severities
| order by IsInternetFacing desc, Revision asc
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


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
