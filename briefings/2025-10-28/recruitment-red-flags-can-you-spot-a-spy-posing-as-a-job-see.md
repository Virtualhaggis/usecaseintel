# [HIGH] Recruitment red flags: Can you spot a spy posing as a job seeker?

**Source:** ESET WeLiveSecurity
**Published:** 2025-10-28
**Article:** https://www.welivesecurity.com/en/business-security/recruitment-spot-spy-job-seeker/

## Threat Profile

Back in July 2024, cybersecurity vendor KnowBe4 began to observe suspicious activity linked to a new hire. The individual began manipulating and transferring potentially harmful files, and tried to execute unauthorized software. He was subsequently found out to be a North Korean worker who had tricked the firm’s HR team into gaining remote employment with the firm. In all, the individual managed to pass four video conference interviews as well as a background and pre-hiring check.
The incident u…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1078** — Valid Accounts
- **T1656** — Impersonation
- **T1133** — External Remote Services
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DPRK 'WageMole/Jasper Sleet' RMM stack on recently-enrolled corporate device

`UC_554_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdline values(Processes.parent_process_name) as parent FROM datamodel=Endpoint.Processes WHERE Processes.process_name IN ("jumpconnect.exe","tinypilot.exe","rustdesk.exe","anyviewer.exe","anydesk.exe","teamviewer.exe") BY Processes.dest Processes.user Processes.process_name _time span=1h | `drop_dm_object_name(Processes)` | eval is_new_hire_device=if(firstSeen > relative_time(now(),"-30d"),"yes","no") | search is_new_hire_device="yes" | sort - lastSeen
```

**Defender KQL:**
```kql
// DPRK IT-worker RMM stack on a freshly enrolled device — Jasper Sleet / UNC5267
let _rmm_dprk = dynamic(["jumpconnect.exe","tinypilot.exe","rustdesk.exe","anyviewer.exe","anydesk.exe","teamviewer.exe"]);
let _new_devices =
    DeviceInfo
    | where Timestamp > ago(120d)
    | summarize FirstSeen = min(Timestamp) by DeviceId, DeviceName
    | where FirstSeen > ago(30d);   // device enrolled in last 30 days = proxy for new hire
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (_rmm_dprk)
| where AccountName !endswith "$"
| join kind=inner _new_devices on DeviceId
| where Timestamp between (FirstSeen .. FirstSeen + 30d)
| extend DaysSinceEnrollment = datetime_diff('day', Timestamp, FirstSeen)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName,
          FirstSeen, DaysSinceEnrollment, SHA256
| order by Timestamp desc
```

### [LLM] Astrill VPN client or relay traffic from a corporate endpoint (DPRK IT-worker location obfuscation)

`UC_554_1` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.dest) as hosts FROM datamodel=Endpoint.Processes WHERE (Processes.process_name IN ("astrill.exe","astrillvpn.exe","astrillservice.exe") OR Processes.process="*astrill*") BY Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls FROM datamodel=Web.Web WHERE Web.url="*astrill.com*" OR Web.url="*astrillvpn*" BY Web.src Web.user | `drop_dm_object_name(Web)` ] | sort - lastTime
```

**Defender KQL:**
```kql
// Astrill VPN — named by Microsoft as the favoured DPRK IT-worker VPN
let _astrill_proc = dynamic(["astrill.exe","astrillvpn.exe","astrillservice.exe","astrillopenweb.exe"]);
let _astrill_strings = dynamic(["astrill","astrillvpn"]);
union isfuzzy=true
  ( DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where AccountName !endswith "$"
    | where FileName in~ (_astrill_proc)
       or InitiatingProcessFileName in~ (_astrill_proc)
       or ProcessCommandLine has_any (_astrill_strings)
    | project Timestamp, DeviceName, AccountName, Source="Process",
              Detail=strcat(FileName, " :: ", ProcessCommandLine),
              Parent=InitiatingProcessFileName ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any (_astrill_strings)
       or InitiatingProcessFileName in~ (_astrill_proc)
    | project Timestamp, DeviceName,
              AccountName=InitiatingProcessAccountName,
              Source="Network",
              Detail=strcat(RemoteUrl, " ", tostring(RemoteIP), ":", tostring(RemotePort)),
              Parent=InitiatingProcessFileName ),
  ( DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName has_any (_astrill_strings)
    | project Timestamp, DeviceName,
              AccountName=InitiatingProcessAccountName,
              Source="FileDrop",
              Detail=strcat(FolderPath, "\\", FileName),
              Parent=InitiatingProcessFileName )
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
