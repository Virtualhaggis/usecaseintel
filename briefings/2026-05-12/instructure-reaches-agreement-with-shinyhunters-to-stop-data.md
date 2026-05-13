# [MED] Instructure reaches 'agreement' with ShinyHunters to stop data leak

**Source:** BleepingComputer
**Published:** 2026-05-12
**Article:** https://www.bleepingcomputer.com/news/security/instructure-reaches-agreement-with-shinyhunters-to-stop-data-leak/

## Threat Profile

Instructure reaches 'agreement' with ShinyHunters to stop data leak 
By Sergiu Gatlan 
May 12, 2026
05:23 AM
0 
Instructure, the edtech giant behind the widely popular Canvas learning management system (LMS), has reached an "agreement" with the ShinyHunters extortion group to prevent the data stolen in a recent breach from being leaked online.
The company says over 30 million educators and students use its Canvas platform across more than 8,000 schools and universities worldwide.
In a Tuesday st…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1185** — Browser Session Hijacking
- **T1539** — Steal Web Session Cookie
- **T1190** — Exploit Public-Facing Application
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1199** — Trusted Relationship

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Canvas LMS browser sessions during ShinyHunters breach window (Apr 30 – May 7 2026)

`UC_44_0` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as Hits
    min(_time) as FirstSeen
    max(_time) as LastSeen
    values(Web.url) as SampleUrls
    values(Web.dest) as DestHosts
    dc(Web.dest) as UniqueHosts
    from datamodel=Web
    where _time>="2026-04-30T00:00:00" _time<="2026-05-07T23:59:59"
      (Web.url="*.instructure.com*" OR Web.url="*.canvaslms.com*"
       OR Web.dest="*.instructure.com" OR Web.dest="*.canvaslms.com")
    by Web.user Web.src
| `drop_dm_object_name(Web)`
| eval AdminPanelHit=if(match(mvjoin(SampleUrls," "),"(?i)/accounts/[0-9]+|/admin|/api/v1/accounts|/branding|/authentication_providers"),1,0)
| eval FFTHit=if(match(mvjoin(DestHosts," "),"(?i)canvas\.instructure\.com|free-for-teacher"),1,0)
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%dT%H:%M:%S"), LastSeen=strftime(LastSeen,"%Y-%m-%dT%H:%M:%S")
| sort - Hits
```

**Defender KQL:**
```kql
// Canvas LMS Breach-Window Affected-User Enumeration
// Surfaces internal users whose browsers contacted Canvas LMS during
// the ShinyHunters XSS / session-hijack window 2026-04-30 — 2026-05-07.
let WindowStart = datetime(2026-04-30 00:00:00);
let WindowEnd   = datetime(2026-05-07 23:59:59);
let CanvasHostSuffixes = dynamic([".instructure.com",".canvaslms.com"]);
DeviceNetworkEvents
| where Timestamp between (WindowStart .. WindowEnd)
| where InitiatingProcessFileName in~ (
    "chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe","opera.exe","iexplore.exe","safari.exe"
  )
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (CanvasHostSuffixes)
| extend AdminPath = RemoteUrl matches regex @"(?i)/accounts/\d+|/admin|/api/v1/accounts|/branding|/authentication_providers"
| extend FFTHit    = RemoteUrl has "canvas.instructure.com" or RemoteUrl has "free-for-teacher"
| summarize Hits         = count(),
            FirstSeen    = min(Timestamp),
            LastSeen     = max(Timestamp),
            DeviceCount  = dcount(DeviceId),
            Devices      = make_set(DeviceName, 50),
            AdminPathHits= countif(AdminPath),
            FFTHostHits  = countif(FFTHit),
            SampleUrls   = make_set(RemoteUrl, 25)
            by InitiatingProcessAccountName, InitiatingProcessAccountDomain
| order by Hits desc
```

### [LLM] Successful Entra ID / Okta sign-ins to Canvas LMS during breach window

`UC_44_1` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as Sessions
    min(_time) as FirstSeen
    max(_time) as LastSeen
    values(Authentication.src) as SourceIps
    values(Authentication.app) as Apps
    values(Authentication.user_agent) as UserAgents
    dc(Authentication.src) as UniqueSrcIPs
    from datamodel=Authentication
    where _time>="2026-04-30T00:00:00" _time<="2026-05-07T23:59:59"
      Authentication.action=success
      (Authentication.app="*canvas*" OR Authentication.app="*instructure*"
       OR Authentication.signature="*canvas*" OR Authentication.signature="*instructure*")
    by Authentication.user
| `drop_dm_object_name(Authentication)`
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%dT%H:%M:%S"), LastSeen=strftime(LastSeen,"%Y-%m-%dT%H:%M:%S")
| sort - Sessions
```

**Defender KQL:**
```kql
// Canvas / Instructure SSO sign-ins during ShinyHunters breach window
let WindowStart = datetime(2026-04-30 00:00:00);
let WindowEnd   = datetime(2026-05-07 23:59:59);
AADSignInEventsBeta
| where Timestamp between (WindowStart .. WindowEnd)
| where ErrorCode == 0   // success — a usable session was issued
| where Application       has_any ("Canvas","Instructure")
     or AppDisplayName    has_any ("Canvas","Instructure")
     or ResourceDisplayName has_any ("Canvas","Instructure")
| summarize Sessions    = count(),
            FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            SourceIps   = make_set(IPAddress, 25),
            Countries   = make_set(Country, 20),
            UserAgents  = make_set(UserAgent, 20),
            Apps        = make_set(coalesce(AppDisplayName, Application), 5)
            by AccountUpn, AccountObjectId
| order by Sessions desc
```


## Why this matters

Severity classified as **MED** based on: 2 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
