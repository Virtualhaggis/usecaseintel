# [HIGH] Nintendo confirms data stolen in WebMD subsidiary cyberattack

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/nintendo-confirms-data-stolen-in-webmd-subsidiary-cyberattack/

## Threat Profile

Nintendo confirms data stolen in WebMD subsidiary cyberattack 
By Bill Toulas 
June 18, 2026
02:31 PM
0 
Nintendo of America has confirmed to BleepingComputer that threat actors stole survey data from the third-party TinyPulse service used internally, but its systems were not compromised.
The company’s statement comes after claims from the Shadowbyt3$ “extortion-as-a-service” threat group that they exfiltrated sensitive data related to Nintendo of America employees.
“We are aware of an issue inv…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `nintendo.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1199** — Trusted Relationship
- **T1213** — Data from Information Repositories
- **T1530** — Data from Cloud Storage
- **T1567.002** — Exfiltration to Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1657** — Financial Theft
- **T1486** — Data Encrypted for Impact

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anomalous bulk export / cross-geo admin access to TinyPulse (WebMD) SaaS tenant

`UC_28_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.src_ip) as src_ip dc(Authentication.src_ip) as ip_count dc(Authentication.src_country) as country_count from datamodel=Authentication where Authentication.app IN ("*TinyPulse*","*tinypulse*","*WebMD*","*webmd*") Authentication.action="success" by Authentication.user Authentication.app | `drop_dm_object_name(Authentication)` | where country_count > 2 OR ip_count > 10 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TinyPulseApps = dynamic(["TinyPulse","tinypulse","WebMD","webmd","WebMD Health Services"]);
let BulkOps = dynamic(["Export","BulkDownload","MassDownload","DownloadFile","ExportToCsv","ExportData","DownloadReport"]);
let SignInAnomaly = AADSignInEventsBeta
  | where Timestamp > ago(30d)
  | where Application has_any (TinyPulseApps) or ApplicationId has_any (TinyPulseApps)
  | where ErrorCode == 0
  | summarize SignInCount = count(),
              Countries = make_set(Country, 10),
              IPs = make_set(IPAddress, 25),
              FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
              by AccountUpn, Application
  | where array_length(Countries) > 2 or SignInCount > 200
  | extend Signal = "cross-geo or volumetric sign-in";
let BulkExport = CloudAppEvents
  | where Timestamp > ago(30d)
  | where Application has_any (TinyPulseApps)
  | where ActionType has_any (BulkOps)
     or (ActivityType has_any ("download","export","bulk") and isnotempty(ObjectName))
  | summarize EventCount = count(),
              Objects = make_set(ObjectName, 25),
              Countries = make_set(CountryCode, 10),
              IPs = make_set(IPAddress, 10),
              FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
              by AccountDisplayName, Application, ActionType
  | extend Signal = "bulk export against TinyPulse";
SignInAnomaly
| union BulkExport
| order by LastSeen desc
```

### First-time outbound to mega.nz file-sharing infrastructure (Shadowbyt3$ leak host)

`UC_28_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.url) as url values(Web.bytes_out) as bytes_out sum(Web.bytes_out) as total_bytes from datamodel=Web where (Web.url IN ("*mega.nz*","*mega.io*","*mega.co.nz*","*g.api.mega.co.nz*") OR Web.dest IN ("mega.nz","mega.io","mega.co.nz")) by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | where total_bytes > 1048576 OR firstTime > relative_time(now(), "-7d")
```

**Defender KQL:**
```kql
let MegaPatterns = dynamic(["mega.nz","mega.io","mega.co.nz","g.api.mega.co.nz","userstorage.mega.co.nz"]);
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(90d) .. ago(7d))
    | where RemoteUrl has_any (MegaPatterns)
    | summarize by DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (MegaPatterns) or RemoteUrl matches regex @"(?i)\bmega\.(?:nz|io|co\.nz)\b"
| where RemoteIPType == "Public"
| join kind=leftanti Baseline on DeviceId
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ConnCount = count(),
            URLs = make_set(RemoteUrl, 10),
            IPs = make_set(RemoteIP, 10),
            Processes = make_set(InitiatingProcessFileName, 5),
            CmdLines = make_set(InitiatingProcessCommandLine, 5)
            by DeviceId, DeviceName, InitiatingProcessAccountName
| order by FirstSeen desc
```

### Inbound email referencing Shadowbyt3$ extortion / leak negotiation

`UC_28_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subject values(All_Email.message_id) as message_id from datamodel=Email where All_Email.direction="inbound" (All_Email.subject IN ("*Shadowbyt3*","*shadowbyt3*","*ShadowByt3*") OR All_Email.body IN ("*Shadowbyt3*","*shadowbyt3*","*48 hours*ransom*","*2 million*","*data leak*ransom*")) by All_Email.src_user All_Email.recipient | `drop_dm_object_name(All_Email)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let ExtortionKeywords = dynamic(["Shadowbyt3","shadowbyt3","ShadowByt3$","shadow byt3"]);
let RansomLanguage = dynamic(["48 hours","48-hour","$2 million","2,000,000","extortion as a service","Deleted Permanently","leak site","data leak"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where Subject has_any (ExtortionKeywords)
    or Subject has_any (RansomLanguage)
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(30d)
    | where Url has_any ("mega.nz","mega.io","mega.co.nz")
    | project NetworkMessageId, LeakUrl=Url
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          LeakUrl, ThreatTypes
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `nintendo.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
