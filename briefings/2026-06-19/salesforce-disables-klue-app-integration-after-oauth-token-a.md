# [HIGH] Salesforce Disables Klue App Integration After OAuth Token Abuse Exposes Customer Data

**Source:** The Hacker News
**Published:** 2026-06-19
**Article:** https://thehackernews.com/2026/06/salesforce-disables-klue-app.html

## Threat Profile

Salesforce Disables Klue App Integration After OAuth Token Abuse Exposes Customer Data 
 Ravie Lakshmanan  Jun 19, 2026 Data Breach / Cloud Security 
Salesforce has revealed that it disabled the Klue Battlecards app integration within its platform in response to a security incident impacting the competitive intelligence company on June 11, 2026.
To that end, organizations will be unable to connect to Salesforce via the app until further notice, the American cloud-based software company noted i…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`
- **Domain (defanged):** `house.com.au`
- **Domain (defanged):** `robinskitchen.com.au`
- **Domain (defanged):** `baccarat.com.au`
- **Domain (defanged):** `gofile.io`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1071** — Application Layer Protocol
- **T1550.001** — Application Access Token
- **T1199** — Trusted Relationship
- **T1213.000** — Data from Information Repositories
- **T1059.006** — Python
- **T1526** — Cloud Service Discovery
- **T1087** — Account Discovery
- **T1119** — Automated Collection
- **T1567.002** — Exfiltration to Cloud Storage
- **T1041** — Exfiltration Over C2 Channel
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Icarus IOC IPs reaching Salesforce tenant via connected app

`UC_24_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.app IN ("*alesforce*","*Klue*","*Battlecard*") Authentication.src IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by Authentication.src Authentication.user Authentication.app Authentication.action | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=true count from datamodel=Network_Traffic where All_Traffic.dest IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
let IcarusIps = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where IPAddress in (IcarusIps)
| project Timestamp, Application, AccountDisplayName, AccountObjectId, IPAddress, ISP, CountryCode, UserAgent, ActionType, ActivityType, ObjectName, RawEventData
| order by Timestamp desc
```

### python-urllib User-Agent against Salesforce connected app

`UC_24_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web where Web.dest_category="salesforce" OR Web.site="*.salesforce.com" OR Web.dest="*.my.salesforce.com" Web.http_user_agent="python-urllib*" by Web.src Web.user Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "Salesforce"
| where UserAgent has "python-urllib"
| extend RestPath = tostring(parse_json(tostring(RawEventData)).URI)
| project Timestamp, Application, AccountDisplayName, AccountObjectId, AccountType, IPAddress, ISP, UserAgent, ActionType, ActivityType, ObjectName, RestPath, RawEventData
| order by Timestamp desc
```

### Salesforce sObjects catalog enumeration via REST from connected app

`UC_24_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where (Web.site="*.salesforce.com" OR Web.dest="*.my.salesforce.com") Web.url="*/services/data/v*/sobjects*" by _time span=15m Web.user Web.src Web.http_user_agent | where count >= 20 | sort 0 - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "Salesforce"
| where RawEventData has "/services/data/" and (RawEventData has "/sobjects" or ActivityType has "sobjects" or ObjectName has "sobjects")
| summarize SObjectCalls = count(), DistinctObjects = dcount(ObjectName), Sample = any(RawEventData), UAs = make_set(UserAgent, 5), IPs = make_set(IPAddress, 5)
          by bin(Timestamp, 15m), AccountDisplayName, AccountObjectId
| where SObjectCalls >= 20
| order by Timestamp desc
```

### Sustained Salesforce /query + QueryMore loop from single connected app

`UC_24_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as QueryCount from datamodel=Web where (Web.site="*.salesforce.com" OR Web.dest="*.my.salesforce.com") (Web.url="*/services/data/v*/query*" OR Web.url="*queryMore*" OR Web.url="*/query/01g*") by _time span=15m Web.user Web.src Web.http_user_agent | where QueryCount >= 800 | sort 0 - QueryCount
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where RawEventData has "/services/data/" and (RawEventData has "/query" or RawEventData has "QueryMore" or ActivityType has "query")
| summarize QueryCount = count(), DistinctIPs = dcount(IPAddress), DistinctUAs = dcount(UserAgent), Sample = any(RawEventData), UAs = make_set(UserAgent, 5)
          by bin(Timestamp, 15m), AccountDisplayName, AccountObjectId
| where QueryCount >= 800   // ~1000-in-15-min burst observed by ReliaQuest
| order by QueryCount desc
| union (
  CloudAppEvents
  | where Timestamp > ago(7d)
  | where Application has "Salesforce"
  | where RawEventData has "/services/data/" and (RawEventData has "/query" or RawEventData has "QueryMore")
  | summarize SustainedQueries = count(), SessionWindowHours = (max(Timestamp) - min(Timestamp)) / 1h
            by bin(Timestamp, 1h), AccountObjectId, AccountDisplayName
  | where SustainedQueries >= 500 and SessionWindowHours >= 6   // 6h+ extraction window
)
```

### Endpoint egress to Icarus Klue-campaign C2/exfil infrastructure

`UC_24_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=true count from datamodel=Network_Resolution where DNS.query IN ("gofile.io","*.gofile.io","house.com.au","robinskitchen.com.au","baccarat.com.au") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` ]
```

**Defender KQL:**
```kql
let IcarusIps = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
let IcarusDomains = dynamic(["gofile.io","house.com.au","robinskitchen.com.au","baccarat.com.au"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IcarusIps)
   or RemoteUrl has_any (IcarusDomains)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### Icarus extortion email: 'top secret email' subject + 48-hour deadline body

`UC_24_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Email where All_Email.direction=inbound (All_Email.subject="*top secret email*" OR All_Email.message="*Salesforce data has been downloaded*" OR All_Email.message="*48 hours to communicate*" OR All_Email.message="*Do the right decision*") by _time All_Email.src_user All_Email.recipient All_Email.subject All_Email.src | `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where (Subject =~ "top secret email" or Subject has "top secret email")
   or Subject has_any ("Your Salesforce data has been downloaded", "Do the right decision")
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, AuthenticationDetails
| order by Timestamp desc
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`, `house.com.au`, `robinskitchen.com.au`, `baccarat.com.au`, `gofile.io`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
