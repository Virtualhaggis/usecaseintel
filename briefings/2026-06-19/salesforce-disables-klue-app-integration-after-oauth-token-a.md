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
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1526** — Cloud Service Discovery
- **T1213** — Data from Information Repositories
- **T1567** — Exfiltration Over Web Service
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Salesforce REST API access with Python-urllib agent from integration identity (Icarus/UNC6395)

`UC_85_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Web.url) as urls, dc(Web.url) as distinct_urls from datamodel=Web where Web.url="*/services/data/*" AND Web.http_user_agent="*urllib*" by Web.user, Web.src, Web.http_user_agent | `drop_dm_object_name("Web")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where UserAgent has "urllib"          // bare Python-urllib agent used by Icarus/UNC6395 automation (ReliaQuest)
| summarize ApiEvents = count(),
            Actions = make_set(ActionType, 15),
            SourceIPs = make_set(IPAddress, 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by AccountId, AccountDisplayName, UserAgent
| order by ApiEvents desc
```

### Salesforce object-catalog enumeration via /services/data/v59.0/sobjects

`UC_85_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.url="*/services/data/v59.0/sobjects*" by Web.user, Web.src, Web.http_user_agent | `drop_dm_object_name("Web")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Raw = tostring(RawEventData)
| where Raw has "/services/data/" and Raw has "sobjects"
| summarize Hits = count(),
            SourceIPs = make_set(IPAddress, 25),
            UserAgents = make_set(UserAgent, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by AccountId, AccountDisplayName
| order by Hits desc
```

### Bulk Salesforce CRM extraction: high-volume /query + QueryMore loop from one identity

`UC_85_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.url="*/services/data/v59.0/query*" by Web.user, Web.src, _time span=15m | `drop_dm_object_name("Web")` | where count > 500 | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| extend Raw = tostring(RawEventData)
| where Raw has "/services/data/v59.0/query" or Raw has "queryMore" or Raw has "QueryMore"
| summarize QueryCalls = count(),
            ObjectsTouched = dcount(ObjectName),
            UserAgents = make_set(UserAgent, 5),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by AccountId, AccountDisplayName, IPAddress, bin(Timestamp, 15m)
| where QueryCalls > 500    // ~1000 query calls / 15min observed by ReliaQuest; 500 = conservative half-threshold
| order by QueryCalls desc
```

### Egress to Icarus Salesforce data-theft infrastructure (campaign IPs + gofile.io exfil)

`UC_85_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name("All_Traffic")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - count
```

**Defender KQL:**
```kql
let IocIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
let IocDomains = dynamic(["house.com.au","robinskitchen.com.au","baccarat.com.au","gofile.io"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IocIPs) or RemoteUrl has_any (IocDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
