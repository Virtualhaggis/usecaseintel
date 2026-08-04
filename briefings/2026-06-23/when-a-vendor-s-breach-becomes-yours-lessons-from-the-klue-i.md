# [HIGH] When a vendor's breach becomes yours: lessons from the Klue incident

**Source:** Snyk
**Published:** 2026-06-23
**Article:** https://snyk.io/blog/when-a-vendors-breach-becomes-yours-lessons-from-the-klue-incident/

## Threat Profile

Snyk Blog In this article
Written by Anthony Larkin 
June 23, 2026
0 mins read There's an uncomfortable truth that every security team eventually runs into: the breach that hurts you most may not happen inside your walls at all. You can patch your code, rotate your secrets periodically, and keep your perimeter tight — and still wake up to find an incident because of a system you don't own.
That's the shape of the incident involving Klue, a market intelligence platform used by a wide range of com…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1119** — Automated Collection
- **T1213** — Data from Information Repositories
- **T1567.002** — Exfiltration to Cloud Storage / Over Web Service
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.003** — Proxy: Multi-hop Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Klue/Icarus: bulk Salesforce CRM record retrieval via connected app (Case/Contact/Account/Opportunity)

`UC_329_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="sfdc:reportexport" OR sourcetype="sfdc:api" OR sourcetype="sfdc:restapi" OR sourcetype="sfdc:bulkapi"
| eval crm_object=coalesce(ENTITY_NAME, ENTITY)
| where (crm_object IN ("Case","Contact","Account","Opportunity")) OR (EVENT_TYPE IN ("ReportExport","BulkApi","BulkApiV2"))
| bin _time span=1h
| stats count AS RecordOps dc(crm_object) AS DistinctObjects values(crm_object) AS Objects values(USER_AGENT) AS UserAgents dc(CLIENT_IP) AS SrcIPCount values(CLIENT_IP) AS SrcIPs by _time, USER_NAME, USER_ID, CONNECTED_APP_NAME
| where RecordOps > 1000
| sort - RecordOps
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Salesforce"
| where ActionType has_any ("Api","ReportExport","Report exported","Bulk","Mass","Export","Read")
| where ObjectType in~ ("Case","Contact","Account","Opportunity") or isempty(ObjectType)
| summarize RecordOps = count(),
            DistinctRecords = dcount(ObjectId),
            ObjectsTouched = make_set(ObjectType, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            UserAgents = make_set(UserAgent, 10),
            SrcIPs = make_set(IPAddress, 15),
            ISPs = make_set(ISP, 8)
            by AccountDisplayName, AccountObjectId, AccountType, ApplicationId, bin(Timestamp, 1h)
| where RecordOps > 1000   // bulk automated pull; productized Klue sync runs far lower, attacker mass-export spikes
| order by RecordOps desc
```

### Salesforce API access bearing python-requests/aiohttp automation user-agent (Icarus OAuth abuse)

`UC_329_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="sfdc:api" OR sourcetype="sfdc:restapi" OR sourcetype="sfdc:bulkapi" OR sourcetype="sfdc:reportexport"
| where like(lower(USER_AGENT),"%python-requests%") OR like(lower(USER_AGENT),"%aiohttp%") OR like(lower(USER_AGENT),"%python-urllib%")
| stats count AS Hits values(EVENT_TYPE) AS EventTypes values(ENTITY_NAME) AS Objects dc(CLIENT_IP) AS SrcIPCount values(CLIENT_IP) AS SrcIPs min(_time) AS firstSeen max(_time) AS lastSeen by USER_NAME, USER_ID, USER_AGENT, CONNECTED_APP_NAME
| sort - Hits
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Salesforce"
| where UserAgent has_any ("python-requests","aiohttp","python-urllib","Python/3")
| summarize EventCount = count(),
            Actions = make_set(ActionType, 12),
            Objects = make_set(ObjectType, 12),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SrcIPs = make_set(IPAddress, 15),
            ISPs = make_set(ISP, 8),
            AnonProxy = make_set(IsAnonymousProxy, 3)
            by AccountDisplayName, AccountObjectId, AccountType, UserAgent
| order by EventCount desc
```

### Salesforce connected-app OAuth access from first-seen ISP / anonymizing proxy (stolen-token reuse)

`UC_329_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) AS firstSeen max(_time) AS lastSeen from datamodel=Authentication where Authentication.app="Salesforce" earliest=-1d by Authentication.user, Authentication.src, Authentication.app
| `drop_dm_object_name(Authentication)`
| search NOT
    [| tstats `summariesonly` count from datamodel=Authentication where Authentication.app="Salesforce" earliest=-30d latest=-1d by Authentication.user, Authentication.src
     | `drop_dm_object_name(Authentication)`
     | fields user, src]
| iplocation src
| table firstSeen, lastSeen, user, app, src, City, Country, count
| sort - firstSeen
```

**Defender KQL:**
```kql
let Lookback = 30d;
let Baseline = CloudAppEvents
    | where Timestamp between (ago(Lookback) .. ago(1d))
    | where Application == "Salesforce"
    | summarize by AccountObjectId, ISP;
CloudAppEvents
| where Timestamp > ago(1d)
| where Application == "Salesforce"
| where isnotempty(AccountObjectId)
| join kind=leftanti Baseline on AccountObjectId, ISP
| summarize EventCount = count(),
            Actions = make_set(ActionType, 10),
            Objects = make_set(ObjectType, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            UserAgents = make_set(UserAgent, 8),
            AnyAnonProxy = max(tobool(IsAnonymousProxy))
            by AccountDisplayName, AccountObjectId, AccountType, IPAddress, ISP, CountryCode
| order by AnyAnonProxy desc, FirstSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
