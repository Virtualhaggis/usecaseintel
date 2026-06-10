# [MED] ServiceNow discloses security incident exposing customer data

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/security/servicenow-discloses-security-incident-exposing-customer-data/

## Threat Profile

ServiceNow discloses security incident exposing customer data 
By Lawrence Abrams 
June 9, 2026
05:34 PM
0 


ServiceNow is warning about a security incident after attackers exploited an unauthenticated access flaw through a vulnerable API endpoint, allowing them to query data from customer instances.


The company quietly warned impacted customers through a support bulletin and direct support cases after detecting "anomalous activity" related to the issue.


The bulletin, which is hidden …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `51.159.98.241`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1213** — Data from Information Repositories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1530** — Data from Cloud Storage Object

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ServiceNow unauthenticated /api/now/related_list_edit/create access from attacker IP 51.159.98.241

`UC_4_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.status) as status values(Web.user) as user from datamodel=Web.Web where Web.url="*/api/now/related_list_edit/create*" OR Web.src="51.159.98.241" by Web.dest Web.http_method | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Defender XDR has no native ServiceNow telemetry; pivot via egress to attacker IP from corporate endpoints
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "51.159.98.241"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### ServiceNow attacker IP 51.159.98.241 observed in CASB/proxy egress from corporate networks

`UC_4_2` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="51.159.98.241" by All_Traffic.dest All_Traffic.action | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "51.159.98.241"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Hosts=make_set(DeviceName, 50), Processes=make_set(InitiatingProcessFileName, 25), Users=make_set(InitiatingProcessAccountName, 25) by RemoteIP, RemotePort
| order by FirstSeen asc
```

### ServiceNow audit log: anonymous/guest user reading sys_db_object tables via related_list_edit

`UC_4_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`servicenow_audit` (user IN ("guest","anonymous","") OR session_type="unauthenticated") (url="*/api/now/related_list_edit*" OR url="*/api/now/table/*") | stats min(_time) as firstTime max(_time) as lastTime count values(tablename) as tables values(operation) as operation values(client_ip) as client_ip by user session_id | where count > 5 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// ServiceNow audit is not shipped to Defender XDR; pivot via CloudAppEvents if ServiceNow is onboarded as a CASB app
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "ServiceNow"
| where (ActionType has_any ("TableRead","RecordRead","List","Query") and (AccountDisplayName has_any ("guest","anonymous") or isempty(AccountDisplayName)))
   or IPAddress == "51.159.98.241"
| project Timestamp, Application, ActionType, AccountDisplayName, AccountObjectId, IPAddress, ObjectName, ObjectType, ActivityObjects, RawEventData
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `51.159.98.241`


## Why this matters

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
