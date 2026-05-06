# [MED] Vimeo data breach exposes personal information of 119,000 people

**Source:** BleepingComputer
**Published:** 2026-05-05
**Article:** https://www.bleepingcomputer.com/news/security/vimeo-data-breach-exposes-personal-information-of-119-000-people/

## Threat Profile

Vimeo data breach exposes personal information of 119,000 people 
By Sergiu Gatlan 
May 5, 2026
09:03 AM
0 
The ShinyHunters extortion gang stole personal information belonging to over 119,000 people after hacking the Vimeo online video platform in April, according to data breach notification service Have I Been Pwned.
Vimeo is a video hosting and streaming platform publicly traded on the Nasdaq stock market, with over 300 million registered users and over 1,100 employees, and reported revenues …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1199** — Trusted Relationship
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1566.004** — Phishing: Spearphishing Voice

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Anodot service principal / OAuth app sign-in from non-Anodot infrastructure

`UC_43_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count, values(Authentication.src) as src_ips, values(Authentication.app) as apps, dc(Authentication.src) as src_count from datamodel=Authentication where Authentication.signature_id="ServicePrincipalSignIn" (Authentication.app="*Anodot*" OR Authentication.user="*anodot*") by _time, Authentication.app, Authentication.user, Authentication.dest span=1h | `drop_dm_object_name(Authentication)` | where src_count > 0
```

**Defender KQL:**
```kql
// Defender XDR — Anodot OAuth app activity in Cloud App audit
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Anodot" or AccountDisplayName has "Anodot" or tostring(RawEventData) has_cs "anodot"
| extend ASN = tostring(parse_json(tostring(AdditionalFields)).ASN)
| summarize Activity = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            SourceIPs = make_set(IPAddress, 100),
            Countries = make_set(CountryCode, 25),
            Actions   = make_set(ActionType, 50),
            Objects   = make_set(ObjectName, 50)
            by Application, AccountObjectId, AccountDisplayName
| where array_length(Countries) > 1 or LastSeen > ago(7d)
| order by LastSeen desc
```

### [LLM] ShinyHunters vishing — new MFA method registered then immediate SSO access to data-rich SaaS apps

`UC_43_1` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count from datamodel=Change where Change.action="updated" Change.object_category="user_auth_method" by _time, Change.user, Change.src span=1m | `drop_dm_object_name(Change)` | rename src as reg_src, _time as reg_time | join type=inner user [ | tstats `summariesonly` count from datamodel=Authentication where Authentication.app IN ("Salesforce","Slack","Dropbox","Atlassian","Zendesk","Adobe","SAP","Workplace","Microsoft 365","Google Workspace") Authentication.action="success" by _time, Authentication.user, Authentication.app, Authentication.src | `drop_dm_object_name(Authentication)` | rename src as auth_src, _time as auth_time ] | where auth_time>=reg_time AND auth_time<=reg_time+1800 AND reg_src!=auth_src
```

**Defender KQL:**
```kql
// Defender XDR — MFA / security-info change followed by SaaS sign-in from a different IP within 30 min
let TargetApps = dynamic(["Salesforce","Slack","Dropbox","Atlassian","Jira","Confluence","Zendesk","Adobe","SAP","Microsoft 365","Google Workspace","OneDrive","SharePoint"]);
let MfaChanges = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application has_any ("Microsoft Entra","Office 365","Azure Active Directory")
    | where ActionType has_any ("Update user","Add registered owner","Register security info",
                                 "User registered security info","Update authentication method",
                                 "Add authentication method")
    | project RegTime = Timestamp, AccountObjectId, AccountDisplayName, RegIP = IPAddress, RegCountry = CountryCode;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where Application in~ (TargetApps) or AppDisplayName in~ (TargetApps)
| join kind=inner MfaChanges on AccountObjectId
| where Timestamp between (RegTime .. RegTime + 30m)
| where IPAddress != RegIP and Country != RegCountry
| project AccountUpn, AccountDisplayName,
          RegTime, RegIP, RegCountry,
          SignInTime = Timestamp, IPAddress, Country, City,
          Application, ResourceDisplayName,
          DelaySec = datetime_diff('second', Timestamp, RegTime)
| order by SignInTime desc
```


## Why this matters

Severity classified as **MED** based on: 2 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
