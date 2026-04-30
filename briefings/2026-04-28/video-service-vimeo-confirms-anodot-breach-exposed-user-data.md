# [HIGH] Video service Vimeo confirms Anodot breach exposed user data

**Source:** BleepingComputer
**Published:** 2026-04-28
**Article:** https://www.bleepingcomputer.com/news/security/video-service-vimeo-confirms-anodot-breach-exposed-user-data/

## Threat Profile

Video service Vimeo confirms Anodot breach exposed user data 
By Bill Toulas 
April 28, 2026
03:04 PM
0 
Vimeo has disclosed that data belonging to some of its customers and users has been accessed without authorization following the recent breach at the Anodot data anomaly detection company.
The video platform says that the threat actor accessed email addresses for some of its customers, but most of the exposed information included technical data, video titles, and metadata.
"We have identified…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1528** — Steal Application Access Token
- **T1567.002** — Exfiltration to Cloud Storage
- **T1213.003** — Code Repositories / Cloud Data Stores
- **T1530** — Data from Cloud Storage
- **T1098.001** — Account Manipulation: Additional Cloud Credentials

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Anodot service-account auth to Snowflake/BigQuery from non-Anodot egress IP space

`UC_21_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.user_agent) as ua values(Authentication.app) as app from datamodel=Authentication where (Authentication.app="snowflake" OR Authentication.app="bigquery" OR Authentication.app="gcp*") AND (Authentication.user="*anodot*" OR Authentication.user="ANODOT_*" OR Authentication.signature="OAUTH_ACCESS_TOKEN" Authentication.app_name="Anodot") by Authentication.user Authentication.app Authentication.src Authentication.dest | `drop_dm_object_name(Authentication)` | iplocation src | search NOT src_country IN ("Israel","United States") OR NOT cidrmatch("<known_anodot_egress_cidr>",src) | where firstTime>=relative_time(now(),"-30d@d")
```

**Defender KQL:**
```kql
let anodotPrincipals = dynamic(["anodot","ANODOT_USER","ANODOT_SVC","anodot-connector","anodot_integration"]);
CloudAppEvents
| where Timestamp >= datetime(2026-04-01)
| where Application in ("Snowflake","Google Cloud Platform","Microsoft 365 BigQuery") or ApplicationId in (28375,11599)
| where ActionType in ("Log on","LogonSuccess","OAuthTokenIssued","Service account login")
| extend principal = tolower(tostring(RawEventData.user_name))
| where principal has_any (anodotPrincipals) or tostring(RawEventData.client_application_id) has "Anodot"
| extend asn = tostring(IPTags), country = tostring(CountryCode)
| summarize logins=count(), srcIPs=make_set(IPAddress,50), uaSet=make_set(UserAgent,20), countries=make_set(country,20) by principal, Application, AccountObjectId
| where array_length(srcIPs) > 1 or countries !has "IL"
```

### [LLM] Bulk export / COPY INTO via Anodot integration user on Snowflake or BigQuery

`UC_21_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`snowflake_query_history` (user_name="ANODOT*" OR user_name="*anodot*" OR application_name="Anodot") (query_text="COPY INTO @*" OR query_text="GET @*" OR query_text="PUT file://*" OR query_text="CREATE STAGE*" OR query_text="SELECT * FROM*" rows_produced>500000) 
| eval bytes_mb=round(bytes_written/1024/1024,2) 
| stats sum(rows_produced) as rows sum(bytes_written) as bytes values(query_text) as queries values(client_ip) as src dc(query_id) as queries_n by user_name warehouse_name database_name 
| where bytes>104857600 OR rows>1000000 OR queries_n>50 
| append [ search `bigquery_audit` protoPayload.authenticationInfo.principalEmail="*anodot*" (protoPayload.methodName="jobservice.jobcompleted" OR protoPayload.methodName="google.cloud.bigquery.v2.JobService.InsertJob") ("EXPORT DATA" OR jobConfig.extract.destinationUri="gs://*") | stats sum(jobStatistics.totalProcessedBytes) as bytes by protoPayload.authenticationInfo.principalEmail ]
```

**Defender KQL:**
```kql
let anodot = dynamic(["anodot","anodot_svc","anodot-connector"]);
CloudAppEvents
| where Timestamp >= datetime(2026-04-01)
| where Application in ("Snowflake","Google Cloud Platform")
| extend principal = tolower(tostring(RawEventData.user_name))
| extend qtext = tostring(RawEventData.query_text), method = tostring(RawEventData.methodName), bytes = tolong(RawEventData.bytes_written)
| where principal has_any (anodot)
| where ActionType in ("DataExport","QueryExecuted","jobservice.jobcompleted")
     or qtext matches regex @"(?i)\b(COPY\s+INTO\s+@|GET\s+@|EXPORT\s+DATA|UNLOAD)\b"
     or method == "google.cloud.bigquery.v2.JobService.InsertJob"
| summarize totalBytes=sum(bytes), queries=count(), samples=make_set(qtext,10), tables=make_set(tostring(RawEventData.objects_accessed),20) by principal, Application, bin(Timestamp,1h)
| where totalBytes > 100*1024*1024 or queries > 50
```

### [LLM] Continued use of Anodot OAuth/integration credential after vendor revocation date

`UC_21_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.dest) as dest values(Authentication.action) as action from datamodel=Authentication where Authentication.app IN ("snowflake","bigquery","gcp_iam","azure_ad") AND (Authentication.user="*anodot*" OR Authentication.user="ANODOT_*" OR Authentication.app_name="Anodot" OR Authentication.signature="Anodot*") by Authentication.user Authentication.app Authentication.action _time span=1h | `drop_dm_object_name(Authentication)` | eval revocation_epoch=strptime("2026-04-28 18:00:00","%Y-%m-%d %H:%M:%S") | where _time >= revocation_epoch AND action="success"
```

**Defender KQL:**
```kql
let revocation = datetime(2026-04-28T18:00:00Z);
let anodot = dynamic(["anodot","anodot_svc","ANODOT_USER","anodot-connector","anodot_integration"]);
union isfuzzy=true
  (CloudAppEvents
   | where Timestamp >= revocation
   | where Application in ("Snowflake","Google Cloud Platform")
   | extend principal = tolower(tostring(RawEventData.user_name))
   | where principal has_any (anodot)
   | where ActionType in ("Log on","LogonSuccess","OAuthTokenIssued","QueryExecuted")),
  (AADSignInEventsBeta
   | where Timestamp >= revocation
   | where AppDisplayName has "Anodot" or ResourceDisplayName has "Anodot" or ServicePrincipalName has "anodot"
   | where ErrorCode == 0)
| project Timestamp, principal=coalesce(principal, AccountUpn, ServicePrincipalName), Application=coalesce(Application, AppDisplayName), IPAddress, ActionType, ResourceDisplayName
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
