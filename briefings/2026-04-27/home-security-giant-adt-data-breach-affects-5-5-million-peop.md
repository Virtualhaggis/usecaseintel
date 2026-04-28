<!-- curated:true -->
# [MED] Home Security Giant ADT Data Breach Affects 5.5 Million People — ShinyHunters Attribution

**Source:** BleepingComputer
**Published:** 2026-04-27
**Article:** https://www.bleepingcomputer.com/news/security/home-security-giant-adt-data-breach-affects-55-million-people/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

**ShinyHunters** stole personal data on **5.5 million ADT customers** in early April 2026 (per HaveIBeenPwned). ShinyHunters has been the most prolific 2024-2026 large-scale data-extortion crew, with prior victims including:
- Snowflake-hosted environments (~165 enterprises in 2024)
- Salesforce, Dropbox Sign, Bandsintown, AT&T (165M records)
- Multiple ticketing platforms, hospitality groups, telcos

Their **dominant TTP** is **valid-credential abuse against externally-exposed corporate apps with weak MFA enforcement**:
1. Acquire valid credentials via infostealer logs (sold on Russian Market / 2easy / Genesis-successors).
2. Identify accounts with access to data-storage SaaS (Snowflake, Salesforce, Dropbox, Workday, Zendesk).
3. Bulk-export tables / files via legitimate API.
4. Extort for non-publication.

For SOCs not directly on ADT's customer side, the **detection lessons are universal** — every step of the ShinyHunters playbook is detectable if the right rules are in place.

We've kept severity **MED** — the breach impact is consumer-facing, but the **TTP class is the dominant 2026 large-data-extortion playbook** and worth tagging as a defensive priority for any enterprise with significant SaaS data presence.

## Indicators of Compromise

- _ADT customer-PII exfil details, no technical IOCs published in the article excerpt._
- ShinyHunters TTPs (durable):
  - Login from infostealer-aligned ASN (residential proxies via OxyLabs, Soax, BrightData, Astrill, M247).
  - **Bulk read** API calls — most legit users read few records; exfil reads thousands per session.
  - Use of Snowflake CLI / Salesforce DataLoader / Dropbox API explicitly to enumerate.
  - Single user → many tables / many objects → minutes-scale window.

## MITRE ATT&CK (analyst-validated)

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1110.004** — Brute Force: Credential Stuffing
- **T1556** — Modify Authentication Process (where MFA is bypassed via session-token theft)
- **T1539** — Steal Web Session Cookie (the source of the credentials)
- **T1213** — Data from Information Repositories
- **T1567.002** — Exfiltration to Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1657** — Financial Theft (the extortion stage)

## Recommended SOC actions (priority-ordered)

1. **Audit MFA enforcement on data-storage SaaS.** Snowflake / Databricks / Salesforce / Dropbox / Workday / Zendesk / Box. ShinyHunters specifically targets these. If any of them allows password-only auth for service accounts or specific user roles, that's the gap.
2. **Hunt bulk-export anomalies.** A sudden 100x increase in records read by a user is the strongest signal for this attack class.
3. **Hunt sign-ins from VPN / residential-proxy ASN.** Maintain a deny-list of known infostealer-credential consumer ASNs. Common: M247, DataPacket, Astrill, OxyLabs, Soax, BrightData. (Some legitimate use exists; tune carefully.)
4. **Enable session-token binding / continuous access evaluation** in Entra ID for SaaS apps. CAE catches token reuse from new IPs.
5. **Quarterly infostealer-cred-rotation drill**: subscribe to a feed (HaveIBeenPwned Premium API, IntelX, KELA), match employee emails against new dumps, force resets.
6. **Customer-data-extraction policy**: limit which roles can bulk-export PII, require step-up auth for downloads >N records.

## Splunk SPL — bulk record reads from SaaS API

```spl
index=salesforce OR index=snowflake OR index=dropbox OR index=zendesk OR index=workday
    action IN ("query","read","export","download","fetch","listObjects","getObject")
| stats sum(records_returned) AS total_records, count AS api_calls,
        earliest(_time) AS firstTime, latest(_time) AS lastTime
        by user, src_ip, _time
| where total_records > 10000 OR api_calls > 100
| sort - total_records
```

## Splunk SPL — sign-in from residential / VPN-provider ASN

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
    by Authentication.user, Authentication.src
| `drop_dm_object_name(Authentication)`
| iplocation src
| where match(ASN_org,
    "(?i)(M247|DataPacket|Astrill|OxyLabs|Soax|BrightData|NetProtect|Mullvad|ProtonVPN|ExpressVPN|NordVPN)")
| stats values(ASN_org) AS asns, values(Country) AS countries, count by user
```

## Splunk SPL — token reuse across geographies

```spl
| tstats `summariesonly` count
    from datamodel=Authentication.Authentication
    where Authentication.action="success" AND Authentication.is_interactive="false"
    by Authentication.user, Authentication.src, Authentication.session_id
| `drop_dm_object_name(Authentication)`
| iplocation src
| stats dc(Country) AS countries, dc(src) AS source_ips, values(Country) AS country_list
        by user, session_id
| where countries > 1 AND source_ips > 1
```

## Defender KQL — sign-ins from suspect ASN

```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ResultType == 0
| where NetworkLocationDetails has_any (
    "M247","DataPacket","Astrill","OxyLabs","Soax","BrightData","NetProtect",
    "Mullvad","ProtonVPN","ExpressVPN","NordVPN","Hetzner","Vultr","DigitalOcean")
| summarize signins = count(),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp),
            uniqueIPs = dcount(IPAddress)
            by AccountUpn, NetworkLocationDetails, Country
| order by signins desc
```

## Defender KQL — token-replay across countries (CAE coverage gap)

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IsInteractive == false
| summarize sessions = count(),
            countries = make_set(Country),
            asns = make_set(NetworkLocationDetails)
            by AccountUpn, SessionId
| where array_length(countries) > 1
| order by sessions desc
```

## Defender KQL — high-volume Salesforce data export

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where ActionType in ("ReportExport","DataExport","ListView","BulkApiQuery","RestApiCall")
| summarize records = sum(toint(coalesce(tostring(RawEventData.RecordCount),"1"))),
            calls = count(),
            firstSeen = min(Timestamp), lastSeen = max(Timestamp)
            by AccountUpn, IPAddress
| where records > 10000 or calls > 100
| order by records desc
```

## Why this matters for your SOC

Even if your org isn't an ADT victim, **ShinyHunters' next campaign will look operationally identical**: infostealer-cred → SaaS API access → bulk export → extort. The defender posture is:

1. **MFA + CAE** on every data-storage SaaS, no exceptions, no service-account carve-outs without compensating controls.
2. **Bulk-read anomaly detection** in your CASB / SaaS monitoring stack.
3. **Active monitoring of infostealer dumps** for employee credentials.
4. **A documented bulk-export response playbook** that triggers within the same hour as detection.

The detections above are the most cost-effective controls against the entire ShinyHunters-class playbook. Build one, test it, deploy, then the next.
