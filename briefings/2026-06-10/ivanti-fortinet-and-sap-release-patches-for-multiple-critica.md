# [CRIT] Ivanti, Fortinet, and SAP Release Patches for Multiple Critical Vulnerabilities

**Source:** The Hacker News
**Published:** 2026-06-10
**Article:** https://thehackernews.com/2026/06/ivanti-fortinet-and-sap-release-patches.html

## Threat Profile

Ivanti, Fortinet, and SAP Release Patches for Multiple Critical Vulnerabilities 
 Ravie Lakshmanan  Jun 10, 2026 Vulnerability / Patch Management 
Fortinet, Ivanti, and SAP have released security updates to address multiple critical security vulnerabilities that could result in arbitrary code execution and information disclosure.
The security flaw patched by Fortinet relates to a command injection vulnerability in FortiSandbox, FortiSandbox Cloud, and FortiSandbox PaaS WEB UI. It's tracked as …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-25089`
- **CVE:** `CVE-2026-10520`
- **CVE:** `CVE-2026-10523`
- **CVE:** `CVE-2026-44748`
- **CVE:** `CVE-2026-27671`
- **CVE:** `CVE-2026-22732`
- **CVE:** `CVE-2026-40128`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1136.001** — Create Account: Local Account
- **T1078** — Valid Accounts
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1606.002** — Forge Web Credentials: SAML Tokens

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Ivanti Sentry command injection via /mics/api/v2/sentry/mics-config/handleMessage (CVE-2026-10520)

`UC_58_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses values(Web.src) as src_ips values(Web.user_agent) as user_agents from datamodel=Web where Web.url="*/mics/api/v2/sentry/mics-config/handleMessage*" by Web.dest Web.site Web.url_path | `drop_dm_object_name(Web)` | where statuses!=401 AND statuses!=403 | eval risk="Ivanti Sentry CVE-2026-10520 endpoint hit" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has "/mics/api/v2/sentry/mics-config/handleMessage"
   or AdditionalFields has "/mics/api/v2/sentry/mics-config/handleMessage"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### Ivanti Sentry unauthenticated admin account creation (CVE-2026-10523)

`UC_58_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Changes.src) as src values(All_Changes.user) as actor values(All_Changes.object) as new_admin from datamodel=Change.Account_Management where (All_Changes.action=created OR All_Changes.action=modified) AND (All_Changes.object_category="administrator" OR All_Changes.object_category="admin") AND (All_Changes.dest="*sentry*" OR All_Changes.dvc="*sentry*" OR All_Changes.app="MobileIron Sentry" OR All_Changes.app="Ivanti Sentry") by All_Changes.dest All_Changes.app | `drop_dm_object_name(All_Changes)` | where actor IN ("-","unauthenticated","anonymous","") OR isnull(actor) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SentryHosts = DeviceInfo
    | where Timestamp > ago(7d)
    | where DeviceName has_any ("sentry","mobileiron")
    | summarize by DeviceId, DeviceName;
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceId in ((SentryHosts | project DeviceId))
   or RemoteDeviceName has_any ("sentry","mobileiron")
| where ActionType in ("LogonSuccess","LogonAttempted")
| where AccountName !endswith "$"
| join kind=leftanti (
    DeviceLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | summarize by AccountName
) on AccountName
| project Timestamp, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, RemoteDeviceName, InitiatingProcessFileName
| order by Timestamp desc
```

### Fortinet FortiSandbox WEB UI command injection HTTP pattern (CVE-2026-25089)

`UC_58_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as methods values(Web.status) as statuses values(Web.url) as urls values(Web.user_agent) as uas from datamodel=Web where (Web.dest="*fortisandbox*" OR Web.site="*fortisandbox*" OR Web.url="*/cgi-bin/fsa*" OR Web.url="*/login/*" AND Web.site="*sandbox*") by Web.src Web.dest Web.url_path | `drop_dm_object_name(Web)` | eval urlstr=mvjoin(urls," ") | where match(urlstr, "(?i)(%0a|%0d|%26%26|%7c%7c|%24%28|%60|;\s*(id|whoami|uname|wget|curl|cat\s+/etc)|\|\s*(id|whoami|sh|bash|nc)|`[^`]+`|\$\([^)]+\))") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has_any ("fortisandbox","/cgi-bin/fsa","FortiSandbox")
   or AdditionalFields has_any ("fortisandbox","FortiSandbox")
| extend Url = tolower(strcat(tostring(RemoteUrl)," ",tostring(AdditionalFields)))
| where Url matches regex @"(%0a|%0d|%26%26|%7c%7c|%24%28|%60|;\s*(id|whoami|uname|wget|curl|cat\s+/etc)|\|\s*(id|whoami|sh|bash|nc)|`[^`]+`|\$\([^)]+\))"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, AdditionalFields, InitiatingProcessFileName
| order by Timestamp desc
```

### SAP NetWeaver SAML XML signature wrapping anomaly (CVE-2026-44748)

`UC_58_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.dest) as sap_host values(Authentication.app) as app from datamodel=Authentication where Authentication.app="SAP NetWeaver" AND Authentication.authentication_method="SAML" AND Authentication.action=success by Authentication.user Authentication.user_id | `drop_dm_object_name(Authentication)` | join type=left user [ | tstats summariesonly=true values(Authentication.src) as idp_src values(_time) as idp_time count as idp_count from datamodel=Authentication where Authentication.app IN ("AzureAD","Okta","PingFederate","ADFS") AND Authentication.authentication_method="SAML" by Authentication.user | `drop_dm_object_name(Authentication)` ] | where isnull(idp_count) OR idp_count=0 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SAP_SAML = AlertEvidence
    | where Timestamp > ago(7d)
    | where AdditionalFields has_any ("SAP NetWeaver","SAML","ABAP")
    | project Timestamp, AccountUpn, RemoteIP, AdditionalFields;
let IdpSAML = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where AuthenticationRequirement has "singleFactor" or AuthenticationDetails has "SAML" or ResourceDisplayName has_any ("SAP","NetWeaver","ABAP")
    | summarize IdpHits=count(), LastIdpSignin=max(Timestamp) by AccountUpn, IPAddress, ResourceDisplayName;
SAP_SAML
| join kind=leftouter IdpSAML on AccountUpn
| where isnull(IdpHits) or IdpHits == 0 or RemoteIP != IPAddress
| project Timestamp, AccountUpn, SAPSourceIP=RemoteIP, IdpSourceIP=IPAddress, IdpHits, ResourceDisplayName, AdditionalFields
| order by Timestamp desc
```

### Unpatched Ivanti Sentry / FortiSandbox / SAP NetWeaver in software inventory

`UC_58_10` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Vulnerabilities.signature) as cve values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where Vulnerabilities.signature IN ("CVE-2026-25089","CVE-2026-10520","CVE-2026-10523","CVE-2026-44748","CVE-2026-27671","CVE-2026-22732","CVE-2026-40128") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.vendor_product | `drop_dm_object_name(Vulnerabilities)`
```

**Defender KQL:**
```kql
let TargetCves = dynamic(["CVE-2026-25089","CVE-2026-10520","CVE-2026-10523","CVE-2026-44748","CVE-2026-27671","CVE-2026-22732","CVE-2026-40128"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (TargetCves)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, IsInternetFacing, MachineGroup) by DeviceId
) on DeviceId
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, MachineGroup
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-25089`, `CVE-2026-10520`, `CVE-2026-10523`, `CVE-2026-44748`, `CVE-2026-27671`, `CVE-2026-22732`, `CVE-2026-40128`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
