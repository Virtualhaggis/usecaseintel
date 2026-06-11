# [HIGH] Preventing server-side request forgery in Node.js applications

**Source:** Snyk
**Published:** 2024-02-20
**Article:** https://snyk.io/blog/preventing-server-side-request-forgery-node-js/

## Threat Profile

Snyk Blog In this article
Written by David Ekete 
February 20, 2024
0 mins read Server-side request forgery (SSRF) is a common vulnerability that can crop up unknowingly in any Node.js application. It poses a significant threat because attackers can manipulate a server into making unintended requests to both internal and external resources.
This article will explore SSRF, its potential risks, and the strategies to mitigate SSRF in Node.js applications.
Highly recommended: Take the interactive se…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1190** — Exploit Public-Facing Application
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Web-server runtime connecting to AWS IMDS link-local endpoint (SSRF → cred theft)

`UC_1269_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip="169.254.169.254" AND All_Traffic.app IN ("node","node.exe","python","python.exe","python3","java","java.exe","ruby.exe","php-fpm","nginx","nginx.exe","httpd","httpd.exe","w3wp.exe","dotnet.exe","gunicorn") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.user host
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName in~ ("node.exe","python.exe","python3.exe","java.exe","ruby.exe","php-cgi.exe","php-fpm.exe","w3wp.exe","httpd.exe","nginx.exe","dotnet.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### EC2 instance-role session credentials used from non-AWS source IP (Capital One pattern)

`UC_1269_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.action) as actions from datamodel=Authentication where Authentication.signature="AssumedRole" AND Authentication.user_type="AssumedRole" AND Authentication.app="sts.amazonaws.com" by Authentication.user Authentication.src Authentication.user_role
| `drop_dm_object_name(Authentication)`
| where NOT cidrmatch("10.0.0.0/8", src) AND NOT cidrmatch("172.16.0.0/12", src) AND NOT cidrmatch("192.168.0.0/16", src) AND src!="AWS Internal" AND NOT match(src, "\.amazonaws\.com$")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in~ ("AssumeRole","GetSessionToken","AssumeRoleWithWebIdentity","GetCallerIdentity")
| extend rawUserType = tostring(parse_json(tostring(RawEventData)).userIdentity.type)
| where rawUserType == "AssumedRole" or AccountType == "AssumedRole"
| where not(ipv4_is_private(IPAddress)) and IPAddress != "AWS Internal"
| extend RoleArn = tostring(parse_json(tostring(RawEventData)).userIdentity.arn)
| summarize ApiCalls = count(), DistinctActions = dcount(ActionType), Actions = make_set(ActionType, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by AccountDisplayName, RoleArn, IPAddress, CountryCode
| where ApiCalls >= 3
| order by LastSeen desc
```

### Article-specific behavioural hunt — Preventing server-side request forgery in Node.js applications

`UC_1269_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Preventing server-side request forgery in Node.js applications ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Preventing server-side request forgery in Node.js applications
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
