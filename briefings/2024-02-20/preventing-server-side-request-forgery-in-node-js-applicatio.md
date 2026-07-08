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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Web-app runtime egress to AWS IMDS endpoint (169.254.169.254) — SSRF credential theft

`UC_1372_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("169.254.169.254","fd00:ec2::254") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.transport, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("169.254.169.254", "fd00:ec2::254")
| where InitiatingProcessFileName in~ ("node.exe","python.exe","python3.exe","java.exe","php-cgi.exe","php.exe","w3wp.exe","httpd.exe","nginx.exe","ruby.exe","dotnet.exe","tomcat.exe")
| where InitiatingProcessFileName !in~ ("amazon-ssm-agent.exe","ssm-agent.exe","amazoncloudwatchagent.exe","awscloudwatchagent.exe","cloud-init.exe","ec2launch.exe")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count(), SampleCmd=any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemotePort
| order by FirstSeen desc
```

### SSRF probe via 'instance-data' IMDS alias hostname resolution

`UC_1372_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*instance-data*" by DNS.src, DNS.query, DNS.dest | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl contains "instance-data"
| where InitiatingProcessFileName !in~ ("amazon-ssm-agent.exe","cloud-init.exe","ec2launch.exe")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), SampleCmd=any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
| order by FirstSeen desc
```

### Article-specific behavioural hunt — Preventing server-side request forgery in Node.js applications

`UC_1372_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
