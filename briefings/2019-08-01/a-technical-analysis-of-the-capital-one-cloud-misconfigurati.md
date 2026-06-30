# [HIGH] A technical analysis of the Capital One cloud misconfiguration breach

**Source:** Snyk
**Published:** 2019-08-01
**Article:** https://snyk.io/blog/a-technical-analysis-of-the-capital-one-cloud-misconfiguration-breach/

## Threat Profile

Snyk Blog In this article
Written by Josh Stella 
August 1, 2019
0 mins read Editor's note This blog originally appeared on fugue.co. Fugue joined Snyk in 2022 and is a key component of Snyk IaC .
UPDATE: August 26, 2019 Since posting this, AWS has made some public statements regarding the breach that shed some light on what likely happened. From their  response to Senator Ron Wyden , AWS stated:
"As Capital One outlined in their public announcement, the attack occurred due to a  misconfiguratio…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1619** — Cloud Storage Object Discovery
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### EC2 instance-metadata credential theft via curl to 169.254.169.254 IAM endpoint

`UC_3196_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where Processes.process="*169.254.169.254*" Processes.process="*iam/security-credentials*" by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "169.254.169.254"
| where ProcessCommandLine has "iam/security-credentials"
| where FileName in~ ("curl","wget","python","python3","perl","ruby","php","node","bash","sh")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### EC2 instance-role temporary credentials used from non-AWS public IP (exfiltrated creds)

`UC_3196_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype=aws:cloudtrail userIdentity.type=AssumedRole NOT errorCode=*
| eval src=sourceIPAddress
| where src!="AWS Internal" AND NOT cidrmatch("10.0.0.0/8", src) AND NOT cidrmatch("172.16.0.0/12", src) AND NOT cidrmatch("192.168.0.0/16", src) AND NOT cidrmatch("100.64.0.0/10", src)
| stats count min(_time) as firstTime max(_time) as lastTime dc(eventName) as distinctActions values(eventName) as actions values(eventSource) as services by userIdentity.arn userIdentity.sessionContext.sessionIssuer.userName src userAgent
| where count > 0
| sort - count
```

### Single principal mass S3 bucket enumeration and object duplication (700+ buckets)

`UC_3196_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype=aws:cloudtrail eventSource="s3.amazonaws.com" (eventName=GetObject OR eventName=ListObjects OR eventName=ListBucket OR eventName=ListBuckets) NOT errorCode=*
| bin _time span=1h
| stats dc(requestParameters.bucketName) as distinctBuckets count as s3Calls values(eventName) as ops by _time userIdentity.arn sourceIPAddress userAgent
| where distinctBuckets >= 50
| sort - distinctBuckets
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
