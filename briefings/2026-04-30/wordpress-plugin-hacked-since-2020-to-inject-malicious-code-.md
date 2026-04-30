# [HIGH] WordPress Plugin Hacked Since 2020 to Inject Malicious Code Silently

**Source:** Cyber Security News
**Published:** 2026-04-30
**Article:** https://cybersecuritynews.com/wordpress-plugin-hacked/

## Threat Profile

Home Cyber Security News 
WordPress Plugin Hacked Since 2020 to Inject Malicious Code Silently 
By Abinaya 
April 30, 2026 
A massive supply chain attack has been uncovered in the Quick Page/Post Redirect Plugin, a popular WordPress plugin with over 70,000 active installations.
Security researcher Austin Ginder discovered a dormant backdoor introduced five years ago that silently injects arbitrary code into websites.
The malicious code bypassed official security checks by leveraging a custom rem…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1053.005** — Scheduled Task
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1505.003** — Server Software Component: Web Shell
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Quick Page/Post Redirect plugin C2 callback to anadnet.com from WordPress hosts

`UC_20_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua values(Web.dest) as dest from datamodel=Web where (Web.url="*anadnet.com*" OR Web.dest IN ("anadnet.com","w.anadnet.com") OR Web.url IN ("*w.anadnet.com/bro/3*","*anadnet.com/updates*")) by Web.src host | `drop_dm_object_name(Web)` | append [| tstats summariesonly=t count from datamodel=Network_Resolution where Network_Resolution.DNS.query IN ("anadnet.com","*.anadnet.com") by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name(Network_Resolution.DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where RemoteUrl has_any ("anadnet.com","w.anadnet.com") or RemoteUrl matches regex @"(?i)anadnet\.com/(updates|bro/3)"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType ),
( DeviceEvents
  | where ActionType == "DnsQueryResponse" and AdditionalFields has "anadnet.com"
  | project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields )
| sort by Timestamp desc
```

### [LLM] PHP/web-server process initiating outbound connection to anadnet update server

`UC_20_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dport values(All_Traffic.app) as app from datamodel=Network_Traffic where All_Traffic.dest IN ("anadnet.com","w.anadnet.com") OR All_Traffic.dest_host="*anadnet.com" by All_Traffic.src All_Traffic.process_name host | `drop_dm_object_name(All_Traffic)` | search process_name IN ("php*","php-fpm*","php-cgi*","httpd*","nginx*","w3wp.exe","apache2*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm","httpd.exe","nginx.exe","w3wp.exe","apache2")
| where RemoteUrl has "anadnet.com" or RemoteUrl has "w.anadnet.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp desc
```

### [LLM] Hunt for tampered Quick Page/Post Redirect plugin files referencing anadnet update source

`UC_20_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.file_hash) as hashes values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.file_path="*wp-content/plugins/quick-pagepost-redirect-plugin*" AND Filesystem.file_name="*.php" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where FolderPath has "wp-content\\plugins\\quick-pagepost-redirect-plugin" or FolderPath has "wp-content/plugins/quick-pagepost-redirect-plugin"
| where FileName endswith ".php"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("anadnet.com","w.anadnet.com","plugin-update-checker")
    | project Timestamp2=Timestamp, DeviceName, MatchCmd=ProcessCommandLine
) on DeviceName
| sort by Timestamp desc
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
