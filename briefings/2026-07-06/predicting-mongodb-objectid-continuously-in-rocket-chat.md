# [HIGH] Predicting MongoDB ObjectId continuously in Rocket.Chat

**Source:** Aikido
**Published:** 2026-07-06
**Article:** https://www.aikido.dev/blog/predicting-mongodb-objectid-rocket-chat

## Threat Profile

Blog Vulnerabilities & Threats Predicting MongoDB ObjectId() continuously in Rocket.Chat Predicting MongoDB ObjectId() continuously in Rocket.Chat Written by Jorian Woltjer Published on: Jul 6, 2026 Applications using MongoDB have a common pitfall of treating the ObjectId() function as cryptographically secure. Recently, we found Rocket.Chat , an open source Slack-like application, to be a victim of this. At Aikido, we run AI Pentests on various open source applications to test our agents and id…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1213** — Data from Information Repositories
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Rocket.Chat Livechat file-upload ID enumeration sweep (ObjectId harvest)

`UC_191_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as total_requests dc(Web.uri_path) as distinct_files min(_time) as firstTime max(_time) as lastTime values(Web.status) as statuses values(Web.http_user_agent) as user_agent from datamodel=Web where Web.uri_path="/file-upload/*" (Web.uri_query="*rc_room_type=l*" OR Web.uri_query="*rc_token=*") by Web.src Web.dest
| `drop_dm_object_name(Web)`
| where distinct_files >= 25
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - distinct_files
```

### Rocket.Chat anonymous Livechat visitor bootstrap chained to file-upload access

`UC_191_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where (Web.uri_path="/api/v1/livechat/visitor" OR Web.uri_path="/api/v1/livechat/room" OR Web.uri_path="/file-upload/*") by Web.src Web.dest Web.uri_path _time span=10m
| `drop_dm_object_name(Web)`
| eval isVisitor=if(uri_path="/api/v1/livechat/visitor",1,0), isRoom=if(uri_path="/api/v1/livechat/room",1,0), isFile=if(like(uri_path,"/file-upload/%"),1,0)
| stats sum(isVisitor) as visitorReg sum(isRoom) as roomReq sum(isFile) as fileReq dc(uri_path) as distinctPaths min(_time) as firstTime max(_time) as lastTime by src dest
| where visitorReg>=1 AND roomReq>=1 AND fileReq>=1
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - fileReq
```

### Rocket.Chat file-upload request carrying Livechat auth params (IDOR signature)

`UC_191_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.status) as statuses values(Web.http_user_agent) as user_agent from datamodel=Web where Web.http_method="GET" Web.uri_path="/file-upload/*" Web.uri_query="*rc_room_type=l*" Web.uri_query="*rc_token=*" by Web.src Web.dest Web.uri_path
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
