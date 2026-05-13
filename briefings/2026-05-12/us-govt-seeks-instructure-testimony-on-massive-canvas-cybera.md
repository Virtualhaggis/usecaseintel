# [MED] US govt seeks Instructure testimony on massive Canvas cyberattack

**Source:** BleepingComputer
**Published:** 2026-05-12
**Article:** https://www.bleepingcomputer.com/news/security/us-govt-seeks-instructure-testimony-on-massive-canvas-cyberattack/

## Threat Profile

US govt seeks Instructure testimony on massive Canvas cyberattack 
By Lawrence Abrams 
May 12, 2026
07:09 PM
0 
The U.S. House Committee on Homeland Security is calling on Instructure executives to testify about two cyberattacks by the ShinyHunters extortion group that targeted the company’s Canvas platform, allowing threat actors to steal student data and disrupt schools during final exams.
In a letter sent Monday afternoon to Instructure CEO Steve Daly, Homeland Security Committee Chairman And…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1567** — Exfiltration Over Web Service
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ShinyHunters Instructure Canvas breach — egress to actor extortion infrastructure (91.215.85.103 / pay_or_leak URI / v3 onion)

`UC_4_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="91.215.85.103" OR All_Traffic.dest_ip="91.215.85.103" OR All_Traffic.dest="*shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid*") by All_Traffic.src, All_Traffic.src_ip, All_Traffic.user, All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, All_Traffic.action | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*pay_or_leak/instructure_affected_schools_list*" OR Web.url="*shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid*" OR Web.dest="91.215.85.103") by Web.src, Web.user, Web.dest, Web.url, Web.http_user_agent, Web.action | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) ] | sort - lastTime
```

**Defender KQL:**
```kql
let _badIP = "91.215.85.103";
let _badUriToken = "pay_or_leak/instructure_affected_schools_list";
let _onion = "shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid";
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == _badIP
         or (isnotempty(RemoteUrl) and (RemoteUrl has _badUriToken or RemoteUrl has _onion))
    | project Timestamp, DeviceName, DeviceId,
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP, RemotePort, RemoteUrl, ActionType,
              EventSource = "DeviceNetworkEvents" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has _onion
    | project Timestamp, DeviceName, DeviceId,
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP = "", RemotePort = int(null), RemoteUrl = Q, ActionType,
              EventSource = "DeviceEvents.DnsQueryResponse" )
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
