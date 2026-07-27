# [HIGH] ShinyHunters data leaks fuel $2,000 sextortion email scam

**Source:** BleepingComputer
**Published:** 2026-07-25
**Article:** https://www.bleepingcomputer.com/news/security/shinyhunters-data-leaks-fuel-2-000-sextortion-email-scam/

## Threat Profile

ShinyHunters data leaks fuel $2,000 sextortion email scam 
By Lawrence Abrams 
July 25, 2026
10:16 AM
0 
Threat actors are using email addresses exposed in data breaches leaked by the ShinyHunters extortion group to send sextortion emails demanding $2,000 in Bitcoin.
The emails claim to come from ShinyHunters and tell recipients that hackers compromised their devices after obtaining their email addresses from breached company databases.
However, the messages appear to be sent by someone who down…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1656** — Impersonation
- **T1566** — Phishing
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake ShinyHunters sextortion email by fixed subject + spoofed display name

`UC_18_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.direction=inbound (All_Email.subject="Information about your online security" OR All_Email.src_user="ShinyHunters" OR All_Email.src_user="You've Been HACKED") by All_Email.src_user, All_Email.src, All_Email.subject, All_Email.recipient, All_Email.message_id | `drop_dm_object_name(All_Email)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where Subject =~ "Information about your online security"
    or SenderDisplayName has_any ("ShinyHunters", "You've Been HACKED")
| where DeliveryAction != "Blocked"    // surface what actually landed in the mailbox
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, SenderIPv4, SenderFromDomain, Subject, RecipientEmailAddress, DeliveryAction, DeliveryLocation, ThreatTypes
| order by Timestamp desc
```

### ShinyHunters sextortion campaign fan-out (one subject, many random senders/recipients)

`UC_18_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Email.recipient) as recipients dc(All_Email.src) as distinct_senders count min(_time) as firstTime max(_time) as lastTime values(All_Email.src) as sender_addresses from datamodel=Email.All_Email where All_Email.direction=inbound (All_Email.subject="Information about your online security" OR All_Email.src_user="ShinyHunters" OR All_Email.src_user="You've Been HACKED") by All_Email.subject | `drop_dm_object_name(All_Email)` | where recipients>=5 | convert ctime(firstTime) ctime(lastTime) | sort - recipients
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where Subject =~ "Information about your online security"
    or SenderDisplayName has_any ("ShinyHunters", "You've Been HACKED")
| summarize Recipients = dcount(RecipientEmailAddress),
            DistinctSenders = dcount(SenderFromAddress),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleSenders = make_set(SenderFromAddress, 15),
            SampleSenderIPs = make_set(SenderIPv4, 15)
        by Subject
| where Recipients >= 5     // 5 = low bar for a coordinated blast vs a one-off; tune up in large tenants
| order by Recipients desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
