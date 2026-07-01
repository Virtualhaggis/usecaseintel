# [HIGH] Malicious code found in npm package event-stream downloaded 8 million times in the past 2.5 months

**Source:** Snyk
**Published:** 2018-11-27
**Article:** https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/

## Threat Profile

Snyk Blog In this article
Written by Danny Grander 
November 27, 2018
0 mins read A widely used npm package, event-stream , has been found to contain a malicious package named flatmap-stream . This was disclosed via a GitHub issue raised against the source repo .
The event-stream package makes creating and working with streams easy, and is very popular, getting roughly 2 million downloads a week. The malicious child package has been downloaded nearly 8 million times since its inclusion back in S…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious npm flatmap-stream / event-stream@3.3.6 dependency dropped to endpoint disk

`UC_3287_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*flatmap-stream*" OR Filesystem.file_path="*\\node_modules\\flatmap-stream\\*" OR Filesystem.file_name="flatmap-stream*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "flatmap-stream" or FileName has "flatmap-stream"
   or (FolderPath has @"\node_modules\event-stream\" and FolderPath has "3.3.6")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Copay wallet-stealer C2 exfil to copayapi.host / 111.90.151.134

`UC_3287_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="111.90.151.134" OR All_Traffic.dest_host="copayapi.host" OR All_Traffic.url="*copayapi.host*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.app All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has "copayapi.host" or RemoteIP == "111.90.151.134"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
