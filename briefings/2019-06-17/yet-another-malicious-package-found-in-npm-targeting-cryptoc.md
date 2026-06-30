# [HIGH] Yet another malicious package found in npm, targeting cryptocurrency wallets

**Source:** Snyk
**Published:** 2019-06-17
**Article:** https://snyk.io/blog/yet-another-malicious-package-found-in-npm-targeting-cryptocurrency-wallets/

## Threat Profile

Snyk Blog In this article
Written by Simon Maple 
June 17, 2019
0 mins read Cryptocurrency wallet developer Komodo has been in the news recently as the most recent victim of an attempted cryptocurrency attack by malicious code injection via npm dependencies. The EasyDEX-GUI project which provides a graphical user interface (GUI) to SuperNET/Iguana cryptocurrency APIs and is used by Komodo’s Agama wallet has been found to contain a malicious package namedelectron-native-notify. This was disclosed…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.007** — JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Agama wallet C2/exfil callback to updatecheck.herokuapp.com (electron-native-notify)

`UC_3210_0` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="updatecheck.herokuapp.com" OR DNS.query="*.updatecheck.herokuapp.com" by DNS.src DNS.query DNS.answer index sourcetype | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "updatecheck.herokuapp.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Malicious npm package electron-native-notify present in node_modules

`UC_3210_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*node_modules*electron-native-notify*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has "node_modules" and FolderPath has "electron-native-notify"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
