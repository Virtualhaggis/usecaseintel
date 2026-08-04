# [HIGH] Responsible disclosure: CodeCov CEO & CTO share learnings from the breach

**Source:** Snyk
**Published:** 2021-12-09
**Article:** https://snyk.io/blog/codecov-ceo-cto-share-learnings-from-breach-tsd/

## Threat Profile

Snyk Blog In this article
Written by Mariah Gresham 
December 9, 2021
0 mins read In January of 2021, CodeCov suffered a supply chain attack that exposed client environment variables. In the following months, the specifics of the breach and its technical applications have been thoroughly examined by the application security community to determine what went wrong and how to combat similar attacks in the future. But another interesting outcome of the breach were the insights into a slightly less g…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `104.248.94.23`
- **IPv4 (defanged):** `178.62.86.114`
- **IPv4 (defanged):** `79.135.72.34`
- **IPv4 (defanged):** `185.211.156.78`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1041** — Exfiltration Over C2 Channel
- **T1552** — Unsecured Credentials
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CodeCov Bash Uploader CI env-var exfiltration via curl (<<<<<< ENV marker)

`UC_2764_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl AND Processes.process="*<<<<<< ENV*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "curl"
| where ProcessCommandLine contains "<<<<<< ENV"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### CodeCov uploader egress to non-CodeCov host (surfaces exfil server IP)

`UC_2764_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as exfil_ip values(All_Traffic.dest_port) as exfil_ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.direction=outbound NOT (All_Traffic.dest="*.codecov.io" OR All_Traffic.dest="*.storage.googleapis.com") by All_Traffic.src | `drop_dm_object_name(All_Traffic)` | search [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name=curl Processes.process="*<<<<<< ENV*" by Processes.dest | `drop_dm_object_name(Processes)` | rename dest as src | fields src | format] | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "curl"
| where InitiatingProcessCommandLine contains "<<<<<< ENV"
| where RemoteIPType == "Public"
| where not(RemoteUrl endswith "codecov.io" or RemoteUrl endswith "storage.googleapis.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp desc
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `104.248.94.23`, `178.62.86.114`, `79.135.72.34`, `185.211.156.78`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
