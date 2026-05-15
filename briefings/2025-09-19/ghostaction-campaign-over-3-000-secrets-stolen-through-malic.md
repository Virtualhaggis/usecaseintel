# [HIGH] GhostAction Campaign: Over 3,000 Secrets Stolen Through Malicious GitHub Workflows

**Source:** StepSecurity
**Published:** 2025-09-19
**Article:** https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows

## Threat Profile

Back to Blog Threat Intel GhostAction Campaign: Over 3,000 Secrets Stolen Through Malicious GitHub Workflows GitGuardian researchers discover massive supply chain attack affecting 817 repositories across 327 GitHub users. Malicious workflows exfiltrated 3,325 secrets including PyPI, npm, and DockerHub tokens through compromised developer accounts. Ashish Kurmi View LinkedIn September 5, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `bold-dhawan.45-139-104-115.plesk.page`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1552.004** — Unsecured Credentials: Private Keys / CI Secrets
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1005** — Data from Local System
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GhostAction C2 egress to bold-dhawan/objective-hopper .plesk.page or 45.139.104.115

`UC_644_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="45.139.104.115" OR All_Traffic.dest="bold-dhawan.45-139-104-115.plesk.page" OR All_Traffic.dest="objective-hopper.45-139-104-115.plesk.page" OR All_Traffic.dest="*.45-139-104-115.plesk.page" OR All_Traffic.url="*bold-dhawan.45-139-104-115.plesk.page*" OR All_Traffic.url="*objective-hopper.45-139-104-115.plesk.page*" by All_Traffic.src,All_Traffic.dest,All_Traffic.dest_ip,All_Traffic.dest_port,All_Traffic.user | `drop_dm_object_name("All_Traffic")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GhostActionDomains = dynamic(["bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page"]);
let GhostActionIP = "45.139.104.115";
union isfuzzy=true
  ( DeviceNetworkEvents
      | where Timestamp > ago(30d)
      | where RemoteIP == GhostActionIP
         or RemoteUrl has_any (GhostActionDomains)
         or RemoteUrl endswith ".45-139-104-115.plesk.page"
      | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessAccountName, InitiatingProcessFolderPath ),
  ( DeviceEvents
      | where Timestamp > ago(30d)
      | where ActionType == "DnsQueryResponse"
      | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
      | where QueryName has_any (GhostActionDomains)
         or QueryName endswith ".45-139-104-115.plesk.page"
      | project Timestamp, DeviceName, ActionType, RemoteUrl=QueryName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessAccountName, InitiatingProcessFolderPath )
| order by Timestamp desc
```

### [LLM] GhostAction curl POST exfiltrating *_TOKEN= to plesk.page sub-domain on self-hosted runner

`UC_644_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl","curl.exe","wget","wget.exe","powershell.exe","pwsh","pwsh.exe")) AND (Processes.process="*bold-dhawan.45-139-104-115.plesk.page*" OR Processes.process="*objective-hopper.45-139-104-115.plesk.page*" OR Processes.process="*45-139-104-115.plesk.page*" OR Processes.process="*45.139.104.115*") by host,Processes.user,Processes.process_name,Processes.parent_process_name,Processes.process | `drop_dm_object_name("Processes")` | where match(process,"(?i)(CODECOV_TOKEN|NPM_TOKEN|PYPI_API_TOKEN|PYPI_TOKEN|DOCKERHUB_TOKEN|DOCKER_PASSWORD|GH_TOKEN|GITHUB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|CLOUDFLARE_API_TOKEN|CF_API_TOKEN|secrets\\.)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GhostActionHosts = dynamic(["bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page","45-139-104-115.plesk.page","45.139.104.115"]);
let SecretTokens = dynamic(["CODECOV_TOKEN","NPM_TOKEN","PYPI_API_TOKEN","PYPI_TOKEN","DOCKERHUB_TOKEN","DOCKER_PASSWORD","DOCKERHUB_USERNAME","GH_TOKEN","GITHUB_TOKEN","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","CLOUDFLARE_API_TOKEN","CF_API_TOKEN","secrets."]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe","pwsh","bash","sh","dash")
   or InitiatingProcessFileName in~ ("curl.exe","curl","wget.exe","wget")
| where ProcessCommandLine has_any (GhostActionHosts)
   or InitiatingProcessCommandLine has_any (GhostActionHosts)
| extend Cmd = strcat(tostring(ProcessCommandLine), " || ", tostring(InitiatingProcessCommandLine))
| where Cmd has_any (SecretTokens) or Cmd has "-X POST" or Cmd has "--data" or Cmd matches regex @"(?i)\-d\s+['\"]?[A-Z0-9_]+_TOKEN="
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
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
  - IP / domain IOC(s): `bold-dhawan.45-139-104-115.plesk.page`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
