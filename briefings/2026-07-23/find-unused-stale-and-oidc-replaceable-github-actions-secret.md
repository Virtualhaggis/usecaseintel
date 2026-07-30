# [HIGH] Find Unused, Stale, and OIDC-Replaceable GitHub Actions Secrets Across Your GitHub Organization

**Source:** StepSecurity
**Published:** 2026-07-23
**Article:** https://www.stepsecurity.io/blog/find-unused-stale-and-oidc-replaceable-github-actions-secrets-across-your-github-organization

## Threat Profile

Back to Blog Product Find Unused, Stale, and OIDC-Replaceable GitHub Actions Secrets Across Your GitHub Organization StepSecurity now shows which GitHub Actions secrets are actually used, which workflows use them, and which can be replaced with OIDC. Varun Sharma View LinkedIn July 22, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Attackers are no longer just poisoning packages. They are going straight for the secrets stored…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.139.104.115`
- **IPv4 (defanged):** `216.126.225.129`
- **Domain (defanged):** `bold-dhawan.45-139-104-115.plesk.page`
- **Domain (defanged):** `objective-hopper.45-139-104-115.plesk.page`
- **Domain (defanged):** `carte-avantage.com`
- **SHA1:** `acac5a9854650c4ae2883c4740bf87d34120c038`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1204.003** — User Execution: Malicious Image
- **T1059** — Command and Scripting Interpreter
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Network egress from CI/build host to GhostAction secret-exfil infrastructure

`UC_122_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="45.139.104.115" OR All_Traffic.dest_ip="216.126.225.129" OR All_Traffic.dest="bold-dhawan.45-139-104-115.plesk.page" OR All_Traffic.dest="objective-hopper.45-139-104-115.plesk.page" OR All_Traffic.dest="carte-avantage.com") by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
let iocIPs = dynamic(["45.139.104.115","216.126.225.129"]);
let iocDomains = dynamic(["bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page","carte-avantage.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (iocIPs) or RemoteUrl has_any (iocDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Shai-Hulud / GhostAction malicious workflow artifact dropped on runner or repo checkout

`UC_122_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="shai-hulud-workflow.yml" OR Filesystem.file_hash="acac5a9854650c4ae2883c4740bf87d34120c038" OR (Filesystem.file_name="bundle.js" AND (Filesystem.file_path="*\\.github\\*" OR Filesystem.file_path="*/_work/*" OR Filesystem.file_path="*actions-runner*"))) by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "shai-hulud-workflow.yml"
   or SHA1 == "acac5a9854650c4ae2883c4740bf87d34120c038"
   or (FileName =~ "bundle.js" and FolderPath has_any (@"\.github\", @"\_work\", @"\actions-runner\", "/.github/", "/_work/"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### CI runner process POSTing secrets to GhostAction exfil host via curl/wget/node

`UC_122_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*bold-dhawan.45-139-104-115.plesk.page*" OR Processes.process="*objective-hopper.45-139-104-115.plesk.page*" OR Processes.process="*carte-avantage.com*" OR Processes.process="*45.139.104.115*" OR Processes.process="*216.126.225.129*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page","carte-avantage.com","45.139.104.115","216.126.225.129")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
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
  - IP / domain IOC(s): `45.139.104.115`, `216.126.225.129`, `bold-dhawan.45-139-104-115.plesk.page`, `objective-hopper.45-139-104-115.plesk.page`, `carte-avantage.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `acac5a9854650c4ae2883c4740bf87d34120c038`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
