# [HIGH] Security Advisory: Critical RCE Vulnerabilities in React Server Components (CVE-2025-55182)

**Source:** Snyk
**Published:** 2025-12-03
**Article:** https://snyk.io/blog/security-advisory-critical-rce-vulnerabilities-react-server-components/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
December 3, 2025
0 mins read TL;DR On December 3, 2025, coordinated disclosures revealed that multiple releases of React 19 and Next.js contain a critical flaw in the React Server Components (RSC) “Flight” protocol , allowing unauthenticated remote code execution (RCE) . The vulnerability originates from unsafe deserialization of attacker-controlled data in server-side RSC payload handling.
Exploitation only requires a crafted HTTP request ,…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-66478`
- **IPv4 (defanged):** `140.99.223.178`
- **IPv4 (defanged):** `156.234.209.103`
- **IPv4 (defanged):** `38.162.112.141`
- **IPv4 (defanged):** `45.32.158.54`
- **IPv4 (defanged):** `46.36.37.85`
- **IPv4 (defanged):** `47.84.57.207`
- **IPv4 (defanged):** `95.169.180.135`
- **IPv4 (defanged):** `31.56.27.76`
- **IPv4 (defanged):** `193.34.213.150`
- **IPv4 (defanged):** `72.62.67.33`
- **IPv4 (defanged):** `193.24.123.68`
- **IPv4 (defanged):** `146.88.129.138`
- **IPv4 (defanged):** `192.238.202.17`
- **IPv4 (defanged):** `115.42.60.223`
- **IPv4 (defanged):** `31.57.46.28`
- **IPv4 (defanged):** `47.84.79.46`
- **IPv4 (defanged):** `194.69.203.32`
- **IPv4 (defanged):** `162.215.170.26`
- **IPv4 (defanged):** `216.158.232.43`
- **IPv4 (defanged):** `196.251.100.191`
- **IPv4 (defanged):** `92.246.87.48`
- **Domain (defanged):** `reactcdn.windowserrorapis.com`
- **Domain (defanged):** `res.qiqigece.top`
- **Domain (defanged):** `help.093214.xyz`
- **Domain (defanged):** `keep.camdvr.org`
- **Domain (defanged):** `superminecraft.net.br`
- **Domain (defanged):** `vip.kof97.lol`
- **Domain (defanged):** `anywherehost.site`
- **Domain (defanged):** `xpertclient.net`
- **Domain (defanged):** `overcome-pmc-conferencing-books.trycloudflare.com`
- **Domain (defanged):** `donaldjtrmp.anondns.net`
- **Domain (defanged):** `labubu.anondns.net`
- **Domain (defanged):** `krebsec.anondns.net`
- **Domain (defanged):** `ghostbin.axel.org`
- **Domain (defanged):** `vps-zap812595-1.zap-srv.com`
- **SHA256:** `a455731133c00fdd2a141bdfba4def34ae58195126f762cdf951056b0ef161d4`
- **SHA256:** `2b0dc27f035ba1417990a21dafb361e083e4ed94a75a1c49dc45690ecf463de4`
- **SHA256:** `1663d98c259001f1b03f82d0c5bee7cfd3c7623ccb83759c994f9ab845939665`
- **SHA256:** `18c68a982f91f665effe769f663c51cb0567ea2bfc7fab6a1a40d4fe50fc382b`
- **SHA256:** `1a3e7b4ee2b2858dbac2d73dd1c52b1ea1d69c6ebb24cc434d1e15e43325b74e`
- **SHA256:** `1cdd9b0434eb5b06173c7516f99a832dc4614ac10dda171c8eed3272a5e63d20`
- **SHA256:** `1e31dc074a4ea7f400cb969ea80e8855b5e7486660aab415da17591bc284ac5b`
- **SHA256:** `2ca913556efd6c45109fd8358edb18d22a10fb6a36c1ab7b2df7594cd5b0adbc`
- **SHA256:** `4ff096fbea443778fec6f960bf2b9c84da121e6d63e189aebaaa6397d9aac948`
- **SHA256:** `55ae00bc8482afd085fd128965b108cca4adb5a3a8a0ee2957d76f33edd5a864`
- **SHA256:** `62e9a01307bcf85cdaeecafd6efb5be72a622c43a10f06d6d6d3b566b072228d`
- **SHA256:** `7d25a97be42b357adcc6d7f56ab01111378a3190134aa788b1f04336eb924b53`
- **SHA256:** `7f05bad031d22c2bb4352bf0b6b9ee2ca064a4c0e11a317e6fedc694de37737a`
- **SHA256:** `9c931f7f7d511108263b0a75f7b9fcbbf9fd67ebcc7cd2e5dcd1266b75053624`
- **SHA256:** `ac2182dfbf56d58b4d63cde3ad6e7a52fed54e52959e4c82d6fc999f20f8d693`
- **SHA256:** `ac7027f30514d0c00d9e8b379b5ad8150c9827c827dc7ee54d906fc2585b6bf6`
- **SHA256:** `b38ec4c803a2d84277d9c598bfa5434fb8561ddad0ec38da6f9b8ece8104d787`
- **SHA256:** `bc31561c44a36e1305692d0af673bc5406f4a5bb2c3f2ffdb613c09b4e80fa9f`
- **SHA256:** `bf602b11d99e815e26c88a3a47eb63997d43db8b8c60db06d6fbddf386fd8c4a`
- **SHA256:** `d704541cde64a3eef5c4f80d0d7f96dc96bae8083804c930111024b274557b16`
- **SHA256:** `d9313f949af339ed9fafb12374600e66b870961eeb9b2b0d4a3172fd1aa34ed0`
- **SHA256:** `e2d7c8491436411474cef5d3b51116ddecfee68bab1e15081752a54772559879`
- **SHA256:** `4745703f395282a0687def2c7dcf82ed1683f3128bef1686bd74c966273ce1c5`
- **SHA256:** `4a759cbc219bcb3a1f8380a959307b39873fb36a9afd0d57ba0736ad7a02763b`
- **SHA256:** `33641bfbbdd5a9cd2320c61f65fe446a2226d8a48e3bd3c29e8f916f0592575f`
- **SHA256:** `ebdb85704b2e7ced3673b12c6f3687bc0177a7b1b3caef110213cc93a75da837`
- **SHA256:** `f88ce150345787dd1bcfbc301350033404e32273c9a140f22da80810e3a3f6ea`
- **SHA256:** `fc9e53675e315edeea2292069c3fbc91337c972c936ca0f535da01760814b125`
- **SHA256:** `1f3f0695c7ec63723b2b8e9d50b1838df304821fcb22c7902db1f8248a812035`
- **SHA256:** `c2867570f3bbb71102373a94c7153239599478af84b9c81f2a0368de36f14a7c`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable react-server-dom-* package versions (CVE-2025-55182) in workload inventory

`UC_693_4` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Vulnerabilities.cve) as cve, values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where (Vulnerabilities.cve="CVE-2025-55182" OR Vulnerabilities.signature IN ("*react-server-dom-webpack*","*react-server-dom-parcel*","*react-server-dom-turbopack*")) by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | search signature IN ("*19.0.0*","*19.1.0*","*19.1.1*","*19.2.0*") OR cve="CVE-2025-55182" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId == "CVE-2025-55182"
   or (SoftwareName has_any ("react-server-dom-webpack","react-server-dom-parcel","react-server-dom-turbopack") and SoftwareVersion in ("19.0.0","19.1.0","19.1.1","19.2.0"))
   or (SoftwareName =~ "next" and SoftwareVersion matches regex @"^(15\.|16\.)")
| join kind=leftouter DeviceInfo on DeviceId
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, IsInternetFacing, RecommendedSecurityUpdate
| order by IsInternetFacing desc, Timestamp desc
```

### Node.js process spawning interactive shell — suspected post-exploit RCE on Next.js / RSC server

`UC_693_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as cmd, values(Processes.parent_process) as parent_cmd, values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","ash") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(parent_cmd, "next\s+(build|dev)") AND NOT match(user, "\\$$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","ash")
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where InitiatingProcessCommandLine !has "next build"
      and InitiatingProcessCommandLine !has "next dev"
      and InitiatingProcessParentFileName !in~ ("npm.exe","npm","yarn.exe","yarn","pnpm.exe","pnpm","npm-cli.js")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          GrandparentImage = InitiatingProcessParentFileName,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Anomalous POST to Next.js Server Action / RSC endpoint with 5xx error clustering

`UC_693_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Web.uri_path) as distinct_uris, values(Web.http_user_agent) as user_agents, values(Web.uri_path) as uris, values(Web.status) as statuses from datamodel=Web where Web.http_method=POST AND (Web.uri_query="*_rsc=*" OR Web.uri_query="*RSC=1*" OR Web.uri_path="*/_next/*" OR Web.http_header="*Next-Action*") AND Web.status>=500 AND Web.status<600 by Web.src, Web.dest, _time span=5m | `drop_dm_object_name(Web)` | where count >= 10 | sort - count
```

**Defender KQL:**
```kql
// Defender XDR has limited HTTP-server-log telemetry; this pivots on outbound connections initiated by the Node.js process serving RSC after a burst of inbound 5xx (use UC2/UC3-network combo if HTTP logs unavailable).
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize ConnCount = count(), DistinctRemotes = dcount(RemoteIP), Remotes = make_set(RemoteIP, 20), SampleCmd = any(InitiatingProcessCommandLine) by DeviceName, bin(Timestamp, 5m)
| where DistinctRemotes >= 3 or ConnCount > 20
| order by Timestamp desc
```

### Article-specific behavioural hunt — Security Advisory: Critical RCE Vulnerabilities in React Server Components (CVE-

`UC_693_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Security Advisory: Critical RCE Vulnerabilities in React Server Components (CVE- ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Security Advisory: Critical RCE Vulnerabilities in React Server Components (CVE-
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`, `CVE-2025-66478`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `140.99.223.178`, `156.234.209.103`, `38.162.112.141`, `45.32.158.54`, `46.36.37.85`, `47.84.57.207`, `95.169.180.135`, `31.56.27.76` _(+27 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a455731133c00fdd2a141bdfba4def34ae58195126f762cdf951056b0ef161d4`, `2b0dc27f035ba1417990a21dafb361e083e4ed94a75a1c49dc45690ecf463de4`, `1663d98c259001f1b03f82d0c5bee7cfd3c7623ccb83759c994f9ab845939665`, `18c68a982f91f665effe769f663c51cb0567ea2bfc7fab6a1a40d4fe50fc382b`, `1a3e7b4ee2b2858dbac2d73dd1c52b1ea1d69c6ebb24cc434d1e15e43325b74e`, `1cdd9b0434eb5b06173c7516f99a832dc4614ac10dda171c8eed3272a5e63d20`, `1e31dc074a4ea7f400cb969ea80e8855b5e7486660aab415da17591bc284ac5b`, `2ca913556efd6c45109fd8358edb18d22a10fb6a36c1ab7b2df7594cd5b0adbc` _(+22 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
