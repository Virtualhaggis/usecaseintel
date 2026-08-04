# [HIGH] Finding eight high-severity vulnerabilities in NodeBB in six hours

**Source:** Aikido
**Published:** 2026-07-22
**Article:** https://www.aikido.dev/blog/eight-high-severity-vulnerabilities-nodebb

## Threat Profile

Blog Vulnerabilities & Threats Finding eight high-severity vulnerabilities in NodeBB in six hours Finding eight high-severity vulnerabilities in NodeBB in six hours Written by Jorian Woltjer Published on: Jul 22, 2026 TL;DR
NodeBB versions prior to 4.14.0 contain multiple high severity vulnerabilities
Upgrade to newer versions to resolve the vulnerabilities
Aikido will automatically flag vulnerable instances
While improving our AI Pentest , we ran a whitebox assessment on NodeBB, a forum softwar…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `4.245.3.4`
- **Domain (defanged):** `attacker.tld`
- **Domain (defanged):** `rhythm-broke-heath-kernel.trycloudflare.com`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1189** — Drive-by Compromise
- **T1059.007** — JavaScript
- **T1071.001** — Web Protocols
- **T1102** — Web Service
- **T1211** — Exploitation for Defense Evasion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NodeBB remote federated-user profile lookup (ActivityPub XSS #1 trigger)

`UC_148_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as requests min(_time) as firstTime max(_time) as lastTime values(Web.src) as src_ips from datamodel=Web where Web.uri_path="/user/*" (Web.uri_path="*@*" OR Web.uri_path="*%40*") by Web.uri_path, Web.dest, Web.http_user_agent | `drop_dm_object_name(Web)` | rex field=uri_path "/user/[^/@]+(?:@|%40)(?<remote_handle_domain>[A-Za-z0-9._-]+)" | where isnotnull(remote_handle_domain) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

### NodeBB server outbound ActivityPub/webfinger fetch to ephemeral tunnel or new domain

`UC_148_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/.well-known/webfinger*" OR Web.url="*/ap/actor/*" OR Web.uri_path="/actor") by Web.dest, Web.url, Web.src | `drop_dm_object_name(Web)` | eval ephemeral_tunnel=if(match(dest,"(?i)\.trycloudflare\.com$|\.workers\.dev$"),1,0) | where ephemeral_tunnel=1 OR NOT [| tstats `summariesonly` count from datamodel=Web where Web.url="*/.well-known/webfinger*" earliest=-30d latest=-1d by Web.dest | `drop_dm_object_name(Web)` | rename dest as known_dest | fields known_dest | rename known_dest as dest | format] | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","nodejs.exe","node")
| where RemoteUrl has "/.well-known/webfinger" or RemoteUrl has "/ap/actor" or RemoteUrl endswith "trycloudflare.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### NodeBB ActivityPub inbox POST carrying HTML-breakout id (Federation Errors stored XSS)

`UC_148_6` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method="POST" (Web.uri_path="*/inbox" OR Web.uri_path="*/ap/inbox/*") by Web.src, Web.dest, Web.uri_path, Web.http_user_agent | `drop_dm_object_name(Web)` | sort - lastTime
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

### Article-specific behavioural hunt — Finding eight high-severity vulnerabilities in NodeBB in six hours

`UC_148_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Finding eight high-severity vulnerabilities in NodeBB in six hours ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("helpers.common.js","inbox.js","render.js","utils.common.js","activitypub.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("helpers.common.js","inbox.js","render.js","utils.common.js","activitypub.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Finding eight high-severity vulnerabilities in NodeBB in six hours
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("helpers.common.js", "inbox.js", "render.js", "utils.common.js", "activitypub.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("helpers.common.js", "inbox.js", "render.js", "utils.common.js", "activitypub.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `4.245.3.4`, `attacker.tld`, `rhythm-broke-heath-kernel.trycloudflare.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
