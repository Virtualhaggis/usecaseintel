# [CRIT] Concerns of supply-chain attacks amplify as remote code execution was found in Ruby gem strong_password

**Source:** Snyk
**Published:** 2019-07-07
**Article:** https://snyk.io/blog/ruby-gem-strong_password-found-to-contain-remote-code-execution-code-in-a-malicious-version-further-strengthening-worries-of-growth-in-supply-chain-attacks/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
July 7, 2019
0 mins read On July 5th, 2019, the CVE-2019-13354 security advisory was published for a malicious version of the strong_password Ruby gem which allows for remote code execution in applications bundling the vulnerable dependency. 
We have already added the vulnerability to our database , and if your Ruby project is being monitored by Snyk, you will have already been notified by our routine alerts. If not, we strongly recommend you to te…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-13354`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1105** — Ingress Tool Transfer
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1505.003** — Server Software Component: Web Shell
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### strong_password 0.0.7 backdoor: Ruby app server fetches second-stage payload from pastebin.com/raw/xa456PFt

`UC_3517_2` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*pastebin.com/raw/xa456PFt*" OR (Web.url="*pastebin.com/raw/*" AND (Web.app="ruby" OR Web.app="puma" OR Web.app="unicorn" OR Web.app="passenger"))) by Web.src Web.dest Web.url Web.app Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName has_any ("ruby","puma","unicorn","passenger","rails") or InitiatingProcessFolderPath has "ruby")
| where RemoteUrl has "pastebin.com"
| extend ExactIOC = RemoteUrl has "pastebin.com/raw/xa456PFt"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ExactIOC
| order by Timestamp desc
```

### strong_password 0.0.7 backdoor: beacon to home server smiley.zzz.com.ua

`UC_3517_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="smiley.zzz.com.ua" OR DNS.query="*.smiley.zzz.com.ua") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "smiley.zzz.com.ua"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### strong_password 0.0.7 backdoor: RCE via attacker-controlled ___id cookie eval middleware

`UC_3517_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.cookie="*___id=*" by Web.src Web.dest Web.http_method Web.uri_path Web.cookie Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-13354`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
